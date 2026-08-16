import { useState } from 'react'
import { useFetch } from '../lib/useFetch'
import { api, countryFlag, countryName, type Block, type GeoIPSummary } from '../lib/api'
import { verdictNow, type BlocksPayload, type EnforcementState } from '../lib/contracts'
import { Card, CardHeader, Spinner, EmptyState, Button, Pill, TextInput, ScrollArea } from '../components/ui'
import { SegmentedControl } from '../components/RangeControl'
import { EntityLink } from '../components/entity'
import { PageTitle } from '../components/PageTitle'
import { Th, Td } from './Devices'
import { useDeviceIndex, type DeviceIndex } from '../lib/links'
import { useIsMobile } from '../lib/useIsMobile'
import { useUrlState } from '../lib/useUrlState'
import { formatCount, formatRelative, formatTime } from '../lib/format'
import { humanError } from '../components/humanError'
import { KernelStatusLine, KernelVerdictPanel, dropsLabel, dropsPhrase } from '../components/KernelVerdict'
import { useOutcomes, OutcomeStrip, type OutcomeSpec, type TargetResult } from '../components/Outcomes'
import { ConfirmDialog } from '../components/ConfirmDialog'
import { useSelection, SelectBox, BulkBar } from '../components/Selection'

// blockName resolves a blocked prefix to a device name when it is a single
// host that the inventory knows (strip the /32 or /128 the API normalises to).
function blockName(index: DeviceIndex, prefix: string): string {
  const host = prefix.replace(/\/(32|128)$/, '')
  return index.names.get(host) ?? ''
}

const TABS = ['blocks', 'countries'] as const
type Tab = (typeof TABS)[number]

// The server caps /api/devices/forget at a batch of this size and the same
// number is right here: this loops one request per target, and a selection
// that would take minutes to run is a selection nobody can supervise.
const BULK_LIMIT = 200

// enforcedNow is the only question a success sentence may branch on: whether
// packets are being dropped is a fact about the mode, and the block path
// cannot end with "recorded but not applied" — the service rolls the row back
// and answers 409 when the kernel refuses.
function recordedOnly(mode: string | undefined): boolean {
  return mode !== 'enforce'
}

// restoreTtl turns an active block's remaining life into a ttl the block
// endpoint accepts, so undoing an unblock restores what was there rather than
// a fresh permanent block. Null means the row cannot be restored exactly —
// its expiry has already passed — and an undo that would guess is not offered.
function restoreTtl(expires: string | null): string | null {
  if (!expires) return ''
  const secs = Math.round((new Date(expires).getTime() - Date.now()) / 1000)
  return secs > 0 ? `${secs}s` : null
}

export function Firewall({ onUnauthorized, canWrite }: { onUnauthorized: () => void; canWrite: boolean }) {
  const [tab, setTab] = useUrlState<Tab>('tab', 'blocks', { valid: TABS, history: 'push' })
  const { data, loading, error, refresh } = useFetch<BlocksPayload>('/api/blocks', {
    pollMs: 5000,
    onUnauthorized,
  })
  const outcomes = useOutcomes()
  const [prefix, setPrefix] = useState('')
  const [reason, setReason] = useState('')
  const [ttl, setTtl] = useState('')
  const [busy, setBusy] = useState(false)
  const [bulkOpen, setBulkOpen] = useState(false)
  const [bulkBusy, setBulkBusy] = useState(false)
  const index = useDeviceIndex(onUnauthorized)
  const isMobile = useIsMobile()

  const blocks = data?.blocks ?? []
  const kernel = data?.kernel
  const mode = data?.enforcement
  const now = Date.now()
  const sel = useSelection(
    blocks.map((b) => b.Prefix),
    tab,
  )

  const unauthorized = (e: unknown) => (e as { status?: number }).status === 401

  const addBlock = async () => {
    setBusy(true)
    const target = prefix.trim()
    const life = ttl.trim()
    try {
      await api.post('/api/blocks', { prefix: target, reason, ttl: life })
      setPrefix('')
      setReason('')
      setTtl('')
      outcomes.report({
        tone: recordedOnly(mode) ? 'accent' : 'ok',
        message: recordedOnly(mode)
          ? `Recorded ${target}. Enforcement is off, so nothing is being dropped.`
          : `Blocked ${target} ${life ? `for ${life}` : 'permanently'}. The firewall accepted the rule.`,
        undo: { label: 'Undo', run: () => undoBlock(target) },
      })
    } catch (e) {
      if (unauthorized(e)) return onUnauthorized()
      outcomes.report({ tone: 'crit', message: humanError(e, 'block') })
    } finally {
      setBusy(false)
      refresh()
    }
  }

  // Every outcome is said out loud. This await used to stand bare, unlike the
  // block path directly above it, so a 409 carrying "the block is still in
  // place" became an unhandled rejection: the row vanished from nothing, the
  // list refreshed, and the operator walked away believing an address was
  // unblocked that the kernel was still dropping.
  const unblock = async (b: Block) => {
    try {
      await api.del(`/api/blocks?prefix=${encodeURIComponent(b.Prefix)}`)
      const ttlBack = restoreTtl(b.Expires)
      outcomes.report({
        tone: 'ok',
        message: recordedOnly(mode)
          ? `Unblocked ${b.Prefix}. Nothing was being dropped anyway — enforcement is off.`
          : `Unblocked ${b.Prefix}. The firewall removed the rule.`,
        // The row is soft-deleted server-side, so prefix, reason and remaining
        // life are all still here to re-post. When the expiry has already
        // passed there is nothing exact to restore and no undo is offered.
        undo: ttlBack === null ? undefined : { label: 'Undo', run: () => undoUnblock(b, ttlBack) },
      })
    } catch (e) {
      if (unauthorized(e)) return onUnauthorized()
      outcomes.report({ tone: 'crit', message: humanError(e, 'unblock') })
    } finally {
      refresh()
    }
  }

  const undoBlock = async (target: string): Promise<OutcomeSpec> => {
    try {
      await api.del(`/api/blocks?prefix=${encodeURIComponent(target)}`)
      return { tone: 'ok', message: `${target} is not blocked — the block was lifted again.` }
    } catch (e) {
      return { tone: 'crit', message: `Could not lift ${target} again: ${humanError(e, 'unblock')}` }
    } finally {
      refresh()
    }
  }

  const undoUnblock = async (b: Block, ttlBack: string): Promise<OutcomeSpec> => {
    try {
      await api.post('/api/blocks', { prefix: b.Prefix, reason: b.Reason, ttl: ttlBack })
      return { tone: 'ok', message: `${b.Prefix} is blocked again${ttlBack ? '' : ', permanently'}.` }
    } catch (e) {
      return { tone: 'crit', message: `Could not block ${b.Prefix} again: ${humanError(e, 'block')}` }
    } finally {
      refresh()
    }
  }

  // Bulk unblock runs one request per address, in order.
  //
  // There is no bulk endpoint: each address goes through the same single-target
  // service call, which is individually atomic and individually rolled back.
  // That is worth saying out loud in the confirmation, because it means a
  // partial result is normal rather than exceptional — and it is why the
  // outcome carries a line per address instead of one number. Sequential, not
  // concurrent: the service serialises applies behind one lock anyway, and
  // firing twenty at once would only scramble the audit log.
  const unblockSelected = async () => {
    const targets = sel.selected.slice(0, BULK_LIMIT)
    const rows = new Map(blocks.map((b) => [b.Prefix, b]))
    setBulkBusy(true)
    const results: TargetResult[] = []
    const restorable: { block: Block; ttl: string }[] = []
    for (const p of targets) {
      try {
        await api.del(`/api/blocks?prefix=${encodeURIComponent(p)}`)
        results.push({ target: p, ok: true, message: 'unblocked' })
        const row = rows.get(p)
        const ttlBack = row ? restoreTtl(row.Expires) : null
        if (row && ttlBack !== null) restorable.push({ block: row, ttl: ttlBack })
      } catch (e) {
        if (unauthorized(e)) {
          setBulkBusy(false)
          setBulkOpen(false)
          return onUnauthorized()
        }
        results.push({ target: p, ok: false, message: humanError(e, 'unblock') })
      }
    }
    setBulkBusy(false)
    setBulkOpen(false)
    sel.clear()
    refresh()

    const ok = results.filter((r) => r.ok).length
    const failed = results.length - ok
    outcomes.report({
      tone: failed === 0 ? 'ok' : ok === 0 ? 'crit' : 'warn',
      message:
        failed === 0
          ? `Unblocked ${ok} ${ok === 1 ? 'address' : 'addresses'}.`
          : ok === 0
            ? `Nothing was unblocked. ${failed} refused.`
            : `Unblocked ${ok}. ${failed} refused.`,
      results,
      undo:
        restorable.length > 0
          ? { label: `Undo ${restorable.length}`, run: () => undoUnblockMany(restorable) }
          : undefined,
    })
  }

  const undoUnblockMany = async (rows: { block: Block; ttl: string }[]): Promise<OutcomeSpec> => {
    const results: TargetResult[] = []
    for (const { block, ttl: life } of rows) {
      try {
        await api.post('/api/blocks', { prefix: block.Prefix, reason: block.Reason, ttl: life })
        results.push({ target: block.Prefix, ok: true, message: 'blocked again' })
      } catch (e) {
        results.push({ target: block.Prefix, ok: false, message: humanError(e, 'block') })
      }
    }
    refresh()
    const ok = results.filter((r) => r.ok).length
    const failed = results.length - ok
    return {
      tone: failed === 0 ? 'ok' : 'crit',
      message:
        failed === 0
          ? `${ok} ${ok === 1 ? 'address is' : 'addresses are'} blocked again.`
          : `Only ${ok} of ${results.length} could be blocked again — the rest are not blocked.`,
      results,
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <PageTitle title="Firewall">what is blocked, whether the kernel really holds it, and what it has caught</PageTitle>
      <SegmentedControl
        value={tab}
        label="Firewall view"
        onChange={setTab}
        options={[
          { value: 'blocks', label: 'Blocked addresses' },
          { value: 'countries', label: 'Countries' },
        ]}
      />

      {/* What the kernel was last found to hold, and when — for both tabs,
          because country prefixes land in the same sets. This replaces two
          banners that were derived from the configuration file and could
          therefore only ever repeat the operator's intention back to them. */}
      {loading && !data ? (
        <div className="rounded-lg border border-line bg-raised px-4 py-3 text-sm text-fg-muted" role="status">
          Reading what the kernel holds…
        </div>
      ) : (
        <KernelVerdictPanel state={kernel} />
      )}

      {tab === 'countries' && (
        <CountryBlocking canWrite={canWrite} onUnauthorized={onUnauthorized} kernel={kernel} />
      )}

      {tab === 'blocks' && canWrite && (
        <Card className="px-4 py-3.5">
          <CardHeader title="Block an address" sub="IP or CIDR — never blocks the gateway or allowlist" />
          <div className="mt-2 flex flex-wrap items-end gap-2 px-0">
            <Field label="Prefix" value={prefix} onChange={setPrefix} placeholder="203.0.113.5 or 203.0.113.0/24" width="w-56" />
            <Field label="Reason" value={reason} onChange={setReason} placeholder="optional note" width="w-48" />
            <Field label="TTL" value={ttl} onChange={setTtl} placeholder="24h · blank = permanent" width="w-40" />
            <Button variant="primary" onClick={addBlock} loading={busy} disabled={!prefix.trim()}>
              Block
            </Button>
          </div>
        </Card>
      )}

      {tab === 'blocks' && (
        <>
          <OutcomeStrip items={outcomes.items} dismiss={outcomes.dismiss} replace={outcomes.replace} />

          {canWrite && (
            <BulkBar
              count={sel.count}
              shown={blocks.length}
              allShown={sel.allShown}
              onSelectAll={sel.selectAllShown}
              onClear={sel.clear}
            >
              <Button variant="danger" onClick={() => setBulkOpen(true)}>
                Unblock {sel.count}…
              </Button>
            </BulkBar>
          )}

          <Card>
            <CardHeader
              title="Active blocks"
              sub={
                <>
                  {/* Never "N enforced": that number came from the config file
                      and said nothing about the kernel. What is recorded and
                      what is held are two separate claims, and only the second
                      one carries a timestamp. */}
                  {blocks.length} recorded ·{' '}
                  <KernelStatusLine state={kernel} prefix="kernel:" />
                  {/* Only where the tally above says "Dropped". Next to "not
                      verified" this sentence would imply packets are being
                      dropped, which is the claim the column just declined to
                      make. */}
                  {kernel && verdictNow(kernel, now) === 'enforcing' && (
                    <>
                      {' '}
                      · blocked packets stay visible to the monitor: capture taps the wire before the firewall
                    </>
                  )}
                </>
              }
            />
            {loading && !data ? (
              <Spinner />
            ) : error ? (
              <EmptyState>Could not load blocks: {error}</EmptyState>
            ) : blocks.length === 0 ? (
              <EmptyState>Nothing is blocked.</EmptyState>
            ) : isMobile ? (
              <div>
                {blocks.map((b) => (
                  <BlockCard
                    key={b.ID}
                    block={b}
                    index={index}
                    kernel={kernel}
                    now={now}
                    canWrite={canWrite}
                    selected={sel.has(b.Prefix)}
                    onSelect={(extend) => sel.toggle(b.Prefix, extend)}
                    onUnblock={() => unblock(b)}
                  />
                ))}
              </div>
            ) : (
              <ScrollArea label="Active blocks">
                <table className="sk-rows w-full text-sm">
                  <thead>
                    <tr style={{ color: 'var(--muted)' }}>
                      {canWrite && (
                        <Th>
                          <span className="sr-only">Select</span>
                        </Th>
                      )}
                      <Th>Prefix</Th>
                      <Th>Origin</Th>
                      <Th>Reason</Th>
                      <Th>{dropsLabel(kernel, now)}</Th>
                      <Th>Created</Th>
                      <Th>Expires</Th>
                      {canWrite && <Th> </Th>}
                    </tr>
                  </thead>
                  <tbody>
                    {blocks.map((b) => (
                      <tr key={b.ID} style={{ borderTop: '1px solid var(--border)' }}>
                        {canWrite && (
                          <Td>
                            <SelectBox
                              checked={sel.has(b.Prefix)}
                              label={`Select ${b.Prefix}`}
                              onToggle={(extend) => sel.toggle(b.Prefix, extend)}
                            />
                          </Td>
                        )}
                        <Td mono>
                          <EntityLink value={b.Prefix} index={index} />
                          {blockName(index, b.Prefix) && (
                            <div className="font-sans text-xs" style={{ color: 'var(--muted)' }}>
                              {blockName(index, b.Prefix)}
                            </div>
                          )}
                        </Td>
                        <Td>
                          <Pill tone={b.Origin === 'manual' ? 'accent' : 'neutral'}>{b.Origin}</Pill>
                        </Td>
                        <Td muted>{b.Reason || '—'}</Td>
                        <Td mono>
                          {b.attempts > 0 ? (
                            <>
                              {formatCount(b.attempts)} pkts
                              {b.last_attempt && (
                                <div className="font-sans text-xs" style={{ color: 'var(--muted)' }}>
                                  last {formatRelative(b.last_attempt)}
                                </div>
                              )}
                            </>
                          ) : (
                            <span style={{ color: 'var(--muted)' }}>—</span>
                          )}
                        </Td>
                        <Td muted>{formatTime(b.Created)}</Td>
                        <Td muted>{b.Expires ? formatRelative(b.Expires) : 'permanent'}</Td>
                        {canWrite && (
                          <Td>
                            <button
                              onClick={() => unblock(b)}
                              aria-label={`Unblock ${b.Prefix}`}
                              // Measured at 25px on a coarse pointer: the most
                              // destructive control in the row was the smallest
                              // thing on the page to aim at.
                              className="inline-flex items-center rounded-md px-2 py-1 text-xs font-medium pointer-coarse:min-h-11 pointer-coarse:px-3"
                              style={{ color: 'var(--crit)' }}
                            >
                              Unblock
                            </button>
                          </Td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </ScrollArea>
            )}
          </Card>
        </>
      )}

      <ConfirmDialog
        // A selection can empty itself under a poll — rows expire, and another
        // operator can lift a block from a second browser. Confirming an empty
        // selection would act on nothing while reading as if it acted.
        open={bulkOpen && sel.count > 0}
        title={`Unblock ${sel.count} ${sel.count === 1 ? 'address' : 'addresses'}?`}
        lead={
          recordedOnly(mode)
            ? 'These are recorded blocks; enforcement is off, so nothing is being dropped for them today.'
            : 'Traffic from these addresses will reach this machine again as soon as the rules come out of the kernel.'
        }
        consequence={
          <>
            Each address is unblocked on its own request, so a partial result is normal: if one is refused the
            others still go through. You will get a line per address.
            {sel.count > BULK_LIMIT && ` Only the first ${BULK_LIMIT} will be attempted.`}
          </>
        }
        targets={sel.selected.slice(0, BULK_LIMIT)}
        confirmLabel={bulkBusy ? 'Unblocking…' : `Unblock ${Math.min(sel.count, BULK_LIMIT)}`}
        busy={bulkBusy}
        onConfirm={unblockSelected}
        onCancel={() => setBulkOpen(false)}
      />
    </div>
  )
}

// BlockCard is the phone rendering of one active block.
//
// The table needs 628px and had 364. 42% of every row was past the right edge
// with no scrollbar, no fade and no cue of any kind — and inside that 42% sat
// the Unblock button, the only undo there is for a block. All seven columns
// are here, and Unblock is full width.
function BlockCard({
  block,
  index,
  kernel,
  now,
  canWrite,
  selected,
  onSelect,
  onUnblock,
}: {
  block: Block
  index: DeviceIndex
  kernel: EnforcementState | undefined
  now: number
  canWrite: boolean
  selected: boolean
  onSelect: (extend: boolean) => void
  onUnblock: () => void
}) {
  const name = blockName(index, block.Prefix)
  return (
    <div className="px-4 py-3" style={{ borderTop: '1px solid var(--border)' }}>
      <div className="flex flex-wrap items-center gap-2">
        {canWrite && <SelectBox checked={selected} label={`Select ${block.Prefix}`} onToggle={onSelect} />}
        <span className="min-w-0 break-all font-mono text-sm">
          <EntityLink value={block.Prefix} index={index} />
        </span>
        <Pill tone={block.Origin === 'manual' ? 'accent' : 'neutral'}>{block.Origin}</Pill>
      </div>
      {name && (
        <div className="text-xs" style={{ color: 'var(--muted)' }}>
          {name}
        </div>
      )}
      <div className="mt-1 text-xs" style={{ color: 'var(--muted)' }}>
        {block.Reason || 'no reason recorded'}
      </div>
      <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 font-mono text-[0.7rem]" style={{ color: 'var(--muted)' }}>
        {/* "dropped" is a claim about the kernel. It is only made when the
            kernel was read back and said so. */}
        <span>{block.attempts > 0 ? dropsPhrase(kernel, now, `${formatCount(block.attempts)} pkts`) : 'nothing seen yet'}</span>
        {block.last_attempt && <span>last {formatRelative(block.last_attempt)}</span>}
        <span>added {formatTime(block.Created)}</span>
        <span>{block.Expires ? `expires ${formatRelative(block.Expires)}` : 'permanent'}</span>
      </div>
      {canWrite && (
        <Button
          variant="danger"
          onClick={onUnblock}
          aria-label={`Unblock ${block.Prefix}`}
          className="mt-2.5 min-h-11 w-full"
        >
          Unblock
        </Button>
      )}
    </div>
  )
}

// CountryBlocking manages the blocked-country list. Preventive: the listed
// countries' networks are loaded into the kernel as soon as the GeoIP
// database is there, so their traffic is dropped before it reaches any
// service; the reactive detector still catches stragglers on sight.
function CountryBlocking({
  canWrite,
  onUnauthorized,
  kernel,
}: {
  canWrite: boolean
  onUnauthorized: () => void
  kernel: EnforcementState | undefined
}) {
  const { data, error, refresh } = useFetch<GeoIPSummary>('/api/geoip/summary?window=1h', { onUnauthorized })
  // `add` is a hand-off from a country bar on Traffic: it prefills the field
  // and stops there. Arriving from a link must never be the same act as
  // blocking a country.
  const [prefill, setPrefill] = useUrlState('add', '')
  // null means untouched, so clearing the field to empty stays empty instead
  // of falling back to the prefill and refilling itself under the cursor.
  const [typed, setTyped] = useState<string | null>(null)
  const [removing, setRemoving] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const outcomes = useOutcomes()
  const input = typed ?? prefill
  const blocked = data?.blocked ?? []
  const prefixCounts = data?.blocked_prefixes ?? {}

  const setInput = (v: string) => {
    setTyped(v)
    if (prefill) setPrefill('')
  }

  // Country blocking is the one path where "recorded, kernel unconfirmed" is
  // the normal outcome rather than a fault: the endpoint stores the list and a
  // separate loop loads the prefixes. The response cannot speak for the kernel,
  // so nothing here says "blocked" — the count beside the flag is the evidence,
  // and it arrives later.
  const save = async (countries: string[]): Promise<boolean> => {
    setBusy(true)
    try {
      await api.post('/api/geoip/blocked', { countries })
      setTyped(null)
      setPrefill('')
      return true
    } catch (e) {
      if ((e as { status?: number }).status === 401) {
        onUnauthorized()
        return false
      }
      outcomes.report({ tone: 'crit', message: countryError(e) })
      return false
    } finally {
      setBusy(false)
      refresh()
    }
  }

  const add = async () => {
    const code = input.trim().toUpperCase()
    if (!code) return
    if (blocked.includes(code)) {
      outcomes.report({ tone: 'neutral', message: `${countryName(code)} is already on the blocked list.` })
      return
    }
    if (!(await save([...blocked, code]))) return
    outcomes.report({
      tone: 'accent',
      message: `${countryName(code)} added. Its networks load into the kernel within a minute — the count beside the flag is the proof.`,
      undo: { label: 'Undo', run: () => undoCountry(blocked, `${countryName(code)} is not blocked again.`) },
    })
  }

  const remove = async (code: string) => {
    const before = blocked
    setRemoving(null)
    if (!(await save(blocked.filter((x) => x !== code)))) return
    outcomes.report({
      tone: 'accent',
      message: `${countryName(code)} removed. Its networks clear from the kernel within a minute.`,
      undo: { label: 'Undo', run: () => undoCountry(before, `${countryName(code)} is on the blocked list again — its networks reload within a minute.`) },
    })
  }

  const undoCountry = async (list: string[], done: string): Promise<OutcomeSpec> => {
    try {
      await api.post('/api/geoip/blocked', { countries: list })
      return { tone: 'accent', message: done }
    } catch (e) {
      return { tone: 'crit', message: `The list was not put back: ${countryError(e)}` }
    } finally {
      refresh()
    }
  }

  const pending = removing ? prefixCounts[removing] : undefined

  return (
    <Card>
      <CardHeader
        title="Country blocking"
        sub="these countries' networks are dropped on the way in (when enforcement is on) — established connections you opened yourself stay untouched"
      />
      <div className="flex flex-col gap-2.5 px-4 pb-4">
        <OutcomeStrip items={outcomes.items} dismiss={outcomes.dismiss} replace={outcomes.replace} />
        <div className="flex flex-wrap items-center gap-1.5">
          {blocked.length === 0 &&
            (error || !data ? (
              // "No countries blocked" is a claim. Without an answer from the
              // server we do not get to make it.
              <span className="text-sm" style={{ color: 'var(--warn)' }}>
                Could not read the blocked-country list — this is not a confirmed empty list.
              </span>
            ) : (
              <span className="text-sm" style={{ color: 'var(--muted)' }}>No countries blocked.</span>
            ))}
          {blocked.map((c) => (
            <span
              key={c}
              className="inline-flex items-center gap-1.5 rounded-full py-0.5 pl-2 pr-1 text-xs font-medium pointer-coarse:min-h-11 pointer-coarse:pl-3"
              style={{ background: 'var(--crit-tint)', color: 'var(--crit)' }}
            >
              {countryFlag(c)} {countryName(c)}
              {prefixCounts[c] > 0 && (
                <span className="font-mono opacity-75" title={`${prefixCounts[c]} networks loaded into the firewall`}>
                  · {formatCount(prefixCounts[c])} nets
                </span>
              )}
              {canWrite && (
                <button
                  onClick={() => setRemoving(c)}
                  aria-label={`Unblock ${countryName(c)}`}
                  // 15×16 was the smallest target in the app, and it removes a
                  // country-wide firewall rule.
                  className="inline-flex h-6 w-6 items-center justify-center rounded-full font-mono pointer-coarse:h-10 pointer-coarse:w-10"
                >
                  ×
                </button>
              )}
            </span>
          ))}
        </div>
        {canWrite && (
          <div className="flex items-center gap-2">
            <div className="w-40">
              <TextInput
                value={input}
                onChange={setInput}
                mono
                placeholder="ISO code, e.g. RU"
                onKeyDown={(e) => e.key === 'Enter' && add()}
              />
            </div>
            <Button onClick={add} loading={busy} disabled={!input.trim()}>Block country</Button>
          </div>
        )}
      </div>

      {/* Confirmed, not merely undoable: undo is cheap to request and slow to
          apply here, because the prefixes reload through a separate loop. The
          count is the part an operator cannot see from the × alone. */}
      <ConfirmDialog
        open={removing !== null}
        title={`Stop blocking ${removing ? countryName(removing) : ''}?`}
        lead={
          pending && pending > 0
            ? `This removes ${formatCount(pending)} networks from the kernel.`
            : 'Skopos has not loaded this country’s networks into the kernel yet, so it cannot say how many networks this is.'
        }
        consequence={
          <>
            Traffic from {removing ? countryName(removing) : 'this country'} reaches this machine again once the
            list reloads, which takes up to a minute. Undo is the same round trip in reverse — it is not instant.
            {kernel && kernel.mode !== 'enforce' && ' Enforcement is off, so nothing is being dropped for it today either way.'}
          </>
        }
        confirmLabel="Stop blocking"
        busy={busy}
        onConfirm={() => removing && remove(removing)}
        onCancel={() => setRemoving(null)}
      />
    </Card>
  )
}

// countryError keeps Go's 501 out of the operator's face. Everything else is
// already prose by the time it reaches here.
function countryError(e: unknown): string {
  if ((e as { status?: number }).status === 501) return 'Country blocking is not available in this build.'
  return humanError(e, 'apply')
}

function Field({
  label,
  value,
  onChange,
  placeholder,
  width,
}: {
  label: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
  width: string
}) {
  return (
    <label className={`flex flex-col gap-1 ${width}`}>
      <span className="font-mono text-[0.62rem] font-semibold uppercase tracking-[0.1em]" style={{ color: 'var(--muted)' }}>
        {label}
      </span>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="rounded-md border px-2.5 py-1.5 text-sm font-mono"
        style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text)' }}
      />
    </label>
  )
}
