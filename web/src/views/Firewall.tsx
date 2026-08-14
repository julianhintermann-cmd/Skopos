import { useState, type ReactNode } from 'react'
import { useFetch } from '../lib/useFetch'
import { api, countryFlag, countryName, type Block, type BlocksResponse, type GeoIPSummary } from '../lib/api'
import { Card, CardHeader, Spinner, EmptyState, Button, Pill, TextInput, ScrollArea, useToast } from '../components/ui'
import { SegmentedControl } from '../components/RangeControl'
import { EntityLink } from '../components/entity'
import { PageTitle } from '../components/PageTitle'
import { Th, Td } from './Devices'
import { useDeviceIndex, type DeviceIndex } from '../lib/links'
import { useIsMobile } from '../lib/useIsMobile'
import { useUrlState } from '../lib/useUrlState'
import { formatCount, formatRelative, formatTime } from '../lib/format'
import { humanError } from '../components/humanError'

// blockName resolves a blocked prefix to a device name when it is a single
// host that the inventory knows (strip the /32 or /128 the API normalises to).
function blockName(index: DeviceIndex, prefix: string): string {
  const host = prefix.replace(/\/(32|128)$/, '')
  return index.names.get(host) ?? ''
}

const TABS = ['blocks', 'countries'] as const
type Tab = (typeof TABS)[number]

export function Firewall({ onUnauthorized, canWrite }: { onUnauthorized: () => void; canWrite: boolean }) {
  const [tab, setTab] = useUrlState<Tab>('tab', 'blocks', { valid: TABS, history: 'push' })
  const { data, loading, error, refresh } = useFetch<BlocksResponse>('/api/blocks', {
    pollMs: 5000,
    onUnauthorized,
  })
  const toast = useToast()
  const [prefix, setPrefix] = useState('')
  const [reason, setReason] = useState('')
  const [ttl, setTtl] = useState('')
  const [busy, setBusy] = useState(false)
  const [formError, setFormError] = useState('')
  const index = useDeviceIndex(onUnauthorized)
  const isMobile = useIsMobile()

  const blocks = data?.blocks ?? []

  const addBlock = async () => {
    setBusy(true)
    setFormError('')
    try {
      await api.post('/api/blocks', { prefix, reason, ttl })
      setPrefix('')
      setReason('')
      setTtl('')
      refresh()
    } catch (e) {
      setFormError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  // Every outcome is said out loud. This await used to stand bare, unlike the
  // block path directly above it, so a 409 carrying "the block is still in
  // place" became an unhandled rejection: the row vanished from nothing, the
  // list refreshed, and the operator walked away believing an address was
  // unblocked that the kernel was still dropping.
  const unblock = async (p: string) => {
    try {
      await api.del(`/api/blocks?prefix=${encodeURIComponent(p)}`)
      toast.show({ message: `${p} is no longer blocked.`, tone: 'ok' })
    } catch (e) {
      toast.show({ message: humanError(e, 'unblock'), tone: 'crit', ttlMs: 9000 })
    } finally {
      refresh()
    }
  }

  const observing = data?.enforcement === 'observe'
  const degraded = data?.enforcement === 'enforce' && data?.enforcing === false

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
      {observing && (
        <Banner tone="warn" title="Observe mode — nothing is actually blocked">
          Blocks are recorded and counted, but the kernel drops no packets, so traffic from
          blocked addresses and countries keeps flowing. When the numbers below look right, arm
          the firewall with <code className="font-mono">firewall.enforcement: enforce</code> in
          config.yaml and restart Skopos.
        </Banner>
      )}
      {degraded && (
        <Banner tone="crit" title="Enforce is set, but the firewall backend is unavailable">
          Skopos cannot program nftables, so blocks are recorded but not applied. The container
          needs <code className="font-mono">network_mode: host</code> and the{' '}
          <code className="font-mono">NET_ADMIN</code> capability, and the kernel must have
          nf_tables. Check the System view and container logs.
        </Banner>
      )}
      {tab === 'countries' && <CountryBlocking canWrite={canWrite} onUnauthorized={onUnauthorized} />}

      {tab === 'blocks' && canWrite && (
        <Card className="px-4 py-3.5">
          <CardHeader title="Block an address" sub="IP or CIDR — never blocks the gateway or allowlist" />
          <div className="mt-2 flex flex-wrap items-end gap-2 px-0">
            <Field label="Prefix" value={prefix} onChange={setPrefix} placeholder="203.0.113.5 or 203.0.113.0/24" width="w-56" />
            <Field label="Reason" value={reason} onChange={setReason} placeholder="optional note" width="w-48" />
            <Field label="TTL" value={ttl} onChange={setTtl} placeholder="24h · blank = permanent" width="w-40" />
            <Button variant="primary" onClick={addBlock} disabled={busy || !prefix}>
              Block
            </Button>
          </div>
          {formError && <p className="mt-2 text-xs" style={{ color: 'var(--crit)' }}>{formError}</p>}
        </Card>
      )}

      {tab === 'blocks' && (
      <Card>
        <CardHeader
          title="Active blocks"
          sub={
            data?.enforcing
              ? `${blocks.length} enforced — blocked packets are still visible to the monitor (capture taps the wire before the firewall), counted here as they are dropped`
              : `${blocks.length} recorded`
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
                enforcing={!!data?.enforcing}
                canWrite={canWrite}
                onUnblock={() => unblock(b.Prefix)}
              />
            ))}
          </div>
        ) : (
          <ScrollArea label="Active blocks">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ color: 'var(--muted)' }}>
                  <Th>Prefix</Th>
                  <Th>Origin</Th>
                  <Th>Reason</Th>
                  <Th>{data?.enforcing ? 'Dropped' : 'Would drop'}</Th>
                  <Th>Created</Th>
                  <Th>Expires</Th>
                  {canWrite && <Th> </Th>}
                </tr>
              </thead>
              <tbody>
                {blocks.map((b) => (
                  <tr key={b.ID} style={{ borderTop: '1px solid var(--border)' }}>
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
                          onClick={() => unblock(b.Prefix)}
                          aria-label={`Unblock ${b.Prefix}`}
                          className="rounded-md px-2 py-1 text-xs font-medium"
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
      )}
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
  enforcing,
  canWrite,
  onUnblock,
}: {
  block: Block
  index: DeviceIndex
  enforcing: boolean
  canWrite: boolean
  onUnblock: () => void
}) {
  const name = blockName(index, block.Prefix)
  return (
    <div className="px-4 py-3" style={{ borderTop: '1px solid var(--border)' }}>
      <div className="flex flex-wrap items-center gap-2">
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
        <span>
          {block.attempts > 0
            ? `${formatCount(block.attempts)} pkts ${enforcing ? 'dropped' : 'would have been dropped'}`
            : enforcing
              ? 'nothing dropped yet'
              : 'nothing seen yet'}
        </span>
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

// Banner is the view's loud qualifier: a firewall page listing "active blocks"
// while nothing is enforced would be a lie by omission.
function Banner({ tone, title, children }: { tone: 'warn' | 'crit'; title: string; children: ReactNode }) {
  const color = tone === 'warn' ? 'var(--warn)' : 'var(--crit)'
  const bg = tone === 'warn' ? 'var(--warn-tint)' : 'var(--crit-tint)'
  return (
    <div className="rounded-lg border px-4 py-3" style={{ background: bg, borderColor: color }}>
      <p className="text-sm font-semibold" style={{ color }}>
        {title}
      </p>
      <p className="mt-1 text-sm" style={{ color: 'var(--text)' }}>
        {children}
      </p>
    </div>
  )
}

// CountryBlocking manages the blocked-country list. Preventive: the listed
// countries' networks are loaded into the kernel as soon as the GeoIP
// database is there, so their traffic is dropped before it reaches any
// service; the reactive detector still catches stragglers on sight.
function CountryBlocking({ canWrite, onUnauthorized }: { canWrite: boolean; onUnauthorized: () => void }) {
  const { data, error, refresh } = useFetch<GeoIPSummary>('/api/geoip/summary?window=1h', { onUnauthorized })
  // `add` is a hand-off from a country bar on Traffic: it prefills the field
  // and stops there. Arriving from a link must never be the same act as
  // blocking a country.
  const [prefill, setPrefill] = useUrlState('add', '')
  // null means untouched, so clearing the field to empty stays empty instead
  // of falling back to the prefill and refilling itself under the cursor.
  const [typed, setTyped] = useState<string | null>(null)
  const [err, setErr] = useState('')
  const input = typed ?? prefill
  const blocked = data?.blocked ?? []
  const prefixCounts = data?.blocked_prefixes ?? {}

  const setInput = (v: string) => {
    setTyped(v)
    if (prefill) setPrefill('')
  }

  const save = async (countries: string[]) => {
    setErr('')
    try {
      await api.post('/api/geoip/blocked', { countries })
      setTyped(null)
      setPrefill('')
      refresh()
    } catch (e) {
      if ((e as { status?: number }).status === 401) return onUnauthorized()
      setErr((e as Error).message)
    }
  }

  const add = () => {
    const code = input.trim().toUpperCase()
    if (!code) return
    save([...blocked, code])
  }

  return (
    <Card>
      <CardHeader
        title="Country blocking"
        sub="these countries' networks are dropped on the way in (when enforcement is on) — established connections you opened yourself stay untouched"
      />
      <div className="flex flex-col gap-2.5 px-4 pb-4">
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
                  onClick={() => save(blocked.filter((x) => x !== c))}
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
            <Button onClick={add} disabled={!input.trim()}>Block country</Button>
            {err && <span className="text-xs" style={{ color: 'var(--crit)' }}>{err}</span>}
          </div>
        )}
      </div>
    </Card>
  )
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
