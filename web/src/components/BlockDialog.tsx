import { useEffect, useRef, useState } from 'react'
import { useFetch } from '../lib/useFetch'
import { api, coveredByProtected, networkPrefix, type BlocksResponse } from '../lib/api'
import { Card, CardHeader, Button } from './ui'
import { formatTime } from '../lib/format'

// BlockDialog blocks an address. Lifted out of the alerts list so the incident
// page and the address dossier open the same dialog rather than each growing
// their own.
//
// Three things decide whether this is safe to put one tap away: it says how
// far the block reaches, it says whether the block will actually drop anything
// (in observe mode it will not), and it refuses the addresses that would lock
// the operator out. The note is not decoration — in a month, "why is this
// blocked?" is the only question that matters, and the audit log and the
// Firewall view both carry the answer through.
export function BlockDialog({
  source,
  detector,
  onClose,
  onDone,
  onUnauthorized,
}: {
  source: string
  detector: string
  onClose: () => void
  onDone: () => void
  onUnauthorized: () => void
}) {
  const { data } = useFetch<BlocksResponse>('/api/blocks', { pollMs: 0, onUnauthorized })
  const card = useRef<HTMLDivElement>(null)
  const [scope, setScope] = useState<'address' | 'network'>('address')
  const [ttl, setTtl] = useState('24h')
  const [note, setNote] = useState(detector ? `${detector} alert` : '')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  const prefix = scope === 'network' ? networkPrefix(source) : source
  const enforcing = data?.enforcing ?? false
  const existing = (data?.blocks ?? []).find((b) => b.Prefix === prefix || b.Prefix === `${source}/32` || b.Prefix === `${source}/128`)
  const clash = coveredByProtected(source, scope, data?.protected ?? [])

  // This dialog renders above the list that opened it. Tap Block on the fifth
  // incident on a phone and it appears at the top of the document, off-screen,
  // with nothing to say it happened.
  useEffect(() => {
    card.current?.scrollIntoView({ block: 'nearest' })
  }, [])

  const save = async () => {
    setBusy(true)
    setErr('')
    try {
      await api.post('/api/blocks', { prefix, reason: note.trim(), ttl: ttl.trim() })
      onDone()
    } catch (e) {
      if ((e as { status?: number }).status === 401) return onUnauthorized()
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div ref={card}>
    <Card className="px-4 py-3.5">
      <CardHeader
        // One of the three things that pushed document.scrollWidth to 586px at
        // a 390px viewport: an IPv6 address in a heading has no break
        // opportunity — `:` is not one — so `Block 2001:db8::…` ran straight
        // off the card and took the page with it. The address breaks; the word
        // does not.
        title={
          <>
            Block <span className="break-all font-mono">{source}</span>
          </>
        }
        sub={
          enforcing
            ? 'dropped in the kernel on the machine running Skopos — traffic that does not pass this machine is unaffected'
            : 'enforcement is off: this will be recorded and counted, but nothing will actually be dropped'
        }
      />

      {!enforcing && (
        <p className="mt-1 rounded-md px-3 py-2 text-xs" style={{ background: 'var(--warn-tint)', color: 'var(--text)' }}>
          Skopos is in observe mode. The block is saved and the Firewall view will count what it would have
          dropped, but the packets keep arriving. Turn enforcement on in Settings to make it real.
        </p>
      )}
      {existing && (
        <p className="mt-1 rounded-md px-3 py-2 text-xs" style={{ background: 'var(--surface-2)', color: 'var(--muted)' }}>
          {existing.Prefix} is already blocked
          {existing.Expires ? ` until ${formatTime(existing.Expires)}` : ' permanently'}. Blocking again replaces it.
        </p>
      )}
      {clash && (
        <p className="mt-1 rounded-md px-3 py-2 text-xs" style={{ background: 'var(--crit-tint)', color: 'var(--crit)' }}>
          This covers {clash}, which is on the never-block list. Skopos will refuse it — remove it from the
          allowlist in Settings first if you really mean it.
        </p>
      )}

      {/* The outer row already wrapped. The overflow came from its children:
          two rows of `flex items-center` with no wrap of their own, holding an
          IPv6 address and a five-control TTL group. Measured min-content 557px
          and 358px inside a 332px card. */}
      <div className="mt-2 flex flex-wrap items-end gap-3">
        <div className="flex min-w-0 flex-col gap-1">
          <FieldLabel>Scope</FieldLabel>
          <div className="flex flex-wrap items-center gap-1.5">
            {([
              ['address', source],
              ['network', networkPrefix(source)],
            ] as const).map(([v, label]) => (
              <button
                key={v}
                onClick={() => setScope(v)}
                aria-pressed={scope === v}
                className="max-w-full break-all rounded-md px-2.5 py-1 text-left font-mono text-xs font-medium pointer-coarse:min-h-11"
                style={
                  scope === v
                    ? { background: 'var(--accent-tint)', color: 'var(--accent-strong)' }
                    : { background: 'var(--surface-2)', color: 'var(--muted)' }
                }
              >
                {label}
              </button>
            ))}
          </div>
        </div>

        <div className="flex min-w-0 flex-col gap-1">
          <FieldLabel>For</FieldLabel>
          <div className="flex flex-wrap items-center gap-1.5">
            {['1h', '24h', '7d', ''].map((v) => (
              <button
                key={v || 'forever'}
                onClick={() => setTtl(v)}
                aria-pressed={ttl === v}
                className="rounded-md px-2.5 py-1 text-xs font-medium pointer-coarse:min-h-11 pointer-coarse:px-3"
                style={
                  ttl === v
                    ? { background: 'var(--accent-tint)', color: 'var(--accent-strong)' }
                    : { background: 'var(--surface-2)', color: 'var(--muted)' }
                }
              >
                {v || 'permanent'}
              </button>
            ))}
            <input
              value={ttl}
              onChange={(e) => setTtl(e.target.value)}
              aria-label="Block duration"
              placeholder="blank = permanent"
              className="w-36 max-w-full rounded-md border px-2.5 py-1.5 font-mono text-sm"
              style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text)' }}
            />
          </div>
        </div>
      </div>

      <label className="mt-3 flex flex-col gap-1">
        <FieldLabel>Note</FieldLabel>
        <input
          autoFocus
          value={note}
          onChange={(e) => setNote(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !busy) save()
            if (e.key === 'Escape') onClose()
          }}
          placeholder="why — you will read this in a month and want to know"
          className="rounded-md border px-2.5 py-1.5 text-sm"
          style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text)' }}
        />
      </label>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Button variant="primary" onClick={save} disabled={busy} className="pointer-coarse:min-h-11">
          {busy ? 'Blocking…' : ttl.trim() ? `Block for ${ttl.trim()}` : 'Block permanently'}
        </Button>
        <Button onClick={onClose} className="pointer-coarse:min-h-11">
          Cancel
        </Button>
      </div>
      {err && <p className="mt-2 text-xs" style={{ color: 'var(--crit)' }}>{err}</p>}
    </Card>
    </div>
  )
}

export function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <span className="font-mono text-[0.62rem] font-semibold uppercase tracking-[0.1em]" style={{ color: 'var(--muted)' }}>
      {children}
    </span>
  )
}
