import { useEffect, useRef, useState } from 'react'
import { useFetch } from '../lib/useFetch'
import { api, coveredByProtected, networkPrefix } from '../lib/api'
import type { BlocksPayload } from '../lib/contracts'
import { Card, CardHeader, Button } from './ui'
import { KernelStatusLine } from './KernelVerdict'
import { formatTime } from '../lib/format'

// What the block that was just applied covered, handed back so the caller can
// offer the exact inverse. Without it the caller would have to reconstruct the
// prefix from the scope toggle, which is the dialog's own business.
export interface BlockApplied {
  prefix: string
  ttl: string
  note: string
}

// BlockDialog blocks an address. Lifted out of the alerts list so the incident
// page and the address dossier open the same dialog rather than each growing
// their own.
//
// Three things decide whether this is safe to put one tap away: it says how
// far the block reaches, it says whether the block will actually drop anything
// (in observe mode it will not, and in enforce mode only if the kernel is
// confirmed to be holding Skopos's rules), and it refuses the addresses that
// would lock the operator out. The note is not decoration — in a month, "why
// is this blocked?" is the only question that matters, and the audit log and
// the Firewall view both carry the answer through.
export function BlockDialog({
  source,
  detector,
  onClose,
  onDone,
  onUnauthorized,
  variant = 'card',
}: {
  source: string
  detector: string
  onClose: () => void
  onDone: (applied: BlockApplied) => void
  onUnauthorized: () => void
  // 'row' drops the card chrome so the panel can sit inside the <li> of the
  // row it belongs to — the disclosure pattern the alert list already uses for
  // events and reputation. The form's justification is the surrounding row, so
  // that is where it belongs; mounted at page level it is a full viewport away
  // from the thing it is about.
  variant?: 'card' | 'row'
}) {
  const { data } = useFetch<BlocksPayload>('/api/blocks', { pollMs: 0, onUnauthorized })
  const card = useRef<HTMLDivElement>(null)
  const [scope, setScope] = useState<'address' | 'network'>('address')
  const [ttl, setTtl] = useState('24h')
  const [note, setNote] = useState(detector ? `${detector} alert` : '')
  const [busy, setBusy] = useState(false)
  const [dirty, setDirty] = useState(false)
  const [asking, setAsking] = useState(false)
  const [err, setErr] = useState('')

  const prefix = scope === 'network' ? networkPrefix(source) : source
  const kernel = data?.kernel
  const enforcing = data?.enforcement === 'enforce'
  const existing = (data?.blocks ?? []).find((b) => b.Prefix === prefix || b.Prefix === `${source}/32` || b.Prefix === `${source}/128`)
  const clash = coveredByProtected(source, scope, data?.protected ?? [])

  // This dialog renders above the list that opened it. Tap Block on the fifth
  // incident on a phone and it appears at the top of the document, off-screen,
  // with nothing to say it happened. `nearest` so a row already in view does
  // not move under the thumb that tapped it.
  useEffect(() => {
    card.current?.scrollIntoView({ block: 'nearest' })
  }, [])

  // Escape closes, unless there is a typed note to lose. The note is the one
  // field that exists to answer "why did I block this in a month", and a
  // keystroke — or, on a phone, a stray thumb on a backdrop — must not be able
  // to discard it silently.
  const close = () => {
    if (dirty && note.trim()) setAsking(true)
    else onClose()
  }

  const save = async () => {
    setBusy(true)
    setErr('')
    const applied = { prefix, ttl: ttl.trim(), note: note.trim() }
    try {
      await api.post('/api/blocks', { prefix: applied.prefix, reason: applied.note, ttl: applied.ttl })
      onDone(applied)
    } catch (e) {
      if ((e as { status?: number }).status === 401) return onUnauthorized()
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const body = (
    <>
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
            ? // "applied", not "dropped": what Skopos does is program the rule.
              // Whether the kernel is holding it is the line underneath.
              'applied to the kernel of the machine running Skopos — traffic that does not pass this machine is unaffected'
            : 'enforcement is off: this will be recorded and counted, but nothing will actually be dropped'
        }
      />

      {/* What the kernel was last found to hold, before the block is placed
          rather than after. "It will be dropped" is a claim about a kernel
          nobody may have looked at for six minutes. */}
      {enforcing && (
        <div className="px-4">
          <KernelStatusLine state={kernel} prefix="Kernel:" />
        </div>
      )}

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
                onClick={() => {
                  setScope(v)
                  setDirty(true)
                }}
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
                onClick={() => {
                  setTtl(v)
                  setDirty(true)
                }}
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
              onChange={(e) => {
                setTtl(e.target.value)
                setDirty(true)
              }}
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
          onChange={(e) => {
            setNote(e.target.value)
            setDirty(true)
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !busy) save()
            if (e.key === 'Escape') close()
          }}
          placeholder="why — you will read this in a month and want to know"
          className="rounded-md border px-2.5 py-1.5 text-sm"
          style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text)' }}
        />
      </label>

      {asking ? (
        <div className="mt-3 flex flex-wrap items-center gap-2 rounded-md px-3 py-2" style={{ background: 'var(--warn-tint)' }}>
          <span className="text-xs" style={{ color: 'var(--text)' }}>
            Discard the note you have typed?
          </span>
          <Button onClick={onClose} className="pointer-coarse:min-h-11">
            Discard
          </Button>
          <Button variant="primary" onClick={() => setAsking(false)} className="pointer-coarse:min-h-11">
            Keep editing
          </Button>
        </div>
      ) : (
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <Button variant="primary" onClick={save} loading={busy} className="pointer-coarse:min-h-11">
            {ttl.trim() ? `Block for ${ttl.trim()}` : 'Block permanently'}
          </Button>
          <Button onClick={close} className="pointer-coarse:min-h-11">
            Cancel
          </Button>
        </div>
      )}
      {err && <p className="mt-2 text-xs" style={{ color: 'var(--crit)' }}>{err}</p>}
    </>
  )

  if (variant === 'row') {
    return (
      // No card, no shadow, no overlay: inside a row this is a disclosure, and
      // a second elevated surface inside a list item reads as a floating thing
      // that has lost its anchor. The left rule is the anchor.
      <div
        ref={card}
        className="rounded-md border-l-2 pl-3 pr-1 pb-1"
        style={{ borderColor: 'var(--accent)', background: 'var(--surface-2)' }}
      >
        {body}
      </div>
    )
  }

  return (
    <div ref={card}>
      <Card className="px-4 py-3.5">{body}</Card>
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
