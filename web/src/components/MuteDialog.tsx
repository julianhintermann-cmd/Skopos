import { useEffect, useRef, useState } from 'react'
import { api, type Incident, type MuteRule } from '../lib/api'
import { Card, CardHeader, Button } from './ui'
import { FieldLabel } from './BlockDialog'

// MuteDialog creates a suppression rule prefilled from an incident. Lifted out
// of the alerts list alongside BlockDialog so the incident page offers the
// same three actions as the row it came from.
export function MuteDialog({
  incident,
  onClose,
  onDone,
  variant = 'card',
}: {
  incident: Incident
  onClose: () => void
  // The created rule comes back with its id, which is the whole inverse:
  // DELETE /api/mutes/{id}. Handing it to the caller is what makes an undo
  // possible at all — reconstructing the rule from the form would only find it
  // by guessing.
  onDone: (created: MuteRule | null) => void
  // 'row' drops the card chrome so the panel can sit inside the <li> of the
  // row it belongs to. See BlockDialog: the form's justification is the
  // surrounding row.
  variant?: 'card' | 'row'
}) {
  const card = useRef<HTMLDivElement>(null)
  const [scope, setScope] = useState<'source' | 'detector' | 'both'>('both')
  const [ttl, setTtl] = useState('')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [asking, setAsking] = useState(false)
  const [err, setErr] = useState('')
  const detector = incident.detectors?.[0] ?? ''

  // BlockDialog got away with rendering above the list because autoFocus on
  // its note input dragged it into view. This one had no autofocus at all, so
  // tapping Mute on a phone did nothing you could see: the dialog opened at
  // the top of the document, several screens up.
  useEffect(() => {
    card.current?.scrollIntoView({ block: 'nearest' })
  }, [])

  // A typed reason is not thrown away by a keystroke. Same rule as the block
  // panel, for the same reason: the reason field is the only record of why
  // these alerts stopped arriving.
  const close = () => {
    if (reason.trim()) setAsking(true)
    else onClose()
  }

  const save = async () => {
    setBusy(true)
    setErr('')
    try {
      const created = await api.post<MuteRule>('/api/mutes', {
        prefix: scope === 'detector' ? '' : incident.source,
        detector: scope === 'source' ? '' : detector,
        ttl,
        reason,
      })
      onDone(created && typeof created.id === 'number' ? created : null)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const body = (
    <>
      <CardHeader
        title="Mute these alerts"
        sub="stops the alert and the notification — blocking is unaffected, so protection stays exactly as it is"
      />
      <div className="mt-2 flex flex-wrap items-end gap-3">
        <div className="flex min-w-0 flex-col gap-1">
          <FieldLabel>Scope</FieldLabel>
          <div className="flex flex-wrap items-center gap-1.5">
            {([
              ['both', `${detector} from ${incident.source}`],
              ['source', `anything from ${incident.source}`],
              ['detector', `${detector} from anywhere`],
            ] as const).map(([v, label]) => (
              <button
                key={v}
                onClick={() => setScope(v)}
                aria-pressed={scope === v}
                // Each label carries the source address, so the same IPv6 that
                // broke BlockDialog is in here three times over.
                className="max-w-full break-all rounded-md px-2.5 py-1 text-left text-xs font-medium pointer-coarse:min-h-11"
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
        <label className="flex w-32 max-w-full flex-col gap-1">
          <FieldLabel>For</FieldLabel>
          <input
            value={ttl}
            onChange={(e) => setTtl(e.target.value)}
            placeholder="24h · blank = forever"
            className="rounded-md border px-2.5 py-1.5 font-mono text-sm"
            style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text)' }}
          />
        </label>
        <label className="flex w-48 max-w-full flex-col gap-1">
          <FieldLabel>Reason</FieldLabel>
          <input
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !busy) save()
              if (e.key === 'Escape') close()
            }}
            placeholder="optional note"
            className="rounded-md border px-2.5 py-1.5 text-sm"
            style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text)' }}
          />
        </label>
        {asking ? (
          <div className="flex flex-wrap items-center gap-2 rounded-md px-3 py-2" style={{ background: 'var(--warn-tint)' }}>
            <span className="text-xs" style={{ color: 'var(--text)' }}>
              Discard the reason you have typed?
            </span>
            <Button onClick={onClose}>
              Discard
            </Button>
            <Button variant="primary" onClick={() => setAsking(false)}>
              Keep editing
            </Button>
          </div>
        ) : (
          <>
            <Button variant="primary" onClick={save} loading={busy}>
              Mute
            </Button>
            <Button onClick={close}>
              Cancel
            </Button>
          </>
        )}
      </div>
      {err && <p className="mt-2 text-xs" style={{ color: 'var(--crit)' }}>{err}</p>}
    </>
  )

  if (variant === 'row') {
    return (
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
