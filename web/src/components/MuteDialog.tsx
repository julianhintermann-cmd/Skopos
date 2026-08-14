import { useState } from 'react'
import { api, type Incident } from '../lib/api'
import { Card, CardHeader, Button } from './ui'
import { FieldLabel } from './BlockDialog'

// MuteDialog creates a suppression rule prefilled from an incident. Lifted out
// of the alerts list alongside BlockDialog so the incident page offers the
// same three actions as the row it came from.
export function MuteDialog({
  incident,
  onClose,
  onDone,
}: {
  incident: Incident
  onClose: () => void
  onDone: () => void
}) {
  const [scope, setScope] = useState<'source' | 'detector' | 'both'>('both')
  const [ttl, setTtl] = useState('')
  const [reason, setReason] = useState('')
  const [err, setErr] = useState('')
  const detector = incident.detectors?.[0] ?? ''

  const save = async () => {
    setErr('')
    try {
      await api.post('/api/mutes', {
        prefix: scope === 'detector' ? '' : incident.source,
        detector: scope === 'source' ? '' : detector,
        ttl,
        reason,
      })
      onDone()
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  return (
    <Card className="px-4 py-3.5">
      <CardHeader
        title="Mute these alerts"
        sub="stops the alert and the notification — blocking is unaffected, so protection stays exactly as it is"
      />
      <div className="mt-2 flex flex-wrap items-end gap-3">
        <div className="flex flex-col gap-1">
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
                className="rounded-md px-2.5 py-1 text-xs font-medium"
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
        <label className="flex w-32 flex-col gap-1">
          <FieldLabel>For</FieldLabel>
          <input
            value={ttl}
            onChange={(e) => setTtl(e.target.value)}
            placeholder="24h · blank = forever"
            className="rounded-md border px-2.5 py-1.5 font-mono text-sm"
            style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text)' }}
          />
        </label>
        <label className="flex w-48 flex-col gap-1">
          <FieldLabel>Reason</FieldLabel>
          <input
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="optional note"
            className="rounded-md border px-2.5 py-1.5 text-sm"
            style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text)' }}
          />
        </label>
        <Button variant="primary" onClick={save}>
          Mute
        </Button>
        <Button onClick={onClose}>Cancel</Button>
      </div>
      {err && <p className="mt-2 text-xs" style={{ color: 'var(--crit)' }}>{err}</p>}
    </Card>
  )
}
