import { useState } from 'react'
import { useFetch } from '../lib/useFetch'
import { api, type Alert } from '../lib/api'
import { Card, CardHeader, Spinner, EmptyState, SeverityBadge, Button, Pill } from '../components/ui'
import { useDeviceNames } from '../lib/deviceNames'
import { formatTime } from '../lib/format'

export function Alerts({ onUnauthorized, canWrite }: { onUnauthorized: () => void; canWrite: boolean }) {
  const [unackedOnly, setUnackedOnly] = useState(false)
  const path = `/api/alerts?limit=200${unackedOnly ? '&unacked=true' : ''}`
  const { data, loading, error, refresh } = useFetch<{ alerts: Alert[] | null }>(path, { pollMs: 5000, onUnauthorized })
  const names = useDeviceNames(onUnauthorized)

  const alerts = data?.alerts ?? []

  const ack = async (id: number) => {
    await api.post(`/api/alerts/${id}/ack`)
    refresh()
  }

  return (
    <Card>
      <CardHeader
        title="Alerts"
        sub={`${alerts.length} shown`}
        right={
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--muted)' }}>
              <input type="checkbox" checked={unackedOnly} onChange={(e) => setUnackedOnly(e.target.checked)} />
              Unacknowledged only
            </label>
            <a
              href="/api/export/alerts.csv"
              download
              className="rounded-md px-2.5 py-1 text-xs font-medium"
              style={{ background: 'var(--surface-2)', color: 'var(--muted)' }}
            >
              Export CSV
            </a>
          </div>
        }
      />
      {loading && !data ? (
        <Spinner />
      ) : error ? (
        <EmptyState>Could not load alerts: {error}</EmptyState>
      ) : alerts.length === 0 ? (
        <EmptyState>No alerts. All quiet.</EmptyState>
      ) : (
        <ul>
          {alerts.map((a) => (
            <li
              key={a.ID}
              className="flex items-start gap-3 px-4 py-3"
              style={{ borderTop: '1px solid var(--border)', opacity: a.Ack ? 0.55 : 1 }}
            >
              <div className="pt-0.5">
                <SeverityBadge severity={a.Severity} />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium">{a.Title}</span>
                  {a.Count > 1 && <Pill>{a.Count}×</Pill>}
                  {a.Ack && <Pill tone="good">acked</Pill>}
                </div>
                <div className="text-xs" style={{ color: 'var(--muted)' }}>
                  {a.Detail}
                  {a.Source && (
                    <span className="font-mono">
                      {' · '}
                      {a.Source}
                      {names.get(a.Source) && <span className="font-sans"> ({names.get(a.Source)})</span>}
                    </span>
                  )}
                </div>
              </div>
              <div className="flex shrink-0 items-center gap-3">
                <span className="font-mono text-xs" style={{ color: 'var(--muted)' }}>
                  {formatTime(a.Time)}
                </span>
                {canWrite && !a.Ack && (
                  <Button onClick={() => ack(a.ID)} className="!px-2 !py-1 !text-xs">
                    Ack
                  </Button>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}
