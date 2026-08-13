import { useEffect, useState } from 'react'
import { useFetch } from '../lib/useFetch'
import { api, countryFlag, countryName, type Alert, type ReputationInfo } from '../lib/api'
import { Card, CardHeader, Spinner, EmptyState, SeverityBadge, Button, Pill } from '../components/ui'
import { useDeviceNames } from '../lib/deviceNames'
import { formatTime } from '../lib/format'

// isPublic filters out addresses a WHOIS lookup cannot say anything about.
function isPublic(ip: string): boolean {
  return !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80:|fc|fd)/i.test(ip)
}

// Reputation loads and renders who an external address belongs to.
function Reputation({ ip }: { ip: string }) {
  const [info, setInfo] = useState<ReputationInfo | null>(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    let stop = false
    api
      .get<ReputationInfo>(`/api/reputation?ip=${encodeURIComponent(ip)}`)
      .then((i) => !stop && setInfo(i))
      .catch((e) => !stop && setErr((e as Error).message))
    return () => {
      stop = true
    }
  }, [ip])

  if (err) return <div className="text-xs" style={{ color: 'var(--crit)' }}>Lookup failed: {err}</div>
  if (!info) return <div className="text-xs" style={{ color: 'var(--muted)' }}>Looking up {ip}…</div>

  const score = info.abuse_score
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 rounded-md px-3 py-2 text-xs" style={{ background: 'var(--surface-2)' }}>
      {info.org && <span><span style={{ color: 'var(--muted)' }}>Owner</span> {info.org}{info.handle ? ` (${info.handle})` : ''}</span>}
      {info.country && (
        <span>
          <span style={{ color: 'var(--muted)' }}>Country</span> {countryFlag(info.country)} {countryName(info.country)}
        </span>
      )}
      {info.isp && <span><span style={{ color: 'var(--muted)' }}>ISP</span> {info.isp}</span>}
      {info.usage_type && <span><span style={{ color: 'var(--muted)' }}>Type</span> {info.usage_type}</span>}
      {score !== undefined ? (
        <span
          className="rounded-full px-2 py-0.5 font-medium"
          style={
            score >= 50
              ? { background: 'var(--crit-tint)', color: 'var(--crit)' }
              : score > 0
                ? { background: 'var(--warn-tint)', color: 'var(--warn)' }
                : { background: 'var(--good-tint)', color: 'var(--good)' }
          }
        >
          Abuse {score}% · {info.abuse_reports} reports
        </span>
      ) : (
        <span style={{ color: 'var(--muted)' }}>No attack reports on record for this address.</span>
      )}
    </div>
  )
}

export function Alerts({ onUnauthorized, canWrite }: { onUnauthorized: () => void; canWrite: boolean }) {
  const [unackedOnly, setUnackedOnly] = useState(false)
  const path = `/api/alerts?limit=200${unackedOnly ? '&unacked=true' : ''}`
  const { data, loading, error, refresh } = useFetch<{ alerts: Alert[] | null }>(path, { pollMs: 5000, onUnauthorized })
  const names = useDeviceNames(onUnauthorized)

  const alerts = data?.alerts ?? []
  const [expanded, setExpanded] = useState<number | null>(null)

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
                  {a.Source && isPublic(a.Source) && (
                    <button
                      onClick={() => setExpanded(expanded === a.ID ? null : a.ID)}
                      className="ml-2 rounded px-1.5 py-0.5 font-medium"
                      style={{ background: 'var(--surface-2)', color: 'var(--accent-strong)' }}
                    >
                      {expanded === a.ID ? 'hide' : 'who is this?'}
                    </button>
                  )}
                </div>
                {expanded === a.ID && a.Source && (
                  <div className="mt-2">
                    <Reputation ip={a.Source} />
                  </div>
                )}
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
