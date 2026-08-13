import { useEffect, useState } from 'react'
import { useFetch } from '../lib/useFetch'
import { api, countryFlag, countryName, type Alert, type Incident, type MuteRule, type ReputationInfo } from '../lib/api'
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
  const signals = info.signals ?? []
  const reports = info.abuse_reports ?? 0
  return (
    <div className="rounded-md px-3 py-2 text-xs" style={{ background: 'var(--surface-2)' }}>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        {info.org && <span><span style={{ color: 'var(--muted)' }}>Owner</span> {info.org}{info.handle ? ` (${info.handle})` : ''}</span>}
        {info.country && (
          <span>
            <span style={{ color: 'var(--muted)' }}>
              {info.country_source === 'registry' ? 'Registered in' : 'Country'}
            </span>{' '}
            {countryFlag(info.country)} {countryName(info.country)}
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
                : { background: 'var(--warn-tint)', color: 'var(--warn)' }
            }
          >
            Abuse {score}%{reports > 0 ? ` · ${reports} reports` : ''}
          </span>
        ) : (
          // Never green. No free source having data on an address does not
          // make it safe — it makes it unknown, and this card sits next to an
          // alert that fired for a reason.
          <span className="rounded-full px-2 py-0.5 font-medium" style={{ background: 'var(--surface)', color: 'var(--muted)' }}>
            No reports — unknown, not cleared
          </span>
        )}
      </div>

      {signals.length > 0 && (
        <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5" style={{ color: 'var(--muted)' }}>
          {signals.map((s) => (
            <span key={s.source}>
              {s.source}: {s.detail}
            </span>
          ))}
        </div>
      )}

      <div className="mt-1 flex flex-wrap gap-x-3" style={{ color: 'var(--muted)' }}>
        <span>Look up elsewhere:</span>
        <Lookup href={`https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`}>AbuseIPDB</Lookup>
        <Lookup href={`https://www.shodan.io/host/${encodeURIComponent(ip)}`}>Shodan</Lookup>
        <Lookup href={`https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}`}>VirusTotal</Lookup>
      </div>
    </div>
  )
}

// Lookup opens a third-party report on the address. Nothing is sent anywhere
// until the operator clicks: these are plain links, not background requests.
function Lookup({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noreferrer" className="underline" style={{ color: 'var(--accent-strong)' }}>
      {children}
    </a>
  )
}

export function Alerts({ onUnauthorized, canWrite }: { onUnauthorized: () => void; canWrite: boolean }) {
  const [unackedOnly, setUnackedOnly] = useState(false)
  const [grouped, setGrouped] = useState(true)
  const path = `/api/alerts?limit=200${unackedOnly ? '&unacked=true' : ''}`
  const { data, loading, error, refresh } = useFetch<{ alerts: Alert[] | null }>(path, {
    pollMs: grouped ? 0 : 5000,
    onUnauthorized,
  })
  const names = useDeviceNames(onUnauthorized)

  const alerts = data?.alerts ?? []
  const [expanded, setExpanded] = useState<number | null>(null)

  const ack = async (id: number) => {
    await api.post(`/api/alerts/${id}/ack`)
    refresh()
  }

  if (grouped) {
    return (
      <Incidents
        onUnauthorized={onUnauthorized}
        canWrite={canWrite}
        unackedOnly={unackedOnly}
        setUnackedOnly={setUnackedOnly}
        onUngroup={() => setGrouped(false)}
      />
    )
  }

  return (
    <Card>
      <CardHeader
        title="Alerts"
        sub={`${alerts.length} shown · every event individually`}
        right={
          <div className="flex items-center gap-3">
            <button
              onClick={() => setGrouped(true)}
              className="rounded-md px-2.5 py-1 text-xs font-medium"
              style={{ background: 'var(--surface-2)', color: 'var(--muted)' }}
            >
              Group by source
            </button>
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

// Incidents is the grouped view: one row per source per episode. The flat
// list is still one click away — grouping is a lens, not a replacement, and
// a burst of forty scans from one address should read as one event.
function Incidents({
  onUnauthorized,
  canWrite,
  unackedOnly,
  setUnackedOnly,
  onUngroup,
}: {
  onUnauthorized: () => void
  canWrite: boolean
  unackedOnly: boolean
  setUnackedOnly: (v: boolean) => void
  onUngroup: () => void
}) {
  const path = `/api/incidents?limit=200${unackedOnly ? '&unacked=true' : ''}`
  const { data, loading, error, refresh } = useFetch<{ incidents: Incident[] | null }>(path, {
    pollMs: 5000,
    onUnauthorized,
  })
  const names = useDeviceNames(onUnauthorized)
  const [open, setOpen] = useState<number | null>(null)
  const [muteFor, setMuteFor] = useState<Incident | null>(null)

  const incidents = data?.incidents ?? []

  const ack = async (id: number) => {
    await api.post(`/api/incidents/${id}/ack`)
    refresh()
  }

  return (
    <div className="flex flex-col gap-4">
      {muteFor && (
        <MuteDialog
          incident={muteFor}
          onClose={() => setMuteFor(null)}
          onDone={() => {
            setMuteFor(null)
            refresh()
          }}
        />
      )}

      <Card>
        <CardHeader
          title="Incidents"
          sub={`${incidents.length} shown · alerts grouped by source and episode`}
          right={
            <div className="flex items-center gap-3">
              <button
                onClick={onUngroup}
                className="rounded-md px-2.5 py-1 text-xs font-medium"
                style={{ background: 'var(--surface-2)', color: 'var(--muted)' }}
              >
                Show every alert
              </button>
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
          <EmptyState>Could not load incidents: {error}</EmptyState>
        ) : incidents.length === 0 ? (
          <EmptyState>No incidents. All quiet.</EmptyState>
        ) : (
          <ul>
            {incidents.map((inc) => (
              <li
                key={inc.id}
                className="px-4 py-3"
                style={{ borderTop: '1px solid var(--border)', opacity: inc.ack ? 0.55 : 1 }}
              >
                <div className="flex items-start gap-3">
                  <div className="pt-0.5">
                    <SeverityBadge severity={inc.severity as Alert['Severity']} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium">{inc.title}</span>
                      {inc.alert_count > 1 && <Pill>{inc.alert_count} events</Pill>}
                      {inc.detectors?.map((d) => (
                        <Pill key={d} tone="neutral">
                          {d}
                        </Pill>
                      ))}
                      {inc.ack && <Pill tone="good">acked</Pill>}
                    </div>
                    <div className="mt-0.5 text-xs" style={{ color: 'var(--muted)' }}>
                      <span className="font-mono">{inc.source}</span>
                      {names.get(inc.source) && <span> ({names.get(inc.source)})</span>}
                      {' · '}
                      {formatTime(inc.first_seen)} → {formatTime(inc.last_seen)}
                      <button
                        onClick={() => setOpen(open === inc.id ? null : inc.id)}
                        className="ml-2 rounded px-1.5 py-0.5 font-medium"
                        style={{ background: 'var(--surface-2)', color: 'var(--accent-strong)' }}
                      >
                        {open === inc.id ? 'hide events' : 'events'}
                      </button>
                      {isPublic(inc.source) && (
                        <button
                          onClick={() => setOpen(open === -inc.id ? null : -inc.id)}
                          className="ml-2 rounded px-1.5 py-0.5 font-medium"
                          style={{ background: 'var(--surface-2)', color: 'var(--accent-strong)' }}
                        >
                          {open === -inc.id ? 'hide' : 'who is this?'}
                        </button>
                      )}
                    </div>
                    {open === -inc.id && (
                      <div className="mt-2">
                        <Reputation ip={inc.source} />
                      </div>
                    )}
                    {open === inc.id && <IncidentEvents id={inc.id} />}
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    {canWrite && (
                      <Button onClick={() => setMuteFor(inc)} className="!px-2 !py-1 !text-xs">
                        Mute
                      </Button>
                    )}
                    {canWrite && !inc.ack && (
                      <Button onClick={() => ack(inc.id)} className="!px-2 !py-1 !text-xs">
                        Ack
                      </Button>
                    )}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <MuteRules onUnauthorized={onUnauthorized} canWrite={canWrite} />
    </div>
  )
}

// IncidentEvents lists the alerts inside one episode.
function IncidentEvents({ id }: { id: number }) {
  const { data } = useFetch<Incident>(`/api/incidents/${id}`, {})
  const alerts = data?.alerts ?? []
  if (alerts.length === 0) return null
  return (
    <ul className="mt-2 flex flex-col gap-1 rounded-md px-3 py-2" style={{ background: 'var(--surface-2)' }}>
      {alerts.map((a) => (
        <li key={a.ID} className="flex items-baseline gap-2 text-xs">
          <span className="font-mono" style={{ color: 'var(--muted)' }}>
            {formatTime(a.Time)}
          </span>
          <span className="font-medium">{a.Detector}</span>
          <span style={{ color: 'var(--muted)' }}>{a.Detail}</span>
        </li>
      ))}
    </ul>
  )
}

// MuteDialog creates a suppression rule prefilled from an incident.
function MuteDialog({
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
          <span className="font-mono text-[0.62rem] font-semibold uppercase tracking-[0.1em]" style={{ color: 'var(--muted)' }}>
            Scope
          </span>
          <div className="flex items-center gap-1.5">
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
          <span className="font-mono text-[0.62rem] font-semibold uppercase tracking-[0.1em]" style={{ color: 'var(--muted)' }}>
            For
          </span>
          <input
            value={ttl}
            onChange={(e) => setTtl(e.target.value)}
            placeholder="24h · blank = forever"
            className="rounded-md border px-2.5 py-1.5 font-mono text-sm"
            style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text)' }}
          />
        </label>
        <label className="flex w-48 flex-col gap-1">
          <span className="font-mono text-[0.62rem] font-semibold uppercase tracking-[0.1em]" style={{ color: 'var(--muted)' }}>
            Reason
          </span>
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

// MuteRules lists and removes the active suppression rules.
function MuteRules({ onUnauthorized, canWrite }: { onUnauthorized: () => void; canWrite: boolean }) {
  const { data, refresh } = useFetch<{ rules: MuteRule[] | null }>('/api/mutes', { pollMs: 30000, onUnauthorized })
  const rules = data?.rules ?? []
  if (rules.length === 0) return null

  const remove = async (id: number) => {
    await api.del(`/api/mutes/${id}`)
    refresh()
  }

  return (
    <Card>
      <CardHeader title="Muted" sub="these alerts are suppressed — blocking still applies as configured" />
      <ul className="flex flex-col gap-1.5 px-4 pb-4">
        {rules.map((r) => (
          <li key={r.id} className="flex items-center gap-2 text-sm">
            <span className="font-mono text-xs">
              {[r.detector, r.prefix, r.port ? `port ${r.port}` : ''].filter(Boolean).join(' · ') || 'everything'}
            </span>
            {r.reason && (
              <span className="text-xs" style={{ color: 'var(--muted)' }}>
                {r.reason}
              </span>
            )}
            {r.expires && (
              <span className="text-xs" style={{ color: 'var(--muted)' }}>
                until {formatTime(r.expires)}
              </span>
            )}
            {canWrite && (
              <button
                onClick={() => remove(r.id)}
                className="ml-auto text-xs font-medium"
                style={{ color: 'var(--crit)' }}
              >
                Unmute
              </button>
            )}
          </li>
        ))}
      </ul>
    </Card>
  )
}
