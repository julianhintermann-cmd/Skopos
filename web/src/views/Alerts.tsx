import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useFetch } from '../lib/useFetch'
import { api, type Alert, type Incident, type MuteRule } from '../lib/api'
import { Card, CardHeader, Spinner, EmptyState, SeverityBadge, Button, Pill } from '../components/ui'
import { BlockDialog } from '../components/BlockDialog'
import { MuteDialog } from '../components/MuteDialog'
import { SegmentedControl } from '../components/RangeControl'
import { EntityLink } from '../components/entity'
import { PageTitle } from '../components/PageTitle'
import { useDeviceIndex } from '../lib/links'
import { useUrlState } from '../lib/useUrlState'
import { formatTime } from '../lib/format'

// What Skopos noticed, grouped into episodes, and whether it has been dealt
// with.
//
// The lens and the filter both live in the URL, so /alerts?unacked=1 is a real
// address someone can bookmark — and the rows are links to pages rather than
// in-place expanders, because the detail of an alert is a place you can be
// sent to from a push notification.

const VIEWS = ['incidents', 'events'] as const
type View = (typeof VIEWS)[number]

export function Alerts({ onUnauthorized, canWrite }: { onUnauthorized: () => void; canWrite: boolean }) {
  const [view, setView] = useUrlState<View>('view', 'incidents', { valid: VIEWS, history: 'push' })
  const [unacked, setUnacked] = useUrlState('unacked', '', { valid: ['', '1'] as const, history: 'push' })
  const onlyUnacked = unacked === '1'

  return (
    <div className="flex flex-col gap-4">
      <PageTitle title="Alerts">
        {onlyUnacked ? 'showing only what has not been acknowledged' : 'everything Skopos has noticed'}
      </PageTitle>

      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <SegmentedControl
          value={view}
          label="View"
          onChange={setView}
          options={[
            { value: 'incidents', label: 'Episodes', hint: 'Grouped by source' },
            { value: 'events', label: 'Every alert', hint: 'One row per alert' },
          ]}
        />
        <label className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--muted)' }}>
          <input type="checkbox" checked={onlyUnacked} onChange={(e) => setUnacked(e.target.checked ? '1' : '')} />
          Unacknowledged only
        </label>
        <a
          href="/api/export/alerts.csv"
          download
          className="ml-auto rounded-md px-2.5 py-1 text-xs font-medium"
          style={{ background: 'var(--surface-2)', color: 'var(--muted)' }}
        >
          Export CSV
        </a>
      </div>

      {view === 'incidents' ? (
        <Incidents onUnauthorized={onUnauthorized} canWrite={canWrite} onlyUnacked={onlyUnacked} />
      ) : (
        <Events onUnauthorized={onUnauthorized} canWrite={canWrite} onlyUnacked={onlyUnacked} />
      )}
    </div>
  )
}

// Incidents is the default lens: one row per source per episode. A burst of
// forty scans from one address should read as one event.
function Incidents({
  onUnauthorized,
  canWrite,
  onlyUnacked,
}: {
  onUnauthorized: () => void
  canWrite: boolean
  onlyUnacked: boolean
}) {
  const path = `/api/incidents?limit=200${onlyUnacked ? '&unacked=true' : ''}`
  const { data, loading, error, stale, refresh } = useFetch<{ incidents: Incident[] | null }>(path, {
    pollMs: 5000,
    onUnauthorized,
  })
  const index = useDeviceIndex(onUnauthorized)
  const [muteFor, setMuteFor] = useState<Incident | null>(null)
  const [blockFor, setBlockFor] = useState<Incident | null>(null)

  const incidents = data?.incidents ?? []

  const ack = async (id: number) => {
    await api.post(`/api/incidents/${id}/ack`)
    refresh()
  }

  return (
    <div className="flex flex-col gap-4">
      {muteFor && (
        <MuteDialog
          key={muteFor.id}
          incident={muteFor}
          onClose={() => setMuteFor(null)}
          onDone={() => {
            setMuteFor(null)
            refresh()
          }}
        />
      )}
      {blockFor && (
        <BlockDialog
          key={blockFor.id}
          source={blockFor.source}
          detector={blockFor.detectors?.[0] ?? ''}
          onClose={() => setBlockFor(null)}
          onDone={() => {
            setBlockFor(null)
            refresh()
          }}
          onUnauthorized={onUnauthorized}
        />
      )}

      <Card>
        <CardHeader
          title="Episodes"
          sub={`${incidents.length} shown · alerts grouped by source and episode`}
          right={stale ? <Pill tone="warn">last refresh failed</Pill> : undefined}
        />
        {loading && !data ? (
          <Spinner />
        ) : !data ? (
          <EmptyState>Could not load incidents{error ? `: ${error}` : ''}.</EmptyState>
        ) : incidents.length === 0 ? (
          <EmptyState>{onlyUnacked ? 'Nothing is waiting for you.' : 'No incidents recorded.'}</EmptyState>
        ) : (
          <ul>
            {incidents.map((inc) => (
              <li
                key={inc.id}
                className="px-4 py-3"
                style={{ borderTop: '1px solid var(--border)', opacity: inc.ack ? 0.55 : 1 }}
              >
                <div className="flex flex-wrap items-start gap-3">
                  <div className="pt-0.5">
                    <SeverityBadge severity={inc.severity as Alert['Severity']} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <Link to={`/incidents/${inc.id}`} className="font-medium hover:underline">
                        {inc.title}
                      </Link>
                      {inc.alert_count > 1 && <Pill>{inc.alert_count} events</Pill>}
                      {inc.detectors?.map((d) => (
                        <Pill key={d} tone="neutral">
                          {d}
                        </Pill>
                      ))}
                      {inc.ack && <Pill tone="good">acked</Pill>}
                    </div>
                    <div className="mt-0.5 text-xs" style={{ color: 'var(--muted)' }}>
                      <EntityLink value={inc.source} index={index} />
                      {index.names.get(inc.source) && <span> ({index.names.get(inc.source)})</span>}
                      {' · '}
                      {formatTime(inc.first_seen)} → {formatTime(inc.last_seen)}
                      {' · '}
                      <Link to={`/incidents/${inc.id}`} className="font-medium hover:underline" style={{ color: 'var(--accent-strong)' }}>
                        open
                      </Link>
                    </div>
                  </div>
                  {canWrite && (
                    <div className="flex shrink-0 flex-wrap items-center gap-2">
                      {inc.source && (
                        <Button onClick={() => setBlockFor(inc)} className="!px-2 !py-1 !text-xs">
                          Block
                        </Button>
                      )}
                      <Button onClick={() => setMuteFor(inc)} className="!px-2 !py-1 !text-xs">
                        Mute
                      </Button>
                      {!inc.ack && (
                        <Button onClick={() => ack(inc.id)} className="!px-2 !py-1 !text-xs">
                          Ack
                        </Button>
                      )}
                    </div>
                  )}
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

// Events is the flat lens: every alert individually, each row a link to its
// own page — the page ntfy sends people to.
function Events({
  onUnauthorized,
  canWrite,
  onlyUnacked,
}: {
  onUnauthorized: () => void
  canWrite: boolean
  onlyUnacked: boolean
}) {
  const path = `/api/alerts?limit=200${onlyUnacked ? '&unacked=true' : ''}`
  const { data, loading, error, stale, refresh } = useFetch<{ alerts: Alert[] | null }>(path, {
    pollMs: 5000,
    onUnauthorized,
  })
  const index = useDeviceIndex(onUnauthorized)
  const [blockFor, setBlockFor] = useState<Alert | null>(null)

  const alerts = data?.alerts ?? []

  const ack = async (id: number) => {
    await api.post(`/api/alerts/${id}/ack`)
    refresh()
  }

  return (
    <div className="flex flex-col gap-4">
      {blockFor?.Source && (
        // Keyed on the target: without it React reuses the instance when the
        // operator opens the dialog on one alert and then another, and the
        // note typed for the first would be saved against the second.
        <BlockDialog
          key={blockFor.ID}
          source={blockFor.Source}
          detector={blockFor.Detector}
          onClose={() => setBlockFor(null)}
          onDone={() => {
            setBlockFor(null)
            refresh()
          }}
          onUnauthorized={onUnauthorized}
        />
      )}
      <Card>
        <CardHeader
          title="Every alert"
          sub={`${alerts.length} shown · one row per event`}
          right={stale ? <Pill tone="warn">last refresh failed</Pill> : undefined}
        />
        {loading && !data ? (
          <Spinner />
        ) : !data ? (
          <EmptyState>Could not load alerts{error ? `: ${error}` : ''}.</EmptyState>
        ) : alerts.length === 0 ? (
          <EmptyState>{onlyUnacked ? 'Nothing is waiting for you.' : 'No alerts recorded.'}</EmptyState>
        ) : (
          <ul>
            {alerts.map((a) => (
              <li
                key={a.ID}
                className="flex flex-wrap items-start gap-3 px-4 py-3"
                style={{ borderTop: '1px solid var(--border)', opacity: a.Ack ? 0.55 : 1 }}
              >
                <div className="pt-0.5">
                  <SeverityBadge severity={a.Severity} />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <Link to={`/alerts/${a.ID}`} className="font-medium hover:underline">
                      {a.Title}
                    </Link>
                    {a.Count > 1 && <Pill>{a.Count}×</Pill>}
                    {a.Ack && <Pill tone="good">acked</Pill>}
                  </div>
                  <div className="text-xs" style={{ color: 'var(--muted)' }}>
                    {a.Detail}
                    {a.Source && (
                      <>
                        {' · '}
                        <EntityLink value={a.Source} index={index} />
                        {index.names.get(a.Source) && <span> ({index.names.get(a.Source)})</span>}
                      </>
                    )}
                  </div>
                </div>
                <div className="flex shrink-0 flex-wrap items-center gap-2">
                  <span className="font-mono text-xs" style={{ color: 'var(--muted)' }}>
                    {formatTime(a.Time)}
                  </span>
                  {canWrite && a.Source && (
                    <Button onClick={() => setBlockFor(a)} className="!px-2 !py-1 !text-xs">
                      Block
                    </Button>
                  )}
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
    </div>
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
