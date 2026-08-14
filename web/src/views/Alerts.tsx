import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useFetch } from '../lib/useFetch'
import { api, type Alert, type Incident, type MuteRule } from '../lib/api'
import { Card, CardHeader, Spinner, EmptyState, SeverityBadge, Button, Pill , useToast } from '../components/ui'
import { BlockDialog } from '../components/BlockDialog'
import { MuteDialog } from '../components/MuteDialog'
import { SegmentedControl } from '../components/RangeControl'
import { EntityLink } from '../components/entity'
import { PageTitle } from '../components/PageTitle'
import { useDeviceIndex, type DeviceIndex } from '../lib/links'
import { useIsMobile } from '../lib/useIsMobile'
import { useUrlState } from '../lib/useUrlState'
import { formatTime } from '../lib/format'
import { humanError } from '../components/humanError'

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
          className="ml-auto inline-flex items-center rounded-md px-2.5 py-1 text-xs font-medium pointer-coarse:min-h-11 pointer-coarse:px-3"
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
  const toast = useToast()
  const index = useDeviceIndex(onUnauthorized)
  const isMobile = useIsMobile()
  const [muteFor, setMuteFor] = useState<Incident | null>(null)
  const [blockFor, setBlockFor] = useState<Incident | null>(null)

  const incidents = data?.incidents ?? []

  const ack = async (id: number) => {
    try {
      await api.post(`/api/incidents/${id}/ack`)
      // The Ack button is removed by the refresh that follows, so the outcome
      // has to be said somewhere that outlives it. The toast is a live region;
      // a row quietly dropping to opacity 0.55 is not.
      toast.show({ message: 'Episode acknowledged.', tone: 'ok' })
    } catch (e) {
      toast.show({ message: humanError(e), tone: 'crit', ttlMs: 9000 })
    } finally {
      refresh()
    }
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
          sub={
            <>
              {/* The list re-polls every five seconds. A count that changes on
                  its own has to be announced or it changes in silence. */}
              <span role="status">{incidents.length} shown</span> · alerts grouped by source and episode
            </>
          }
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
            {incidents.map((inc) =>
              isMobile ? (
                <IncidentCard
                  key={inc.id}
                  inc={inc}
                  index={index}
                  canWrite={canWrite}
                  onBlock={() => setBlockFor(inc)}
                  onMute={() => setMuteFor(inc)}
                  onAck={() => ack(inc.id)}
                />
              ) : (
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
              ),
            )}
          </ul>
        )}
      </Card>

      <MuteRules onUnauthorized={onUnauthorized} canWrite={canWrite} />
    </div>
  )
}

// IncidentCard is the phone rendering of one episode.
//
// The desktop row is a flex line with a `shrink-0` action group at the end.
// At 390px that group and the severity badge took 240 of the 334px available
// and the body — the thing the operator opened the push notification to read —
// was left with 93px, wrapping into a 211px column of shredded text. A card
// gives the words the full width and puts the three actions on their own row
// underneath at a thumb's size.
//
// Nothing is dropped relative to the desktop row: title, event count,
// detectors, ack state, source, name, both timestamps, all three actions.
function IncidentCard({
  inc,
  index,
  canWrite,
  onBlock,
  onMute,
  onAck,
}: {
  inc: Incident
  index: DeviceIndex
  canWrite: boolean
  onBlock: () => void
  onMute: () => void
  onAck: () => void
}) {
  const name = index.names.get(inc.source)
  return (
    <li className="px-4 py-3" style={{ borderTop: '1px solid var(--border)', opacity: inc.ack ? 0.55 : 1 }}>
      <div className="flex items-start gap-2">
        <span className="shrink-0 pt-0.5">
          <SeverityBadge severity={inc.severity as Alert['Severity']} />
        </span>
        <Link to={`/incidents/${inc.id}`} className="min-w-0 flex-1 font-medium hover:underline">
          {inc.title}
        </Link>
      </div>

      <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
        {inc.alert_count > 1 && <Pill>{inc.alert_count} events</Pill>}
        {inc.detectors?.map((d) => (
          <Pill key={d} tone="neutral">
            {d}
          </Pill>
        ))}
        {inc.ack && <Pill tone="good">acked</Pill>}
      </div>

      {/* break-all because a source is as likely to be an IPv6 address as an
          IPv4 one, and neither `:` nor `.` is a break opportunity in CSS. */}
      <div className="mt-1 break-all text-xs" style={{ color: 'var(--muted)' }}>
        <EntityLink value={inc.source} index={index} />
        {name && <span> ({name})</span>}
      </div>
      <div className="text-xs" style={{ color: 'var(--muted)' }}>
        {formatTime(inc.first_seen)} → {formatTime(inc.last_seen)}
      </div>

      {canWrite && (
        <div className="mt-2.5 flex gap-2">
          {inc.source && (
            <Button onClick={onBlock} className="min-h-11 flex-1">
              Block
            </Button>
          )}
          <Button onClick={onMute} className="min-h-11 flex-1">
            Mute
          </Button>
          {!inc.ack && (
            <Button variant="primary" onClick={onAck} className="min-h-11 flex-1">
              Ack
            </Button>
          )}
        </div>
      )}
    </li>
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
  const toast = useToast()
  const index = useDeviceIndex(onUnauthorized)
  const isMobile = useIsMobile()
  const [blockFor, setBlockFor] = useState<Alert | null>(null)

  const alerts = data?.alerts ?? []

  const ack = async (id: number) => {
    try {
      await api.post(`/api/alerts/${id}/ack`)
      toast.show({ message: 'Alert acknowledged.', tone: 'ok' })
    } catch (e) {
      toast.show({ message: humanError(e), tone: 'crit', ttlMs: 9000 })
    } finally {
      refresh()
    }
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
          sub={
            <>
              <span role="status">{alerts.length} shown</span> · one row per event
            </>
          }
          right={stale ? <Pill tone="warn">last refresh failed</Pill> : undefined}
        />
        {loading && !data ? (
          <Spinner />
        ) : !data ? (
          <EmptyState>Could not load alerts{error ? `: ${error}` : ''}.</EmptyState>
        ) : alerts.length === 0 ? (
          <EmptyState>{onlyUnacked ? 'Nothing is waiting for you.' : 'No alerts recorded.'}</EmptyState>
        ) : isMobile ? (
          <ul>
            {alerts.map((a) => (
              <AlertCard
                key={a.ID}
                alert={a}
                index={index}
                canWrite={canWrite}
                onBlock={() => setBlockFor(a)}
                onAck={() => ack(a.ID)}
              />
            ))}
          </ul>
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

// AlertCard is the phone rendering of one alert. Same defect as the episode
// row, worse: the timestamp joined the action group inside the `shrink-0`, so
// the body column measured 45px of the 334 available.
function AlertCard({
  alert,
  index,
  canWrite,
  onBlock,
  onAck,
}: {
  alert: Alert
  index: DeviceIndex
  canWrite: boolean
  onBlock: () => void
  onAck: () => void
}) {
  const name = alert.Source ? index.names.get(alert.Source) : undefined
  return (
    <li className="px-4 py-3" style={{ borderTop: '1px solid var(--border)', opacity: alert.Ack ? 0.55 : 1 }}>
      <div className="flex items-start gap-2">
        <span className="shrink-0 pt-0.5">
          <SeverityBadge severity={alert.Severity} />
        </span>
        <Link to={`/alerts/${alert.ID}`} className="min-w-0 flex-1 font-medium hover:underline">
          {alert.Title}
        </Link>
      </div>

      {(alert.Count > 1 || alert.Ack) && (
        <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
          {alert.Count > 1 && <Pill>{alert.Count}×</Pill>}
          {alert.Ack && <Pill tone="good">acked</Pill>}
        </div>
      )}

      <div className="mt-1 break-all text-xs" style={{ color: 'var(--muted)' }}>
        {alert.Detail}
      </div>
      <div className="break-all text-xs" style={{ color: 'var(--muted)' }}>
        {alert.Source && (
          <>
            <EntityLink value={alert.Source} index={index} />
            {name && <span> ({name})</span>}
            {' · '}
          </>
        )}
        {formatTime(alert.Time)}
      </div>

      {canWrite && (alert.Source || !alert.Ack) && (
        <div className="mt-2.5 flex gap-2">
          {alert.Source && (
            <Button onClick={onBlock} className="min-h-11 flex-1">
              Block
            </Button>
          )}
          {!alert.Ack && (
            <Button variant="primary" onClick={onAck} className="min-h-11 flex-1">
              Ack
            </Button>
          )}
        </div>
      )}
    </li>
  )
}

// MuteRules lists and removes the active suppression rules.
function MuteRules({ onUnauthorized, canWrite }: { onUnauthorized: () => void; canWrite: boolean }) {
  const { data, refresh } = useFetch<{ rules: MuteRule[] | null }>('/api/mutes', { pollMs: 30000, onUnauthorized })
  const toast = useToast()
  const rules = data?.rules ?? []
  if (rules.length === 0) return null

  const remove = async (id: number) => {
    try {
      await api.del(`/api/mutes/${id}`)
    } catch (e) {
      toast.show({ message: humanError(e), tone: 'crit', ttlMs: 9000 })
    } finally {
      refresh()
    }
  }

  return (
    <Card>
      <CardHeader title="Muted" sub="these alerts are suppressed — blocking still applies as configured" />
      <ul className="flex flex-col gap-1.5 px-4 pb-4">
        {rules.map((r) => {
          const scope = [r.detector, r.prefix, r.port ? `port ${r.port}` : ''].filter(Boolean).join(' · ') || 'everything'
          return (
            <li key={r.id} className="flex flex-wrap items-center gap-2 text-sm">
              <span className="min-w-0 break-all font-mono text-xs">{scope}</span>
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
                  // The label alone measured 45×16. `Unmute` next to five other
                  // `Unmute`s also named nothing in particular; the rule it
                  // removes is now in the accessible name.
                  aria-label={`Unmute ${scope}`}
                  className="ml-auto inline-flex items-center rounded-md px-2 py-1 text-xs font-medium pointer-coarse:min-h-11 pointer-coarse:px-3"
                  style={{ color: 'var(--crit)' }}
                >
                  Unmute
                </button>
              )}
            </li>
          )
        })}
      </ul>
    </Card>
  )
}
