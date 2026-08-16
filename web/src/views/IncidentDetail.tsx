import { useState } from 'react'
import { Link, useLocation, useParams } from 'react-router-dom'
import { useFetch } from '../lib/useFetch'
import { api, type Alert, type Incident } from '../lib/api'
import { Card, CardHeader, Spinner, EmptyState, SeverityBadge, Button, Pill, useToast } from '../components/ui'
import { BlockDialog } from '../components/BlockDialog'
import { MuteDialog } from '../components/MuteDialog'
import { Reputation } from '../components/Reputation'
import { Explain } from '../components/Explain'
import { EntityLink } from '../components/entity'
import { humanError } from '../components/humanError'
import { useDeviceIndex, isPrivateAddress } from '../lib/links'
import { formatTime } from '../lib/format'

// One episode, as a page.
//
// This is where a phone lands from an ntfy push at three in the morning, so it
// is a route and not an expand-in-place: it has to survive a reload, a share
// and a Back. Everything the operator needs to decide is on it — who the
// source is, what fired, when it started and stopped, and the three actions —
// with no trip back to a list that may no longer contain the row.
export function IncidentDetail({ onUnauthorized, canWrite }: { onUnauthorized: () => void; canWrite: boolean }) {
  const { id = '' } = useParams()
  const { hash } = useLocation()
  const index = useDeviceIndex(onUnauthorized)
  const { data, loading, error, stale, refresh } = useFetch<Incident>(`/api/incidents/${encodeURIComponent(id)}`, {
    pollMs: 15000,
    onUnauthorized,
  })
  const toast = useToast()
  const [muting, setMuting] = useState(false)
  const [blocking, setBlocking] = useState(false)

  if (loading && !data) return <Spinner />

  // A missing incident says so. Rendering the list instead would answer a
  // question the operator did not ask and hide the fact that their link is
  // dead — which is precisely the bug this route exists to fix.
  if (!data) {
    return (
      <div className="flex flex-col gap-4">
        <Breadcrumb label={`Incident ${id}`} />
        <Card className="px-4 py-6">
          <h1 className="text-lg font-semibold tracking-tight">There is no incident {id}.</h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
            {error ? <>The server said: <span className="font-mono">{error}</span>.</> : 'It may have been pruned by retention.'}
          </p>
          <Link
            to="/alerts"
            className="mt-3 inline-block rounded-md px-3 py-1.5 text-sm font-medium"
            style={{ background: 'var(--surface-2)', color: 'var(--accent-strong)' }}
          >
            Open the alerts list
          </Link>
        </Card>
      </div>
    )
  }

  const inc = data
  const alerts = inc.alerts ?? []
  const name = index.names.get(inc.source)
  // Unguarded before: a refused ack threw into nothing and the page looked
  // exactly as it does after a successful one. The toast is also this page's
  // only live region — the Acknowledge button disappears on the next refresh
  // whatever happened, so the outcome has to be said somewhere that outlives it.
  const ack = async () => {
    try {
      await api.post(`/api/incidents/${inc.id}/ack`)
      toast.show({ message: 'Episode acknowledged.', tone: 'ok' })
    } catch (e) {
      toast.show({ message: humanError(e), tone: 'crit', ttlMs: 9000 })
    } finally {
      refresh()
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <Breadcrumb label={inc.title} />

      {blocking && inc.source && (
        <BlockDialog
          source={inc.source}
          detector={inc.detectors?.[0] ?? ''}
          onClose={() => setBlocking(false)}
          onDone={() => {
            setBlocking(false)
            refresh()
          }}
          onUnauthorized={onUnauthorized}
        />
      )}
      {muting && (
        <MuteDialog
          incident={inc}
          onClose={() => setMuting(false)}
          onDone={() => {
            setMuting(false)
            refresh()
          }}
        />
      )}

      <Card className="px-4 py-3.5">
        <div className="flex flex-wrap items-start gap-3">
          <div className="pt-0.5">
            <SeverityBadge severity={inc.severity as Alert['Severity']} />
          </div>
          <div className="min-w-0 flex-1">
            <h1 className="text-lg font-semibold tracking-tight">{inc.title}</h1>
            <div className="mt-1 flex flex-wrap items-center gap-1.5">
              {inc.alert_count > 1 && <Pill>{inc.alert_count} events</Pill>}
              {inc.detectors?.map((d) => (
                <Pill key={d} tone="neutral">
                  {d}
                </Pill>
              ))}
              {inc.ack ? <Pill tone="good">acknowledged</Pill> : <Pill tone="warn">outstanding</Pill>}
            </div>
            <div className="mt-1.5 break-all text-sm" style={{ color: 'var(--muted)' }}>
              <EntityLink value={inc.source} index={index} />
              {name && <span> ({name})</span>}
              {' · '}
              {formatTime(inc.first_seen)} → {formatTime(inc.last_seen)}
            </div>
            {stale && (
              <div className="mt-1 text-xs" style={{ color: 'var(--muted)' }}>
                The last refresh failed; this is the last known state.
              </div>
            )}
          </div>
        </div>

        {canWrite && (
          // break-all on the Block label: an IPv6 source is 39 unbreakable
          // characters, and neither ':' nor '.' is a break opportunity in CSS.
          <div className="mt-3 flex flex-wrap items-center gap-2">
            {inc.source && (
              <Button onClick={() => setBlocking(true)} className="break-all pointer-coarse:min-h-11">
                Block {inc.source}
              </Button>
            )}
            <Button onClick={() => setMuting(true)} className="pointer-coarse:min-h-11">
              Mute
            </Button>
            {!inc.ack && (
              <Button variant="primary" onClick={ack} className="pointer-coarse:min-h-11">
                Acknowledge
              </Button>
            )}
          </div>
        )}
      </Card>

      <Explain subject={{ incident: inc.id }} canWrite={canWrite} />

      {inc.source && !isPrivateAddress(inc.source) && (
        <Card>
          <CardHeader title="Who is this" sub={`what the public registries say about ${inc.source}`} />
          <div className="px-4 pb-4">
            <Reputation ip={inc.source} />
          </div>
        </Card>
      )}

      <Card>
        <CardHeader
          title="Events"
          sub={
            alerts.length === inc.alert_count
              ? `all ${alerts.length} alerts in this episode`
              : `${alerts.length} of ${inc.alert_count} alerts in this episode`
          }
        />
        {alerts.length === 0 ? (
          <EmptyState>No individual alerts are attached to this episode.</EmptyState>
        ) : (
          <ul>
            {alerts.map((a) => (
              <li
                key={a.ID}
                id={`alert-${a.ID}`}
                className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-4 py-2.5 text-sm"
                style={{
                  borderTop: '1px solid var(--border)',
                  background: hash === `#alert-${a.ID}` ? 'var(--accent-tint)' : undefined,
                }}
              >
                <span className="font-mono text-xs" style={{ color: 'var(--muted)' }}>
                  {formatTime(a.Time)}
                </span>
                <span className="font-medium">{a.Detector}</span>
                <span style={{ color: 'var(--muted)' }}>{a.Detail}</span>
                {a.Count > 1 && <Pill>{a.Count}×</Pill>}
                {a.Ack && <Pill tone="good">acked</Pill>}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  )
}

function Breadcrumb({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--muted)' }}>
      {/* 35×20 before. This is the way back out of the page a push notification
          drops you on, so it is a target and not just a word. */}
      <Link to="/alerts" className="inline-flex items-center hover:underline pointer-coarse:min-h-11 pointer-coarse:pr-1">
        Alerts
      </Link>
      <span>/</span>
      <span className="min-w-0 truncate" style={{ color: 'var(--text)' }}>
        {label}
      </span>
    </div>
  )
}
