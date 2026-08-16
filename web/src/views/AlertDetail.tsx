import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useFetch } from '../lib/useFetch'
import { api, type Alert } from '../lib/api'
import { Card, CardHeader, Spinner, SeverityBadge, Button, Pill, useToast } from '../components/ui'
import { BlockDialog } from '../components/BlockDialog'
import { ExplainAlert } from '../components/ExplainAlert'
import { Reputation } from '../components/Reputation'
import { EntityLink } from '../components/entity'
import { humanError } from '../components/humanError'
import { useDeviceIndex, entityHref, isPrivateAddress } from '../lib/links'
import { formatTime } from '../lib/format'

// The ntfy landing page: every push carries Click: {externalURL}/alerts/{id}.
//
// Until today that URL rendered the unfiltered alerts list, so the one flow
// the product exists for — a phone, at three in the morning, from a push —
// ended on a page that did not contain the alert and could not be made to.
export function AlertDetail({ onUnauthorized, canWrite }: { onUnauthorized: () => void; canWrite: boolean }) {
  const { id = '' } = useParams()
  const index = useDeviceIndex(onUnauthorized)
  // One alert, fetched by id. This used to pull the 500 most recent and search
  // them, so an alert older than that page reported itself as missing while its
  // row sat in the table — on exactly the page a 3am push lands on.
  const { data: alert, loading, error, refresh } = useFetch<Alert>(`/api/alerts/${encodeURIComponent(id)}`, {
    onUnauthorized,
  })
  const toast = useToast()
  const [blocking, setBlocking] = useState(false)

  if (loading && !alert) return <Spinner />

  if (!alert) {
    return (
      <div className="flex flex-col gap-4">
        <Breadcrumb label={`Alert ${id}`} />
        <Card className="px-4 py-6">
          <h1 className="text-lg font-semibold tracking-tight">
            {error ? 'Could not read that alert.' : `Alert ${id} was not found.`}
          </h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
            {error ? (
              <>The server said: <span className="font-mono">{error}</span>.</>
            ) : (
              <>
                No alert with that id is in the database — it was never issued, or it has aged past the
                retention window. Nothing here is a claim about what the alert said.
              </>
            )}
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

  const name = index.names.get(alert.Source)
  const sourceHref = alert.Source ? entityHref(alert.Source, index) : null
  // Acknowledging used to be an unguarded await: a refusal threw into nothing,
  // the button vanished on the next refresh either way, and the operator was
  // left unable to tell a handled alert from a failed request. The toast is
  // also the only live region on this page — the state it reports changes
  // without anything on screen saying so.
  const ack = async () => {
    try {
      await api.post(`/api/alerts/${alert.ID}/ack`)
      toast.show({ message: 'Alert acknowledged.', tone: 'ok' })
    } catch (e) {
      toast.show({ message: humanError(e), tone: 'crit', ttlMs: 9000 })
    } finally {
      refresh()
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <Breadcrumb label={alert.Title} />

      {blocking && alert.Source && (
        <BlockDialog
          source={alert.Source}
          detector={alert.Detector}
          onClose={() => setBlocking(false)}
          onDone={() => {
            setBlocking(false)
            refresh()
          }}
          onUnauthorized={onUnauthorized}
        />
      )}

      <Card className="px-4 py-3.5">
        <div className="flex flex-wrap items-start gap-3">
          <div className="pt-0.5">
            <SeverityBadge severity={alert.Severity} />
          </div>
          <div className="min-w-0 flex-1">
            <h1 className="text-lg font-semibold tracking-tight">{alert.Title}</h1>
            <div className="mt-1 flex flex-wrap items-center gap-1.5">
              <Pill tone="neutral">{alert.Detector}</Pill>
              {alert.Count > 1 && <Pill>{alert.Count}×</Pill>}
              {alert.Ack ? <Pill tone="good">acknowledged</Pill> : <Pill tone="warn">outstanding</Pill>}
            </div>
            <p className="mt-1.5 text-sm">{alert.Detail}</p>
            <div className="mt-1 break-all text-sm" style={{ color: 'var(--muted)' }}>
              {alert.Source && (
                <>
                  <EntityLink value={alert.Source} index={index} />
                  {name && <span> ({name})</span>}
                  {' · '}
                </>
              )}
              {formatTime(alert.Time)}
              {alert.Ack && alert.AckTime && <span> · acknowledged {formatTime(alert.AckTime)}</span>}
            </div>
          </div>
        </div>

        {/* This is where a phone lands from a push, so these are the targets
            that matter most in the product. break-all because a source is as
            likely to be IPv6 as IPv4 and neither ':' nor '.' is a break
            opportunity — an unbreakable 39-character label in a 334px column
            is how a button ends up wider than the screen. */}
        <div className="mt-3 flex flex-wrap items-center gap-2">
          {canWrite && alert.Source && (
            <Button onClick={() => setBlocking(true)} className="break-all pointer-coarse:min-h-11">
              Block {alert.Source}
            </Button>
          )}
          {canWrite && !alert.Ack && (
            <Button variant="primary" onClick={ack} className="pointer-coarse:min-h-11">
              Acknowledge
            </Button>
          )}
          {sourceHref && (
            <Link
              to={sourceHref}
              className="inline-flex items-center break-all rounded-md border px-3 py-1.5 text-sm font-medium pointer-coarse:min-h-11"
              style={{ background: 'var(--surface-2)', color: 'var(--text)', borderColor: 'var(--border)' }}
            >
              Everything about {alert.Source}
            </Link>
          )}
        </div>
      </Card>

      <ExplainAlert alertID={alert.ID} canWrite={canWrite} />

      {alert.Source && !isPrivateAddress(alert.Source) && (
        <Card>
          <CardHeader title="Who is this" sub={`what the public registries say about ${alert.Source}`} />
          <div className="px-4 pb-4">
            <Reputation ip={alert.Source} />
          </div>
        </Card>
      )}

      <p className="text-xs" style={{ color: 'var(--muted)' }}>
        This alert may be one of several from the same source. The alerts list groups them into episodes.
      </p>
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
