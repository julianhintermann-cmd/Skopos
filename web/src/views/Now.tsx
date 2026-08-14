import { Link } from 'react-router-dom'
import { useFetch } from '../lib/useFetch'
import type { Incident } from '../lib/api'
import { Card, CardHeader, EmptyState, SeverityBadge, Pill } from '../components/ui'
import { LivePulse } from '../components/LivePulse'
import { TalkerRows } from '../components/entity'
import { PageTitle, CaptureScopeNote } from '../components/PageTitle'
import { useDeviceIndex } from '../lib/links'
import { useLiveStream } from '../lib/live'
import { useStatus, toneColor } from '../lib/status'
import { formatTime } from '../lib/format'

// Now answers one question: is my network normal, and is Skopos actually
// watching it, this second.
//
// It has no time control anywhere on it, by rule. Anything that needs a window
// belongs on Traffic; what is left is the reading, the verdict and the things
// waiting for a human.
const OUTSTANDING_SHOWN = 3
const OUTSTANDING_FETCHED = 20

export function Now({ onUnauthorized }: { onUnauthorized: () => void }) {
  const status = useStatus()
  const index = useDeviceIndex(onUnauthorized)
  const { live, spark, connected } = useLiveStream()
  const incidents = useFetch<{ incidents: Incident[] | null }>(
    `/api/incidents?limit=${OUTSTANDING_FETCHED}&unacked=true`,
    { pollMs: 15000, onUnauthorized },
  )

  const talkers = status.overview.data?.top_talkers ?? []
  const talkersUnavailable = (status.overview.data?.unavailable ?? []).includes('top_talkers')
  const open = incidents.data?.incidents ?? []
  const shown = open.slice(0, OUTSTANDING_SHOWN)
  const more = open.length - shown.length

  return (
    <div className="flex flex-col gap-4">
      <PageTitle title="Now">
        <CaptureScopeNote />
      </PageTitle>

      <Verdict />

      <LivePulse live={live} spark={spark} connected={connected} variant="compact" />

      <Card>
        <CardHeader
          title="Outstanding"
          sub="episodes nobody has acknowledged yet"
          right={
            open.length > 0 ? (
              <Link to="/alerts?unacked=1" className="text-xs font-medium hover:underline" style={{ color: 'var(--accent-strong)' }}>
                See all
              </Link>
            ) : undefined
          }
        />
        {incidents.loading && !incidents.data ? (
          <div className="px-4 pb-4 text-sm" style={{ color: 'var(--muted)' }}>
            Checking…
          </div>
        ) : !incidents.data ? (
          // Not "all clear" — a failed request is not an empty list.
          <EmptyState>Could not read the incident list{incidents.error ? `: ${incidents.error}` : ''}.</EmptyState>
        ) : shown.length === 0 ? (
          <EmptyState>Nothing is waiting for you.</EmptyState>
        ) : (
          <ul>
            {shown.map((inc) => (
              <li key={inc.id} style={{ borderTop: '1px solid var(--border)' }}>
                <Link to={`/incidents/${inc.id}`} className="flex items-start gap-3 px-4 py-3">
                  <span className="pt-0.5">
                    <SeverityBadge severity={inc.severity as 'info' | 'warning' | 'critical'} />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="flex flex-wrap items-center gap-2">
                      <span className="font-medium">{inc.title}</span>
                      {inc.alert_count > 1 && <Pill>{inc.alert_count} events</Pill>}
                    </span>
                    <span className="mt-0.5 block text-xs" style={{ color: 'var(--muted)' }}>
                      <span className="font-mono">{inc.source}</span>
                      {index.names.get(inc.source) && <span> ({index.names.get(inc.source)})</span>}
                      {' · '}
                      {formatTime(inc.last_seen)}
                    </span>
                  </span>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--muted)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden className="mt-1 shrink-0">
                    <path d="M9 18l6-6-6-6" />
                  </svg>
                </Link>
              </li>
            ))}
            {more > 0 && (
              <li style={{ borderTop: '1px solid var(--border)' }}>
                <Link to="/alerts?unacked=1" className="block px-4 py-2.5 text-sm font-medium" style={{ color: 'var(--accent-strong)' }}>
                  and {open.length === OUTSTANDING_FETCHED ? 'more' : `${more} more`}
                </Link>
              </li>
            )}
          </ul>
        )}
      </Card>

      <Card>
        <CardHeader title="Top talkers" sub="last hour · by volume" />
        <div className="px-4 pb-4">
          {talkersUnavailable ? (
            <EmptyState>The server could not answer for top talkers.</EmptyState>
          ) : status.overview.loading && !status.overview.data ? (
            <div className="text-sm" style={{ color: 'var(--muted)' }}>
              Checking…
            </div>
          ) : talkers.length > 0 ? (
            <TalkerRows talkers={talkers} index={index} />
          ) : (
            <EmptyState>No talkers in the last hour.</EmptyState>
          )}
        </div>
      </Card>

      <p className="text-xs" style={{ color: 'var(--muted)' }}>
        Everything here is right now or the last hour.{' '}
        <Link to="/traffic" className="hover:underline" style={{ color: 'var(--accent-strong)' }}>
          Traffic
        </Link>{' '}
        has the time control.
      </p>
    </div>
  )
}

// Verdict is the one sentence composed from the three subsystem states. It
// never reads as an all-clear when one of its inputs is silent — it names the
// silence instead.
function Verdict() {
  const { verdict } = useStatus()
  const { fg, bg } = toneColor(verdict.tone)
  return (
    <div className="rounded-lg border px-4 py-3" style={{ background: bg, borderColor: verdict.tone === 'loading' ? 'var(--border)' : fg }}>
      <p className="text-sm font-medium" style={{ color: verdict.tone === 'loading' ? 'var(--muted)' : fg }}>
        {verdict.text}
      </p>
    </div>
  )
}
