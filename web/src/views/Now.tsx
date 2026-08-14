import { useEffect, useRef, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useFetch } from '../lib/useFetch'
import type { Incident } from '../lib/api'
import type { LiveNow } from '../lib/contracts'
import { Card, CardHeader, EmptyState, SeverityBadge, Pill, StaleBadge } from '../components/ui'
import { LivePulse } from '../components/LivePulse'
import { TalkerRows } from '../components/entity'
import { PageTitle, CaptureScopeNote } from '../components/PageTitle'
import { useDeviceIndex, type DeviceIndex } from '../lib/links'
import { useLiveStream } from '../lib/live'
import { useStatus, toneColor, type Tone } from '../lib/status'
import { useTick } from '../lib/poll'
import { formatRelative, formatTime } from '../lib/format'

// Now answers one question: is my network normal, and is Skopos actually
// watching it, this second.
//
// It has no time control anywhere on it, by rule. Anything that needs a window
// belongs on Traffic; what is left is the reading, the verdict and the things
// waiting for a human.
//
// The one time this page is allowed to talk about is the age of what it is
// showing. Every card here can be looking at a payload that stopped being
// replaced, and a screen that keeps drawing the last good answer as though it
// were current is the same lie as a fabricated one — worse on this page than
// anywhere else, because this is the page somebody glances at to decide that
// nothing is wrong.
const OUTSTANDING_SHOWN = 3
const OUTSTANDING_FETCHED = 20
const OUTSTANDING_POLL_MS = 15000

// The stream publishes a reading every second, so ten seconds of silence is ten
// missed frames. Ten is also useFetch's floor for "quiet has become
// suspicious"; two thresholds on one screen would let the tiles call themselves
// current while the cards beside them call themselves stale.
const LIVE_STALE_MS = 10_000

export function Now({ onUnauthorized }: { onUnauthorized: () => void }) {
  const index = useDeviceIndex(onUnauthorized)
  const { live, spark, sparkTimes, connected } = useLiveStream()

  return (
    <div className="flex flex-col gap-4">
      <PageTitle title="Now">
        <CaptureScopeNote />
      </PageTitle>

      <Verdict />

      <LiveReading live={live} connected={connected} />

      <LivePulse live={live} spark={spark} sparkTimes={sparkTimes} connected={connected} variant="compact" />

      <Outstanding index={index} onUnauthorized={onUnauthorized} />

      <TopTalkers index={index} />

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
  const { verdict, chips } = useStatus()
  const { fg, bg } = toneColor(verdict.tone)
  // A chip carries asOf exactly when its data is on screen and the newest poll
  // did not land. The verdict is composed from those chips, so it inherits
  // their age: without this line a sentence assembled from a poll that stopped
  // arriving still reads as a present-tense statement about the network.
  const asOf = chips.find((c) => c.asOf)?.asOf
  return (
    <div className="rounded-lg border px-4 py-3" style={{ background: bg, borderColor: verdict.tone === 'loading' ? 'var(--border)' : fg }}>
      <p className="text-sm font-medium" style={{ color: verdict.tone === 'loading' ? 'var(--muted)' : fg }}>
        {verdict.text}
      </p>
      {asOf && (
        <p className="mt-1 text-xs" style={{ color: 'var(--muted)' }}>
          As of {asOf} — the last update did not land, so this describes what Skopos knew then, not now.
        </p>
      )}
    </div>
  )
}

// LiveReading says the two things the tiles under it cannot say for themselves:
// what the capture was doing when the numbers were taken, and how old they are.
//
// LivePulse renders an absent measurement as "no reading", which is honest
// about the value and silent about the cause. And a stream that stops
// delivering never fails: the last frame stays on screen at full contrast,
// looking exactly like a network where nothing is happening. That is the poll
// staleness problem arriving through the SSE stream instead of through a fetch,
// and it needs the same answer.
function LiveReading({ live, connected }: { live: LiveNow | null; connected: boolean }) {
  // The stream re-renders this on every frame it delivers. When it stops
  // delivering, nothing re-renders, and the age of the reading would freeze at
  // whatever it was when the last frame arrived.
  useTick(5000)

  const { tone, text } = liveReading(live, connected, Date.now())
  const { fg } = toneColor(tone)
  return (
    <p className="text-xs" style={{ color: fg }}>
      {text}
    </p>
  )
}

// liveReading composes that sentence. Pure and clock-injected, so the age it
// reports is the one the caller re-rendered for.
function liveReading(live: LiveNow | null, connected: boolean, nowMs: number): { tone: Tone; text: string } {
  if (!live) {
    return connected
      ? { tone: 'neutral', text: 'Connected to the live stream; no reading has arrived yet.' }
      : { tone: 'unknown', text: 'Not connected to the live stream, and no reading has arrived — there is nothing behind the tiles below.' }
  }

  let tone: Tone = 'neutral'
  const worse = (t: Tone) => {
    // crit outranks warn outranks unknown outranks neutral. A capture that is
    // down must not be recoloured by a later clause about sampling.
    const rank: Record<string, number> = { neutral: 0, unknown: 1, warn: 2, crit: 3 }
    if ((rank[t] ?? 0) > (rank[tone] ?? 0)) tone = t
  }

  const parts: string[] = []
  const sources =
    typeof live.sources_up === 'number' && typeof live.sources_total === 'number'
      ? `${live.sources_up} of ${live.sources_total} sources`
      : null

  // The server decides this. A rate that stops changing is not evidence of a
  // dead capture, and a client that infers one will eventually infer it in the
  // direction that gets somebody robbed.
  switch (live.capture) {
    case 'up':
      parts.push(sources ? `Capturing on ${sources}` : 'Capturing')
      break
    case 'partial':
      worse('warn')
      parts.push(sources ? `Only ${sources} are capturing` : 'Some capture sources are not running')
      break
    case 'down':
      worse('crit')
      parts.push('Capture is down — nothing is being recorded')
      break
    case 'starting':
      parts.push('Capture is still starting')
      break
    default:
      worse('unknown')
      parts.push('This server does not report a capture state')
  }

  parts.push(live.last_packet_at ? `last packet ${formatRelative(live.last_packet_at)}` : 'no packet since Skopos started')

  // The compact tile row has no Sampling tile, so without this the operator
  // reads a throughput figure that is a floor with nothing saying so.
  if (live.sampling) {
    worse('warn')
    parts.push(
      typeof live.keep_rate === 'number' && live.keep_rate > 0
        ? `sampling 1 in ${Math.round(1 / live.keep_rate)} packets, so every rate here is a floor`
        : 'sampling, so every rate here is a floor',
    )
  }

  const measuredAt = live.measured_at
  if (!measuredAt || !Number.isFinite(new Date(measuredAt).getTime())) {
    worse('unknown')
    parts.push('the server did not say when this reading was taken')
  } else if (nowMs - new Date(measuredAt).getTime() > LIVE_STALE_MS) {
    worse('warn')
    parts.push(`this reading was taken ${formatRelative(measuredAt)} and nothing has replaced it`)
  }

  if (!connected) {
    worse('warn')
    parts.push('the stream is reconnecting')
  }

  return { tone, text: `${parts.join(' · ')}.` }
}

// Outstanding is the list of episodes waiting for a human. Its three failure
// modes are deliberately three different sentences: still asking, could not
// ask, and asked and there is nothing.
function Outstanding({ index, onUnauthorized }: { index: DeviceIndex; onUnauthorized: () => void }) {
  const { data, error, freshness, updatedAt } = useFetch<{ incidents: Incident[] | null }>(
    `/api/incidents?limit=${OUTSTANDING_FETCHED}&unacked=true`,
    { pollMs: OUTSTANDING_POLL_MS, onUnauthorized },
  )

  const header = (right?: ReactNode) => (
    <CardHeader title="Outstanding" sub="episodes nobody has acknowledged yet" right={right} />
  )

  if (freshness === 'loading') {
    return (
      <Card>
        {header()}
        <div className="px-4 pb-4 text-sm" style={{ color: 'var(--muted)' }}>
          Checking…
        </div>
      </Card>
    )
  }

  if (!data) {
    // Not "all clear" — a failed request is not an empty list, and this is the
    // card a person reads to decide whether anything needs them tonight.
    return (
      <Card>
        {header()}
        <EmptyState>
          Could not read the incident list{error ? `: ${error}` : ''}. Skopos cannot say whether anything is waiting.
        </EmptyState>
      </Card>
    )
  }

  // Past the freshness branch: a response arrived, so null here is the server's
  // own answer of "none" rather than our substitute for one.
  const open = data.incidents ?? []
  const shown = open.slice(0, OUTSTANDING_SHOWN)
  const more = open.length - shown.length

  return (
    <Card>
      {header(
        <span className="flex items-center gap-2">
          {freshness === 'stale' && <StaleBadge since={clockOf(updatedAt)} error={error ?? undefined} />}
          {open.length > 0 && (
            <Link to="/alerts?unacked=1" className="text-xs font-medium hover:underline" style={{ color: 'var(--accent-strong)' }}>
              See all
            </Link>
          )}
        </span>,
      )}
      {shown.length === 0 ? (
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
  )
}

// TopTalkers reads the overview poll the status strip is already running, and
// keeps four answers apart: still asking, could not ask, the server could not
// answer for this one key, and nobody talked.
function TopTalkers({ index }: { index: DeviceIndex }) {
  const { overview } = useStatus()
  const asOf = useArrivedAt(overview.data)

  const header = (right?: ReactNode) => <CardHeader title="Top talkers" sub="last hour · by volume" right={right} />

  if (overview.loading && !overview.data) {
    return (
      <Card>
        {header()}
        <div className="px-4 pb-4 text-sm" style={{ color: 'var(--muted)' }}>
          Checking…
        </div>
      </Card>
    )
  }

  if (!overview.data) {
    return (
      <Card>
        {header()}
        <EmptyState>
          Could not read the overview{overview.error ? `: ${overview.error}` : ''}. Skopos cannot say who has been talking.
        </EmptyState>
      </Card>
    )
  }

  const stale = overview.stale ? <StaleBadge since={asOf} error={overview.error ?? undefined} /> : undefined
  // The key is omitted, not zero-filled, when its query failed — so an absent
  // array is "we do not know" and an empty one is "nobody". The unavailable
  // list says which of the two an older payload means.
  const talkers = overview.data.top_talkers
  const named = (overview.data.unavailable ?? []).includes('top_talkers')

  return (
    <Card>
      {header(stale)}
      <div className="px-4 pb-4">
        {talkers === undefined ? (
          <EmptyState>
            {named
              ? 'The server could not answer for top talkers, so this is not "nobody is talking".'
              : 'This server did not report top talkers.'}
          </EmptyState>
        ) : talkers === null || talkers.length === 0 ? (
          <EmptyState>No talkers in the last hour.</EmptyState>
        ) : (
          <TalkerRows talkers={talkers} index={index} />
        )}
      </div>
    </Card>
  )
}

// clockOf is the wall time a payload arrived, for a badge that has to say how
// old what is on screen actually is rather than only that it is old.
function clockOf(ms: number | null | undefined): string | undefined {
  if (ms === null || ms === undefined) return undefined
  return new Date(ms).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hour12: false })
}

// useArrivedAt remembers when data last arrived. The shared overview is
// published as Fetched<OverviewNow>, which carries `stale` but not useFetch's
// `updatedAt`, so a badge over that poll has to keep the arrival time itself.
function useArrivedAt(data: unknown): string | undefined {
  const at = useRef<number | null>(null)
  useEffect(() => {
    if (data) at.current = Date.now()
  }, [data])
  return clockOf(at.current)
}
