import { useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useFetch, type Freshness } from '../lib/useFetch'
import type { Alert, Block, DomainStat, GeoIPSummary } from '../lib/api'
import {
  bucketSecondsOf,
  coverageNote,
  hasMeasurement,
  type LiveNow,
  type Point,
  type SearchResponse,
  type SeriesResponse,
} from '../lib/contracts'
import { Card, CardHeader, Skeleton, EmptyState, Pill, TextInput, StaleBadge } from '../components/ui'
import { ThroughputChart, type DirectionalPoint } from '../components/ThroughputChart'
import { EventStrip, type StripEvent } from '../components/EventStrip'
import { TrafficWorldMap } from '../components/TrafficWorldMap'
import { LivePulse, LiveDot } from '../components/LivePulse'
import { RangeControl, SegmentedControl } from '../components/RangeControl'
import { FlowTable, dirLabel, type FeedFlow } from '../components/FlowTable'
import { TalkerRows, CountryRows } from '../components/entity'
import { PageTitle, CaptureScopeNote } from '../components/PageTitle'
import { useDeviceIndex, type DeviceIndex } from '../lib/links'
import { useLiveStream } from '../lib/live'
import { useTick } from '../lib/poll'
import { toneColor, type Tone } from '../lib/status'
import { apiWindow, rangeWindow, useUrlRange, useUrlState, useUrlText, type Range } from '../lib/useUrlState'
import { formatBytes, formatCount, formatRelative } from '../lib/format'

// Traffic is the whole time axis: what moved, where to and who talked, over
// any span from right now to the last thirty days.
//
// Live and Traffic were never two questions. They were one question at two
// time horizons, and the horizon is a control — so Live is the leftmost
// position on the time control rather than a page of its own, and the five
// filter parameters are the same names in both modes, which is why moving
// between them loses nothing.
//
// Every card here also has to answer a second question the control cannot: how
// much of the window it actually saw, and how old its answer is. A span the
// capture missed and a span with no traffic in it are the same picture, and
// only words can separate them.

const LENSES = ['volume', 'flows', 'domains'] as const
type Lens = (typeof LENSES)[number]

// WindowRange is a range that actually has a window. Live is excluded at the
// type level, so no branch can hand a live view a fabricated from/to.
type WindowRange = Exclude<Range, 'live'>

// How often the volume lens re-asks, and when its answer stops counting as
// current. Three missed refreshes and never under ten seconds is the rule
// useFetch ages its own payloads by; a second threshold here would let the
// chart call itself fresh while the tiles beside it called themselves stale.
const VOLUME_REFRESH_MS = 5000
const VOLUME_STALE_MS = Math.max(3 * VOLUME_REFRESH_MS, 10_000)

// How many alerts the event strip asks for. /api/alerts takes no window, so a
// wide range is filtered client-side and the cap has to be named when it bites.
const STRIP_ALERT_LIMIT = 500

// The live stream publishes a reading every second, so ten seconds of silence
// is ten missed frames — and ten seconds is also useFetch's floor for "quiet
// has become suspicious". One threshold, so no two parts of this page can
// disagree about whether what they show is current.
const LIVE_STALE_MS = 10_000

export function Traffic({ onUnauthorized }: { onUnauthorized: () => void }) {
  const { range, setRange } = useUrlRange('1h')
  const [lens, setLens] = useUrlState<Lens>('lens', 'volume', { valid: LENSES, history: 'push' })
  const index = useDeviceIndex(onUnauthorized)

  return (
    <div className="flex flex-col gap-4">
      <PageTitle title="Traffic">
        <CaptureScopeNote />
      </PageTitle>

      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <RangeControl range={range} setRange={setRange} />
        <SegmentedControl
          value={lens}
          label="Lens"
          onChange={setLens}
          options={[
            { value: 'volume', label: 'Volume', hint: 'How much moved' },
            { value: 'flows', label: 'Flows', hint: 'Every conversation' },
            { value: 'domains', label: 'Domains', hint: 'Names your devices asked for' },
          ]}
        />
      </div>

      {lens === 'volume' &&
        (range === 'live' ? <LiveVolume /> : <WindowVolume range={range} index={index} onUnauthorized={onUnauthorized} />)}
      {lens === 'flows' && <Flows range={range} index={index} onUnauthorized={onUnauthorized} />}
      {lens === 'domains' && <Domains range={range} onUnauthorized={onUnauthorized} />}
    </div>
  )
}

// ---- volume ----------------------------------------------------------------

// LiveVolume is the zero-width position: current rate and a two-minute
// sparkline, pushed over SSE. No window, no chart, no totals — those need a
// span, and a span is a different position on the same control.
function LiveVolume() {
  const { live, spark, sparkTimes, connected } = useLiveStream()
  return (
    <div className="flex flex-col gap-3">
      <LiveReadingNote live={live} connected={connected} />
      <LivePulse live={live} spark={spark} sparkTimes={sparkTimes} connected={connected} />
    </div>
  )
}

function WindowVolume({
  range,
  index,
  onUnauthorized,
}: {
  range: WindowRange
  index: DeviceIndex
  onUnauthorized: () => void
}) {
  // /api/flows takes absolute times, so the path is rebuilt on every tick.
  // Polling one frozen path is how "last hour" became "that hour, yesterday".
  const tick = useTick(VOLUME_REFRESH_MS)
  const { path, exportHref } = useMemo(() => {
    const { from, to } = rangeWindow(range)
    const qs = `from=${from.toISOString()}&to=${to.toISOString()}`
    return { path: `/api/flows?${qs}`, exportHref: `/api/export/flows.csv?${qs}` }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [range, tick])

  const flows = useFetch<SeriesResponse>(path, { onUnauthorized })
  // A new path is a new fetch, and useFetch clears its state on one — by
  // design, so a payload is never drawn under a label it does not belong to.
  // Here the label is the range and the range has not changed; only the two
  // timestamps inside it have moved. Without holding the last answer the chart
  // blanked to a loading state once every five seconds, and a genuinely dropped
  // poll looked exactly like the healthy case.
  const held = useHeld(range, flows.data, flows.updatedAt)
  const data = flows.data ?? held.data
  const arrivedAt = flows.data ? flows.updatedAt : held.at

  const geo = useFetch<GeoIPSummary>(`/api/geoip/summary?window=${apiWindow(range)}`, {
    pollMs: 60000,
    onUnauthorized,
  })
  const [mapDir, setMapDir] = useState<'out' | 'in'>('out')

  // The strip's marks. Both endpoints answer for the whole database rather than
  // for this window, so they are stable paths that poll on their own clock and
  // are cut to the window below.
  const alerts = useFetch<{ alerts: Alert[] | null }>(`/api/alerts?limit=${STRIP_ALERT_LIMIT}`, {
    pollMs: 30000,
    onUnauthorized,
  })
  const blocks = useFetch<{ blocks: Block[] | null }>('/api/blocks', { pollMs: 60000, onUnauthorized })
  const events = useMemo(() => {
    // null is "not loaded" and it is not []. An empty strip asserts that
    // nothing happened in this window, which only an answer can support.
    if (!data || !alerts.data || !blocks.data) return null
    return stripEvents(data, alerts.data.alerts, blocks.data.blocks)
  }, [data, alerts.data, blocks.data])

  if (!data) {
    // The two ways to have nothing to draw are a request still out and a
    // request that failed, and they must not look alike.
    if (flows.freshness === 'loading') return <Skeleton variant="chart" />
    return (
      <EmptyState>
        Could not load traffic{flows.error ? `: ${flows.error}` : ''}. That is a failed request, not an empty window.
      </EmptyState>
    )
  }

  const ageMs = arrivedAt !== null ? Date.now() - arrivedAt : null
  const stale = flows.error !== null || (ageMs !== null && ageMs > VOLUME_STALE_MS)
  const staleBadge = stale ? <StaleBadge since={clockOf(arrivedAt)} error={flows.error ?? undefined} /> : undefined

  // The chart draws its own gaps now, so the series goes through whole: a
  // down or nodata bucket is a break in the line rather than a row quietly
  // removed before the chart ever saw it.
  const points: DirectionalPoint[] = data.series ?? []
  const bucket = bucketSecondsOf(data)
  const units = bucketLabel(bucket)
  const coverage = coverageLine(data, units)
  const split = points.some((p) => p.out_bytes != null && p.in_bytes != null)
  const talkers = data.top_talkers
  const talkersNamed = (data.unavailable ?? []).includes('top_talkers')
  const alertsCapped = alerts.data?.alerts != null && alerts.data.alerts.length >= STRIP_ALERT_LIMIT
  // When either list stops updating the row can be missing a mark that has
  // since been raised, and a row missing a mark reads as a quiet window.
  const marksStale = alerts.freshness === 'stale' || blocks.freshness === 'stale'
  const marksAt = marksStale ? clockOf(oldest(alerts.updatedAt, blocks.updatedAt)) : undefined
  const geoStale =
    geo.freshness === 'stale' ? <StaleBadge since={clockOf(geo.updatedAt)} error={geo.error ?? undefined} /> : undefined

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-2">
        <span className="font-mono text-xs" style={{ color: 'var(--muted)' }}>
          resolution {data.resolution}
        </span>
        <a
          href={exportHref}
          download
          className="ml-auto rounded-md px-3 py-1.5 text-xs font-medium"
          style={{ background: 'var(--surface-2)', color: 'var(--muted)' }}
          title="Download the raw flows of this range as CSV"
        >
          Export CSV
        </a>
      </div>

      <Card>
        <CardHeader
          title="Throughput"
          sub={`${range} · average bits per second${split ? ' · out and in where the split was recorded' : ''}`}
          right={staleBadge}
        />
        {/* The strip is a sibling of the chart inside this one padded box on
            purpose: it reads the chart's drawn frame, and a padding box of its
            own would offset the marks from the spikes they name. */}
        <div className="px-2 pb-2">
          {points.length > 0 ? (
            <>
              <ThroughputChart points={points} bucketSeconds={bucket} height={280} syncGroup="traffic" />
              <EventStrip events={events} from={data.from} to={data.to} syncGroup="traffic" />
            </>
          ) : (
            <EmptyState>{emptyReason(data)}</EmptyState>
          )}
        </div>
        {coverage && (
          <p className="px-4 pb-1 text-xs" style={{ color: coverage.color }}>
            {coverage.text}
          </p>
        )}
        {points.length > 0 && (
          // What the strip does not carry, said rather than implied by an empty
          // row: /api/blocks answers for what is in force now, so a block that
          // expired inside this window leaves no mark.
          <p className="px-4 pb-3 text-xs" style={{ color: 'var(--muted)' }}>
            Marks are alerts raised in this window and blocks still in force; one that has since expired is not on the
            row.
            {alertsCapped && ` Only the newest ${STRIP_ALERT_LIMIT} alerts were read, so older ones in this window are missing.`}
            {marksAt && ` Both lists last arrived at ${marksAt} and have not updated since.`}
          </p>
        )}
      </Card>

      <Card>
        <CardHeader title="Top talkers" sub={`${range} · by volume`} right={staleBadge} />
        <div className="px-4 pb-4">
          {talkers === undefined ? (
            <EmptyState>
              {talkersNamed
                ? 'The server could not answer for top talkers in this window, so this is not "nobody talked".'
                : 'This server did not report top talkers for this window.'}
            </EmptyState>
          ) : talkers === null || talkers.length === 0 ? (
            <EmptyState>No talkers in this range.</EmptyState>
          ) : (
            <TalkerRows talkers={talkers} index={index} />
          )}
        </div>
      </Card>

      <Card>
        <CardHeader
          title="World map"
          sub={`${range} · ${mapDir === 'out' ? 'where your traffic goes' : 'who is knocking from outside'}`}
          right={
            <div className="flex items-center gap-1">
              {geoStale}
              {(['out', 'in'] as const).map((d) => (
                <button
                  key={d}
                  onClick={() => setMapDir(d)}
                  className="rounded-md px-2.5 py-1 text-xs font-medium"
                  style={
                    d === mapDir
                      ? { background: 'var(--accent-tint)', color: 'var(--accent-strong)' }
                      : { background: 'var(--surface-2)', color: 'var(--muted)' }
                  }
                >
                  {d === 'out' ? 'Outbound' : 'Inbound'}
                </button>
              ))}
            </div>
          }
        />
        <div className="px-4 pb-3">
          <GeoBody summary={geo.data} freshness={geo.freshness} error={geo.error}>
            {(s) => {
              const stats = mapDir === 'out' ? s.out : s.in
              return stats.length > 0 ? (
                <TrafficWorldMap stats={stats} />
              ) : (
                <EmptyState>No {mapDir === 'out' ? 'outbound' : 'inbound'} traffic in this range.</EmptyState>
              )
            }}
          </GeoBody>
        </div>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Destination countries" sub={`${range} · tap a country to block it`} right={geoStale} />
          <div className="px-4 pb-4">
            <GeoBody summary={geo.data} freshness={geo.freshness} error={geo.error}>
              {(s) =>
                s.out.length > 0 ? (
                  <CountryRows stats={s.out.slice(0, 12)} />
                ) : (
                  <EmptyState>No outbound traffic in this range.</EmptyState>
                )
              }
            </GeoBody>
          </div>
        </Card>
        <Card>
          <CardHeader title="Source countries" sub={`${range} · who is knocking from outside`} right={geoStale} />
          <div className="px-4 pb-4">
            <GeoBody summary={geo.data} freshness={geo.freshness} error={geo.error}>
              {(s) =>
                s.in.length > 0 ? (
                  <CountryRows stats={s.in.slice(0, 12)} />
                ) : (
                  <EmptyState>No inbound traffic in this range.</EmptyState>
                )
              }
            </GeoBody>
          </div>
        </Card>
      </div>
    </div>
  )
}

// ---- flows -----------------------------------------------------------------

// The five filters are the names /api/search already accepts, and they map one
// to one onto the fields of a streamed flow. That identity is the whole reason
// the switch between live and a window keeps the operator's place: nothing is
// translated, so nothing can be lost in translation.
function Flows({ range, index, onUnauthorized }: { range: Range; index: DeviceIndex; onUnauthorized: () => void }) {
  const [addressDraft, setAddressDraft, address] = useUrlText('address')
  const [portDraft, setPortDraft, port] = useUrlText('port')
  const [nameDraft, setNameDraft, name] = useUrlText('name')
  const [proto, setProto] = useUrlState('proto', '', { valid: ['', 'tcp', 'udp', 'icmp'] as const })
  const [dir, setDir] = useUrlState('dir', '', { valid: ['', 'lan_wan', 'wan_lan'] as const })
  const filter = { address, port, name, proto, dir }

  return (
    <Card>
      <CardHeader
        title="Flows"
        sub={
          range === 'live'
            ? 'every conversation as it completes'
            : 'the raw flow records — the aggregates have already thrown this detail away'
        }
        right={<span className="font-mono text-xs" style={{ color: 'var(--muted)' }}>{range}</span>}
      />

      <div className="flex flex-wrap items-end gap-2 px-4 pb-3">
        <FilterField label="Address" value={addressDraft} onChange={setAddressDraft} placeholder="192.168.1.20 or 10.0.0.0/8" width="w-52" />
        <FilterField label="Port" value={portDraft} onChange={setPortDraft} placeholder="443" width="w-20" />
        <FilterField label="Domain" value={nameDraft} onChange={setNameDraft} placeholder="youtube.com" width="w-40" />
        <div className="flex flex-col gap-1">
          <FilterLabel>Proto</FilterLabel>
          <SegmentedControl
            value={proto}
            label="Protocol"
            onChange={setProto}
            options={[
              { value: '', label: 'Any' },
              { value: 'tcp', label: 'TCP' },
              { value: 'udp', label: 'UDP' },
              { value: 'icmp', label: 'ICMP' },
            ]}
          />
        </div>
        <div className="flex flex-col gap-1">
          <FilterLabel>Direction</FilterLabel>
          <SegmentedControl
            value={dir}
            label="Direction"
            onChange={setDir}
            options={[
              { value: '', label: 'Any' },
              { value: 'lan_wan', label: 'Outbound' },
              { value: 'wan_lan', label: 'Inbound' },
            ]}
          />
        </div>
      </div>

      {range === 'live' ? (
        <LiveFlows filter={filter} index={index} onUnauthorized={onUnauthorized} />
      ) : (
        <SearchFlows range={range} filter={filter} index={index} onUnauthorized={onUnauthorized} />
      )}
    </Card>
  )
}

interface Filter {
  address: string
  port: string
  name: string
  proto: string
  dir: string
}

// matchFlow is the client-side half of the same filter. It is deliberately no
// narrower than the server's: a substring match on an address can only show
// more rows than /api/search would, never fewer, so nothing disappears when
// the operator moves the control from live to a window.
function matchFlow(f: FeedFlow, q: Filter, index: DeviceIndex): boolean {
  if (q.address) {
    const v = q.address.toLowerCase()
    const hay = [f.src, f.dst, index.names.get(f.src) ?? '', index.names.get(f.dst) ?? '']
    if (!hay.some((h) => h.toLowerCase().includes(v))) return false
  }
  if (q.port && String(f.src_port) !== q.port && String(f.dst_port) !== q.port) return false
  if (q.name && !(f.dst_name ?? '').toLowerCase().includes(q.name.toLowerCase())) return false
  if (q.proto && f.proto.toLowerCase() !== q.proto.toLowerCase()) return false
  if (q.dir && f.dir !== q.dir) return false
  return true
}

function LiveFlows({ filter, index, onUnauthorized }: { filter: Filter; index: DeviceIndex; onUnauthorized: () => void }) {
  const [paused, setPaused] = useState(false)
  const { live, rows, connected, buffered, flush } = useLiveStream({ flows: true, paused, onUnauthorized })
  const visible = useMemo(() => rows.filter((r) => matchFlow(r, filter, index)), [rows, filter, index])
  const filtering = !!(filter.address || filter.port || filter.name || filter.proto || filter.dir)

  return (
    <>
      <div className="flex flex-wrap items-center gap-2 px-4 pb-2.5">
        <LiveDot connected={connected} />
        <Pill tone="neutral">{formatCount(visible.length)} shown</Pill>
        <button
          type="button"
          onClick={() => {
            if (paused) flush()
            setPaused(!paused)
          }}
          className="ml-auto rounded-md px-3 py-1.5 text-xs font-medium"
          style={
            paused
              ? { background: 'var(--warn-tint)', color: 'var(--warn)' }
              : { background: 'var(--surface-2)', color: 'var(--muted)' }
          }
        >
          {paused ? `Resume${buffered ? ` (+${buffered})` : ''}` : 'Pause'}
        </button>
      </div>
      <FlowTable
        rows={visible}
        index={index}
        empty={
          rows.length > 0 && filtering
            ? 'No live flows match this filter. Move the control to a window to search history instead.'
            : // An empty feed under a healthy-looking "Listening…" is the one
              // sentence a dead capture must not be allowed to borrow.
              live?.capture === 'down'
              ? 'Capture is down — no flow can arrive while nothing is being recorded.'
              : live?.capture === 'starting'
                ? 'Capture is still starting.'
                : connected
                  ? 'Listening for traffic…'
                  : 'Connecting to the live stream…'
        }
      />
    </>
  )
}

function SearchFlows({
  range,
  filter,
  index,
  onUnauthorized,
}: {
  range: WindowRange
  filter: Filter
  index: DeviceIndex
  onUnauthorized: () => void
}) {
  // window= is resolved by the server against its own clock, so this path is
  // both stable and always relative — the poll cannot go stale.
  const params = new URLSearchParams({ window: apiWindow(range), limit: '300' })
  if (filter.address) params.set('address', filter.address)
  if (filter.port) params.set('port', filter.port)
  if (filter.name) params.set('name', filter.name)
  if (filter.proto) params.set('proto', filter.proto)
  if (filter.dir) params.set('dir', filter.dir)
  const query = params.toString()

  const { data, error, freshness, updatedAt } = useFetch<SearchResponse>(`/api/search?${query}`, {
    pollMs: 15000,
    onUnauthorized,
  })

  if (freshness === 'loading') return <Skeleton variant="row" rows={4} />
  if (!data) {
    return (
      <EmptyState>
        Could not search{error ? `: ${error}` : ''}. Nothing was read, so this is not "nothing matched".
      </EmptyState>
    )
  }

  // Past the freshness branch: the response arrived, so null is the server
  // saying no flow matched rather than us saying it for it.
  const flows = data.flows ?? []
  return (
    <>
      <div className="flex flex-wrap items-center gap-2 px-4 pb-2.5 text-xs" style={{ color: 'var(--muted)' }}>
        {/* truncated is the difference between "nothing else happened" and
            "nothing else fit on the page". Reporting the page size as a total
            is what this line exists to stop. */}
        <span>
          {data.truncated ? `${formatCount(data.count)} of more` : `${formatCount(data.count)} flows`} · {range}
        </span>
        {data.truncated && <Pill tone="warn">page limit reached — narrow the filter</Pill>}
        {filter.dir && <Pill tone="neutral">{dirLabel(filter.dir)}</Pill>}
        {freshness === 'stale' && <StaleBadge since={clockOf(updatedAt)} error={error ?? undefined} />}
        <a href={`/api/search?${query}`} target="_blank" rel="noreferrer" className="ml-auto hover:underline">
          open as JSON
        </a>
      </div>
      <FlowTable rows={flows} index={index} empty="Nothing matched in this window." />
    </>
  )
}

// ---- domains ---------------------------------------------------------------

function Domains({ range, onUnauthorized }: { range: Range; onUnauthorized: () => void }) {
  // Domains are an aggregate and there is no live aggregate to show, so the
  // live position falls back to the last hour — and says so, rather than
  // showing an hour of history under a control that reads "Live".
  const effective: WindowRange = range === 'live' ? '1h' : range
  const { data, error, freshness, updatedAt } = useFetch<{ domains: DomainStat[] | null }>(
    `/api/domains?window=${apiWindow(effective)}&limit=100`,
    { pollMs: 30000, onUnauthorized },
  )

  return (
    <Card>
      <CardHeader
        title="Domains"
        sub={
          range === 'live'
            ? 'last hour — domains are an aggregate, so there is no live view of them'
            : `${range} · names your devices actually asked for, learned from DNS answers and TLS handshakes on the wire`
        }
        right={freshness === 'stale' ? <StaleBadge since={clockOf(updatedAt)} error={error ?? undefined} /> : undefined}
      />
      <div className="px-4 pb-4">
        {freshness === 'loading' ? (
          <Skeleton variant="row" rows={5} />
        ) : !data ? (
          // Error before data was the old order here, so one dropped poll threw
          // away a list that was on screen and correct a second earlier.
          <EmptyState>
            Could not load domains{error ? `: ${error}` : ''}. Skopos cannot say which names were asked for in this
            window.
          </EmptyState>
        ) : (
          <DomainList domains={data.domains ?? []} />
        )}
      </div>
    </Card>
  )
}

function DomainList({ domains }: { domains: DomainStat[] }) {
  if (domains.length === 0) {
    return (
      <EmptyState>
        No domains in this window. Skopos learns them from DNS and mDNS answers and TLS server names as they pass the
        wire — give it a few minutes of traffic.
      </EmptyState>
    )
  }
  const max = Math.max(...domains.map((d) => d.bytes), 1)
  return (
    <ul className="flex flex-col gap-1.5">
      {domains.map((d) => (
        <li key={d.name} className="flex flex-col gap-1">
          <div className="flex items-baseline justify-between gap-3 text-sm">
            <Link
              to={`/domain/${encodeURIComponent(d.name)}`}
              className="min-w-0 truncate font-medium hover:underline"
              style={{ color: 'var(--accent-strong)' }}
            >
              {d.name}
            </Link>
            <span className="shrink-0 font-mono text-xs tabnums" style={{ color: 'var(--muted)' }}>
              {formatBytes(d.bytes)} · {formatCount(d.flows)} flows
              {d.devices > 1 && ` · ${d.devices} devices`}
            </span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full" style={{ background: 'var(--surface-2)' }}>
            <div
              className="h-full rounded-full"
              style={{ width: `${Math.max(1.5, (d.bytes / max) * 100)}%`, background: 'var(--accent)' }}
            />
          </div>
        </li>
      ))}
    </ul>
  )
}

// ---- shared bits -----------------------------------------------------------

function FilterLabel({ children }: { children: React.ReactNode }) {
  return (
    <span className="font-mono text-[0.62rem] font-semibold uppercase tracking-[0.1em]" style={{ color: 'var(--muted)' }}>
      {children}
    </span>
  )
}

function FilterField({
  label,
  value,
  onChange,
  placeholder,
  width,
}: {
  label: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
  width: string
}) {
  return (
    <label className={`flex flex-col gap-1 ${width}`}>
      <FilterLabel>{label}</FilterLabel>
      <TextInput value={value} onChange={onChange} placeholder={placeholder} mono className="!px-2.5 !py-1.5 !text-xs" />
    </label>
  )
}

// LiveReadingNote says the two things the tiles under it cannot say for
// themselves: what the capture was doing when the numbers were taken, and how
// old they are. A stream that stops delivering never errors — the last frame
// stays on screen at full contrast, looking exactly like a network where
// nothing is happening.
//
// Now renders the same sentence over the same payload. Both copies are here
// because neither view may edit LivePulse, which is where this belongs.
function LiveReadingNote({ live, connected }: { live: LiveNow | null; connected: boolean }) {
  // Nothing else re-renders once the frames stop, so the age of the reading
  // would freeze at whatever it was when the last one arrived.
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
    // crit outranks warn outranks unknown. A capture that is down must not be
    // recoloured by a later clause about sampling.
    const rank: Record<string, number> = { neutral: 0, unknown: 1, warn: 2, crit: 3 }
    if ((rank[t] ?? 0) > (rank[tone] ?? 0)) tone = t
  }

  const parts: string[] = []
  const sources =
    typeof live.sources_up === 'number' && typeof live.sources_total === 'number'
      ? `${live.sources_up} of ${live.sources_total} sources`
      : null

  // The server decides the capture state. A rate that stops changing is not
  // evidence of a dead capture, and a client that infers one will infer it
  // wrongly in the direction that matters.
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

// GeoBody renders the three reasons a country card cannot draw yet, once, so
// the three cards cannot drift apart. The old code asked `!geo.data?.available`
// and answered "the database is still downloading" — a claim about the database
// made from a request that never came back.
function GeoBody({
  summary,
  freshness,
  error,
  children,
}: {
  summary: GeoIPSummary | null
  freshness: Freshness
  error: string | null
  children: (s: GeoIPSummary) => React.ReactNode
}) {
  if (!summary) {
    if (freshness === 'loading') {
      return (
        <div className="text-sm" style={{ color: 'var(--muted)' }}>
          Checking…
        </div>
      )
    }
    return (
      <EmptyState>
        Could not read the country summary{error ? `: ${error}` : ''}. That is a failed request, not an absence of
        foreign traffic.
      </EmptyState>
    )
  }
  if (!summary.available) {
    return <EmptyState>The GeoIP database has not finished downloading, so no traffic can be placed on a map yet.</EmptyState>
  }
  return <>{children(summary)}</>
}

// useHeld remembers the last payload that actually arrived under one key, so a
// refresh does not blank the screen. The key is the label the payload was drawn
// under: when it changes the held answer is dropped rather than re-shown beside
// a range it does not describe.
function useHeld<T>(key: string, data: T | null, at: number | null): { data: T | null; at: number | null } {
  const held = useRef<{ key: string; data: T; at: number | null } | null>(null)
  if (data !== null) held.current = { key, data, at }
  else if (held.current && held.current.key !== key) held.current = null
  return held.current ? { data: held.current.data, at: held.current.at } : { data: null, at: null }
}

// clockOf is the wall time a payload arrived, so a stale badge can say how old
// what is on screen is rather than only that it is old.
function clockOf(ms: number | null | undefined): string | undefined {
  if (ms === null || ms === undefined) return undefined
  return new Date(ms).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hour12: false })
}

// oldest is the earlier of two arrival times, so a sentence covering two polls
// dates itself by the one that has been silent longest.
function oldest(a: number | null, b: number | null): number | null {
  if (a === null) return b
  if (b === null) return a
  return Math.min(a, b)
}

function bucketLabel(bucket: number | null): string {
  if (bucket === 60) return 'minutes'
  if (bucket === 3600) return 'hours'
  if (bucket === 86400) return 'days'
  return 'buckets'
}

// coverageLine is the sentence beside the chart: how much of this window was
// actually captured. All three cases speak, including the good one — a card
// that says nothing when coverage is complete says exactly what a server that
// cannot report coverage says, and those are different facts.
function coverageLine(data: SeriesResponse, units: string): { text: string; color: string } | null {
  const c = data.coverage
  if (!c) {
    return {
      color: 'var(--muted)',
      text: 'This server does not report coverage, so a flat stretch here cannot be told apart from a stretch nobody captured.',
    }
  }
  const total = c.measured + c.sampled + c.down + c.nodata + c.unverified
  if (total === 0) return null
  const note = coverageNote(c, units)
  if (!note) return { color: 'var(--muted)', text: `All ${total} ${units} of this window were captured.` }
  return { color: 'var(--warn)', text: `${note}. A bucket with no measurement is a break in the line, never a zero.` }
}

// stripEvents maps what happened in this window onto the strip's vocabulary.
//
// The filtering is client-side because neither endpoint takes a window:
// /api/alerts answers for the whole table and /api/blocks answers for what is
// in force right now. The second is narrower than the truth — a block that
// expired inside the window is not in it — which the caption under the chart
// says out loud rather than letting an empty row imply nothing was blocked.
function stripEvents(series: SeriesResponse, alerts: Alert[] | null, blocks: Block[] | null): StripEvent[] {
  const from = new Date(series.from).getTime()
  const to = new Date(series.to).getTime()
  const out: StripEvent[] = []
  if (!Number.isFinite(from) || !Number.isFinite(to)) return out

  for (const a of alerts ?? []) {
    const t = new Date(a.Time).getTime()
    if (!Number.isFinite(t) || t < from || t > to) continue
    out.push({
      time: a.Time,
      kind: 'alert',
      severity: a.Severity === 'critical' ? 'critical' : a.Severity === 'warning' ? 'warn' : 'info',
      label: `${a.Title} · ${a.Source}`,
    })
  }
  for (const b of blocks ?? []) {
    const t = new Date(b.Created).getTime()
    if (!Number.isFinite(t) || t < from || t > to) continue
    out.push({ time: b.Created, kind: 'block', label: `Blocked ${b.Prefix} — ${b.Reason}` })
  }
  out.push(...gapSpans(series.series, bucketSecondsOf(series)))
  return out
}

// gapSpans turns runs of uncaptured buckets into the spans the strip hatches.
// They are read off the same array the chart draws, so the hatch cannot
// disagree with the break in the line above it.
//
// A span ends at the next bucket's own timestamp rather than at start + one
// bucket. The chart's x-scale runs from the first bucket's timestamp to the
// last one's, so a run that reaches the end of the series would otherwise be
// computed a bucket wider than the picture it is annotating and paint past its
// right edge.
function gapSpans(points: Point[] | null, bucket: number | null): StripEvent[] {
  if (!points || !bucket || bucket <= 0) return []
  const units = bucketLabel(bucket)
  const out: StripEvent[] = []
  let i = 0
  while (i < points.length) {
    const p = points[i]
    if (p.state !== 'down' && p.state !== 'nodata') {
      i++
      continue
    }
    let j = i + 1
    while (j < points.length && points[j].state === p.state) j++
    const until = j < points.length ? points[j].time : points[points.length - 1].time
    if (Number.isFinite(new Date(p.time).getTime()) && Number.isFinite(new Date(until).getTime())) {
      out.push({
        time: p.time,
        until,
        kind: 'gap',
        label:
          p.state === 'down'
            ? `Capture was not running — ${j - i} ${units}`
            : `Outside recorded history — ${j - i} ${units}`,
      })
    }
    i = j
  }
  return out
}

// emptyReason distinguishes the three ways a chart can have nothing to draw.
// "No traffic" is a claim about the network; the other two are claims about
// Skopos, and saying the wrong one is how a broken capture reads as a quiet
// night.
function emptyReason(data: SeriesResponse): string {
  const c = data.coverage
  if (!c) return 'No traffic in this range.'
  if (hasMeasurement(c, data.series)) return 'No traffic in this range.'
  if (c.down > 0 && c.down >= c.nodata) return 'Capture was not running for any of this window — there is nothing to show.'
  if (c.nodata > 0) return 'Skopos has no recorded history for this window.'
  return 'No traffic in this range.'
}
