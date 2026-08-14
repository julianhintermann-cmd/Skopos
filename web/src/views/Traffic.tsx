import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useFetch } from '../lib/useFetch'
import type { DomainStat, GeoIPSummary } from '../lib/api'
import {
  bucketSecondsOf,
  coverageNote,
  hasMeasurement,
  type SearchResponse,
  type SeriesResponse,
} from '../lib/contracts'
import { Card, CardHeader, Spinner, EmptyState, Pill, TextInput } from '../components/ui'
import { ThroughputChart } from '../components/ThroughputChart'
import { TrafficWorldMap } from '../components/TrafficWorldMap'
import { LivePulse, LiveDot } from '../components/LivePulse'
import { RangeControl, SegmentedControl } from '../components/RangeControl'
import { FlowTable, dirLabel, type FeedFlow } from '../components/FlowTable'
import { TalkerRows, CountryRows } from '../components/entity'
import { PageTitle, CaptureScopeNote } from '../components/PageTitle'
import { useDeviceIndex, type DeviceIndex } from '../lib/links'
import { useLiveStream } from '../lib/live'
import { useTick } from '../lib/poll'
import { apiWindow, rangeWindow, useUrlRange, useUrlState, useUrlText, type Range } from '../lib/useUrlState'
import { formatBytes, formatCount } from '../lib/format'

// Traffic is the whole time axis: what moved, where to and who talked, over
// any span from right now to the last thirty days.
//
// Live and Traffic were never two questions. They were one question at two
// time horizons, and the horizon is a control — so Live is the leftmost
// position on the time control rather than a page of its own, and the five
// filter parameters are the same names in both modes, which is why moving
// between them loses nothing.

const LENSES = ['volume', 'flows', 'domains'] as const
type Lens = (typeof LENSES)[number]

// WindowRange is a range that actually has a window. Live is excluded at the
// type level, so no branch can hand a live view a fabricated from/to.
type WindowRange = Exclude<Range, 'live'>

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
  const { live, spark, connected } = useLiveStream()
  return <LivePulse live={live} spark={spark} connected={connected} />
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
  const tick = useTick(5000)
  const { path, exportHref } = useMemo(() => {
    const { from, to } = rangeWindow(range)
    const qs = `from=${from.toISOString()}&to=${to.toISOString()}`
    return { path: `/api/flows?${qs}`, exportHref: `/api/export/flows.csv?${qs}` }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [range, tick])

  const { data, loading, error } = useFetch<SeriesResponse>(path, { onUnauthorized })
  const geo = useFetch<GeoIPSummary>(`/api/geoip/summary?window=${apiWindow(range)}`, {
    pollMs: 60000,
    onUnauthorized,
  })
  const [mapDir, setMapDir] = useState<'out' | 'in'>('out')
  const mapStats = mapDir === 'out' ? (geo.data?.out ?? []) : (geo.data?.in ?? [])

  if (loading && !data) return <Spinner />
  if (!data) return <EmptyState>Could not load traffic: {error}</EmptyState>

  // The chart draws its own gaps now, so the series goes through whole: a
  // down or nodata bucket is a break in the line rather than a row quietly
  // removed before the chart ever saw it.
  const points = data.series ?? []
  const bucket = bucketSecondsOf(data)
  const note = coverageNote(data.coverage, bucketLabel(bucket))
  const talkers = data.top_talkers ?? []
  const talkersUnavailable = (data.unavailable ?? []).includes('top_talkers')

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
        <CardHeader title="Throughput" sub={`${range} · average bits per second`} />
        <div className="px-2 pb-2">
          {points.length > 0 ? (
            <ThroughputChart points={points} bucketSeconds={bucket} height={280} />
          ) : (
            <EmptyState>{emptyReason(data)}</EmptyState>
          )}
        </div>
        {note && (
          <p className="px-4 pb-3 text-xs" style={{ color: 'var(--warn)' }}>
            {note}. Buckets without a measurement are left out of the line rather than drawn as zero.
          </p>
        )}
      </Card>

      <Card>
        <CardHeader title="Top talkers" sub={`${range} · by volume`} />
        <div className="px-4 pb-4">
          {talkersUnavailable ? (
            <EmptyState>The server could not answer for top talkers in this window.</EmptyState>
          ) : talkers.length > 0 ? (
            <TalkerRows talkers={talkers} index={index} />
          ) : (
            <EmptyState>No talkers in this range.</EmptyState>
          )}
        </div>
      </Card>

      <Card>
        <CardHeader
          title="World map"
          sub={`${range} · ${mapDir === 'out' ? 'where your traffic goes' : 'who is knocking from outside'}`}
          right={
            <div className="flex items-center gap-1">
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
          {!geo.data?.available ? (
            <EmptyState>GeoIP database is still downloading — check back in a minute.</EmptyState>
          ) : mapStats.length > 0 ? (
            <TrafficWorldMap stats={mapStats} />
          ) : (
            <EmptyState>No {mapDir === 'out' ? 'outbound' : 'inbound'} traffic in this range.</EmptyState>
          )}
        </div>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Destination countries" sub={`${range} · tap a country to block it`} />
          <div className="px-4 pb-4">
            {!geo.data?.available ? (
              <EmptyState>GeoIP database is still downloading — check back in a minute.</EmptyState>
            ) : geo.data.out.length > 0 ? (
              <CountryRows stats={geo.data.out.slice(0, 12)} />
            ) : (
              <EmptyState>No outbound traffic in this range.</EmptyState>
            )}
          </div>
        </Card>
        <Card>
          <CardHeader title="Source countries" sub={`${range} · who is knocking from outside`} />
          <div className="px-4 pb-4">
            {!geo.data?.available ? (
              <EmptyState>GeoIP database is still downloading — check back in a minute.</EmptyState>
            ) : geo.data.in.length > 0 ? (
              <CountryRows stats={geo.data.in.slice(0, 12)} />
            ) : (
              <EmptyState>No inbound traffic in this range.</EmptyState>
            )}
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
  const { rows, connected, buffered, flush } = useLiveStream({ flows: true, paused, onUnauthorized })
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

  const { data, loading, error } = useFetch<SearchResponse>(`/api/search?${query}`, { pollMs: 15000, onUnauthorized })

  if (loading && !data) return <Spinner />
  if (!data) return <EmptyState>Could not search: {error}</EmptyState>

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
  const { data, loading, error } = useFetch<{ domains: DomainStat[] | null }>(
    `/api/domains?window=${apiWindow(effective)}&limit=100`,
    { pollMs: 30000, onUnauthorized },
  )

  const domains = data?.domains ?? []
  const max = domains.length > 0 ? domains[0].bytes : 1

  return (
    <Card>
      <CardHeader
        title="Domains"
        sub={
          range === 'live'
            ? 'last hour — domains are an aggregate, so there is no live view of them'
            : `${range} · names your devices actually asked for, learned from DNS answers and TLS handshakes on the wire`
        }
      />
      <div className="px-4 pb-4">
        {loading && !data ? (
          <Spinner />
        ) : error ? (
          <EmptyState>Could not load domains: {error}</EmptyState>
        ) : domains.length === 0 ? (
          <EmptyState>
            No domains in this window. Skopos learns them from DNS and mDNS answers and TLS server names as they
            pass the wire — give it a few minutes of traffic.
          </EmptyState>
        ) : (
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
        )}
      </div>
    </Card>
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

function bucketLabel(bucket: number | null): string {
  if (bucket === 60) return 'minutes'
  if (bucket === 3600) return 'hours'
  if (bucket === 86400) return 'days'
  return 'buckets'
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
