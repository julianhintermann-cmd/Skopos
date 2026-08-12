import { useMemo, useState } from 'react'
import { useFetch } from '../lib/useFetch'
import type { GeoIPSummary, TimePoint, Talker } from '../lib/api'
import { Card, CardHeader, Spinner, EmptyState } from '../components/ui'
import { ThroughputChart } from '../components/ThroughputChart'
import { TalkerBars } from '../components/TalkerBars'
import { CountryBars } from '../components/CountryBars'
import { SheetSelect } from '../components/mobile'
import { useDeviceNames } from '../lib/deviceNames'
import { useIsMobile } from '../lib/useIsMobile'
import { formatBytes } from '../lib/format'

interface FlowsResponse {
  from: string
  to: string
  resolution: string
  series: TimePoint[] | null
  top_talkers: Talker[] | null
}

const ranges = [
  { label: '1h', hint: 'Last hour', ms: 3600_000 },
  { label: '6h', hint: 'Last 6 hours', ms: 6 * 3600_000 },
  { label: '24h', hint: 'Last 24 hours', ms: 24 * 3600_000 },
  { label: '7d', hint: 'Last 7 days', ms: 7 * 24 * 3600_000 },
]

export function Traffic({ onUnauthorized }: { onUnauthorized: () => void }) {
  const [range, setRange] = useState(ranges[0])
  const { path, exportHref } = useMemo(() => {
    const to = new Date()
    const from = new Date(to.getTime() - range.ms)
    const window = `from=${from.toISOString()}&to=${to.toISOString()}`
    return { path: `/api/flows?${window}`, exportHref: `/api/export/flows.csv?${window}` }
  }, [range])

  const { data, loading, error } = useFetch<FlowsResponse>(path, { pollMs: 5000, onUnauthorized })
  const names = useDeviceNames(onUnauthorized)
  const geo = useFetch<GeoIPSummary>(`/api/geoip/summary?window=${Math.round(range.ms / 3600_000)}h`, {
    pollMs: 60000,
    onUnauthorized,
  })

  const isMobile = useIsMobile()

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-1.5">
        {isMobile ? (
          <SheetSelect
            value={range.label}
            label="Time range"
            options={ranges.map((r) => ({ value: r.label, label: r.label, hint: r.hint }))}
            onChange={(v) => setRange(ranges.find((r) => r.label === v) ?? ranges[0])}
          />
        ) : (
          ranges.map((r) => (
            <button
              key={r.label}
              onClick={() => setRange(r)}
              className="rounded-md px-3 py-1 text-xs font-medium"
              style={
                r.label === range.label
                  ? { background: 'var(--accent-tint)', color: 'var(--accent-strong)' }
                  : { background: 'var(--surface-2)', color: 'var(--muted)' }
              }
            >
              {r.label}
            </button>
          ))
        )}
        {!isMobile && (
          <span className="ml-2 font-mono text-xs" style={{ color: 'var(--muted)' }}>
            {data ? `resolution ${data.resolution}` : ''}
          </span>
        )}
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

      {loading && !data ? (
        <Spinner />
      ) : error ? (
        <EmptyState>Could not load traffic: {error}</EmptyState>
      ) : (
        <>
          <Card>
            <CardHeader title="Throughput" sub={`${range.label} · average bits per second`} />
            <div className="px-2 pb-2">
              {data?.series?.length ? (
                <ThroughputChart points={data.series} height={280} />
              ) : (
                <EmptyState>No traffic in this range.</EmptyState>
              )}
            </div>
          </Card>
          <Card>
            <CardHeader title="Top talkers" sub={`${range.label} · by volume`} />
            <div className="px-4 pb-4">
              {data?.top_talkers?.length ? (
                <TalkerBars talkers={data.top_talkers} names={names} format={(t) => formatBytes(t.bytes)} />
              ) : (
                <EmptyState>No talkers in this range.</EmptyState>
              )}
            </div>
          </Card>

          <div className="grid gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader title="Destination countries" sub={`${range.label} · where your traffic goes`} />
              <div className="px-4 pb-4">
                {!geo.data?.available ? (
                  <EmptyState>GeoIP database is still downloading — check back in a minute.</EmptyState>
                ) : geo.data.out.length > 0 ? (
                  <CountryBars stats={geo.data.out.slice(0, 12)} />
                ) : (
                  <EmptyState>No outbound traffic in this range.</EmptyState>
                )}
              </div>
            </Card>
            <Card>
              <CardHeader title="Source countries" sub={`${range.label} · who is knocking from outside`} />
              <div className="px-4 pb-4">
                {!geo.data?.available ? (
                  <EmptyState>GeoIP database is still downloading — check back in a minute.</EmptyState>
                ) : geo.data.in.length > 0 ? (
                  <CountryBars stats={geo.data.in.slice(0, 12)} />
                ) : (
                  <EmptyState>No inbound traffic in this range.</EmptyState>
                )}
              </div>
            </Card>
          </div>
        </>
      )}
    </div>
  )
}
