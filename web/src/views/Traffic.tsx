import { useMemo, useState } from 'react'
import { useFetch } from '../lib/useFetch'
import type { TimePoint, Talker } from '../lib/api'
import { Card, CardHeader, Spinner, EmptyState } from '../components/ui'
import { ThroughputChart } from '../components/ThroughputChart'
import { TalkerBars } from '../components/TalkerBars'
import { formatBytes } from '../lib/format'

interface FlowsResponse {
  from: string
  to: string
  resolution: string
  series: TimePoint[] | null
  top_talkers: Talker[] | null
}

const ranges = [
  { label: '1h', ms: 3600_000 },
  { label: '6h', ms: 6 * 3600_000 },
  { label: '24h', ms: 24 * 3600_000 },
  { label: '7d', ms: 7 * 24 * 3600_000 },
]

export function Traffic({ onUnauthorized }: { onUnauthorized: () => void }) {
  const [range, setRange] = useState(ranges[0])
  const path = useMemo(() => {
    const to = new Date()
    const from = new Date(to.getTime() - range.ms)
    return `/api/flows?from=${from.toISOString()}&to=${to.toISOString()}`
  }, [range])

  const { data, loading, error } = useFetch<FlowsResponse>(path, { pollMs: 5000, onUnauthorized })

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-1.5">
        {ranges.map((r) => (
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
        ))}
        <span className="ml-2 font-mono text-xs" style={{ color: 'var(--muted)' }}>
          {data ? `resolution ${data.resolution}` : ''}
        </span>
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
                <TalkerBars talkers={data.top_talkers} format={(t) => formatBytes(t.bytes)} />
              ) : (
                <EmptyState>No talkers in this range.</EmptyState>
              )}
            </div>
          </Card>
        </>
      )}
    </div>
  )
}
