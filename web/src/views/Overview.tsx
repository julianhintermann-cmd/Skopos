import { useFetch } from '../lib/useFetch'
import type { Overview as OverviewData } from '../lib/api'
import { Card, CardHeader, StatTile, Spinner, EmptyState, Pill } from '../components/ui'
import { ThroughputChart } from '../components/ThroughputChart'
import { formatBits, formatBytes, formatPPS } from '../lib/format'
import { TalkerBars } from '../components/TalkerBars'
import { useDeviceNames } from '../lib/deviceNames'

export function Overview({ onUnauthorized }: { onUnauthorized: () => void }) {
  const { data, loading, error } = useFetch<OverviewData>('/api/overview', { pollMs: 2000, onUnauthorized })
  const names = useDeviceNames(onUnauthorized)

  if (loading && !data) return <Spinner />
  if (error) return <EmptyState>Could not load overview: {error}</EmptyState>
  if (!data) return null

  const series = data.throughput_1h ?? []
  const talkers = data.top_talkers ?? []

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile
          label="Throughput"
          value={formatBits(data.live.bits_per_second).split(' ')[0]}
          unit={formatBits(data.live.bits_per_second).split(' ')[1]}
          tone="accent"
          hint={data.live.sampling ? `sampling · ${formatPPS(data.live.packets_per_second)}` : formatPPS(data.live.packets_per_second)}
        />
        <StatTile label="Active blocks" value={String(data.active_blocks)} tone={data.active_blocks > 0 ? 'warn' : 'neutral'} />
        <StatTile
          label="Unacked alerts"
          value={String(data.unacked_alerts)}
          tone={data.unacked_alerts > 0 ? 'crit' : 'good'}
        />
        <StatTile label="Enforcement" value={data.enforcing ? 'On' : 'Observe'} tone={data.enforcing ? 'good' : 'neutral'} />
      </div>

      <Card>
        <CardHeader
          title="Throughput"
          sub="last hour · average bits per second"
          right={data.live.sampling ? <Pill tone="warn">sampling</Pill> : undefined}
        />
        <div className="px-2 pb-2">
          {series.length > 0 ? <ThroughputChart points={series} /> : <EmptyState>No traffic recorded yet.</EmptyState>}
        </div>
      </Card>

      <Card>
        <CardHeader title="Top talkers" sub="last hour · by volume" />
        <div className="px-4 pb-4">
          {talkers.length > 0 ? (
            <TalkerBars talkers={talkers} names={names} format={(t) => formatBytes(t.bytes)} />
          ) : (
            <EmptyState>No talkers yet.</EmptyState>
          )}
        </div>
      </Card>
    </div>
  )
}
