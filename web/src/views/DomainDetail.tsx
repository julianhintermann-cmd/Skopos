import { Link, useParams } from 'react-router-dom'
import { useFetch } from '../lib/useFetch'
import type { DomainStat } from '../lib/api'
import type { SearchResponse } from '../lib/contracts'
import { Card, CardHeader, Spinner, EmptyState, StatTile, Pill } from '../components/ui'
import { FlowTable } from '../components/FlowTable'
import { RangeControl } from '../components/RangeControl'
import { PageTitle } from '../components/PageTitle'
import { useDeviceIndex } from '../lib/links'
import { apiWindow, useUrlRange, WINDOWS } from '../lib/useUrlState'
import { formatBytes, formatCount } from '../lib/format'

// Everything Skopos knows about one name, and which devices asked for it.
//
// The name itself was observed on the wire — a DNS or mDNS answer, or a TLS
// server name — not looked up in reverse, which is why it is worth a page: it
// is what the device actually asked for.
export function DomainDetail({ onUnauthorized }: { onUnauthorized: () => void }) {
  const { name = '' } = useParams()
  const { range, setRange } = useUrlRange('24h', WINDOWS)
  const index = useDeviceIndex(onUnauthorized)

  const totals = useFetch<{ domains: DomainStat[] | null }>(`/api/domains?window=${apiWindow(range)}&limit=500`, {
    pollMs: 60000,
    onUnauthorized,
  })
  const search = useFetch<SearchResponse>(
    `/api/search?name=${encodeURIComponent(name)}&window=${apiWindow(range)}&limit=300`,
    { pollMs: 30000, onUnauthorized },
  )

  const stat = (totals.data?.domains ?? []).find((d) => d.name === name)
  const flows = search.data?.flows ?? []
  const truncated = search.data?.truncated ?? false

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--muted)' }}>
        <Link to="/traffic?lens=domains" className="hover:underline">
          Domains
        </Link>
        <span>/</span>
        <span className="min-w-0 truncate" style={{ color: 'var(--text)' }}>
          {name}
        </span>
      </div>

      <Card className="px-4 py-3.5">
        <PageTitle title={name}>a name your devices asked for, seen on the wire</PageTitle>
      </Card>

      <div className="flex flex-wrap items-center gap-2">
        <RangeControl range={range} setRange={setRange} allowed={WINDOWS} />
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
        <StatTile
          label="Volume"
          value={stat ? formatBytes(stat.bytes).split(' ')[0] : null}
          unit={stat ? formatBytes(stat.bytes).split(' ')[1] : undefined}
          tone={stat ? 'accent' : 'neutral'}
          unavailable={totals.loading ? 'still checking' : 'not in the top names for this window'}
          hint={stat ? `last ${range}` : undefined}
        />
        <StatTile
          label="Flows"
          value={stat ? formatCount(stat.flows) : null}
          unavailable={totals.loading ? 'still checking' : 'not measured for this name'}
          hint={stat ? `last ${range}` : undefined}
        />
        <StatTile
          label="Devices"
          value={stat ? formatCount(stat.devices) : null}
          unavailable={totals.loading ? 'still checking' : 'not measured for this name'}
          hint={stat ? 'asked for this name' : undefined}
        />
      </div>

      <Card>
        <CardHeader
          title="Flows"
          sub={`${range} · every conversation with this name attached`}
          right={truncated ? <Pill tone="warn">page limit reached — this is not the whole window</Pill> : undefined}
        />
        {search.loading && !search.data ? (
          <Spinner />
        ) : !search.data ? (
          <EmptyState>Could not search flows{search.error ? `: ${search.error}` : ''}.</EmptyState>
        ) : (
          <FlowTable rows={flows} index={index} empty={`No flows to ${name} in the last ${range}.`} />
        )}
      </Card>
    </div>
  )
}
