import { useMemo, useState } from 'react'
import { useFetch } from '../lib/useFetch'
import { api, bucketSeconds, type GeoIPSummary, type LiveFlow, type TimePoint, type Talker } from '../lib/api'
import { Card, CardHeader, Spinner, EmptyState } from '../components/ui'
import { ThroughputChart } from '../components/ThroughputChart'
import { TalkerBars } from '../components/TalkerBars'
import { CountryBars } from '../components/CountryBars'
import { TrafficWorldMap } from '../components/TrafficWorldMap'
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
  const [mapDir, setMapDir] = useState<'out' | 'in'>('out')
  const mapStats = mapDir === 'out' ? (geo.data?.out ?? []) : (geo.data?.in ?? [])

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
                <ThroughputChart
                  points={data.series}
                  bucketSeconds={bucketSeconds(data.resolution)}
                  height={280}
                />
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

          <Card>
            <CardHeader
              title="World map"
              sub={`${range.label} · ${mapDir === 'out' ? 'where your traffic goes' : 'who is knocking from outside'}`}
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

          <FlowSearch onUnauthorized={onUnauthorized} />

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

// FlowSearch answers "what actually happened at 3am" from the raw flow
// records the rollups have already summarised away.
function FlowSearch({ onUnauthorized }: { onUnauthorized: () => void }) {
  const [address, setAddress] = useState('')
  const [port, setPort] = useState('')
  const [name, setName] = useState('')
  const [win, setWin] = useState('24h')
  const [query, setQuery] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<{ flows: LiveFlow[] | null; count: number } | null>(null)
  const [err, setErr] = useState('')

  const run = async () => {
    setBusy(true)
    setErr('')
    const params = new URLSearchParams({ window: win, limit: '300' })
    if (address.trim()) params.set('address', address.trim())
    if (port.trim()) params.set('port', port.trim())
    if (name.trim()) params.set('name', name.trim())
    setQuery(params.toString())
    try {
      setResult(await api.get(`/api/search?${params.toString()}`))
    } catch (e) {
      if ((e as { status?: number }).status === 401) return onUnauthorized()
      setErr((e as Error).message)
      setResult(null)
    } finally {
      setBusy(false)
    }
  }

  const flows = result?.flows ?? []

  return (
    <Card>
      <CardHeader
        title="Search history"
        sub="the raw flow records — filter by address, port or domain, over a window"
      />
      <div className="flex flex-col gap-3 px-4 pb-4">
        <div className="flex flex-wrap items-end gap-2">
          <Field label="Address" value={address} onChange={setAddress} placeholder="192.168.1.20 or 10.0.0.0/8" width="w-52" />
          <Field label="Port" value={port} onChange={setPort} placeholder="443" width="w-24" />
          <Field label="Domain" value={name} onChange={setName} placeholder="youtube.com" width="w-44" />
          <label className="flex w-28 flex-col gap-1">
            <span className="font-mono text-[0.62rem] font-semibold uppercase tracking-[0.1em]" style={{ color: 'var(--muted)' }}>
              Window
            </span>
            <select
              value={win}
              onChange={(e) => setWin(e.target.value)}
              className="rounded-md border px-2.5 py-1.5 text-sm"
              style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text)' }}
            >
              {['1h', '24h', '168h', '720h'].map((w) => (
                <option key={w} value={w}>
                  {w}
                </option>
              ))}
            </select>
          </label>
          <button
            onClick={run}
            disabled={busy}
            className="rounded-md px-3 py-1.5 text-xs font-medium"
            style={{ background: 'var(--accent)', color: 'white' }}
          >
            {busy ? 'Searching…' : 'Search'}
          </button>
        </div>

        {err && <p className="text-xs" style={{ color: 'var(--crit)' }}>{err}</p>}

        {result && (
          <>
            <div className="flex items-center justify-between text-xs" style={{ color: 'var(--muted)' }}>
              <span>{result.count} flows</span>
              {query && (
                <a href={`/api/search?${query}`} target="_blank" rel="noreferrer" className="hover:underline">
                  open as JSON
                </a>
              )}
            </div>
            {flows.length === 0 ? (
              <EmptyState>Nothing matched.</EmptyState>
            ) : (
              <div className="max-h-96 overflow-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr style={{ color: 'var(--muted)' }}>
                      <th className="px-2 py-1 text-left font-mono text-[0.62rem] font-semibold uppercase tracking-[0.1em]">Time</th>
                      <th className="px-2 py-1 text-left font-mono text-[0.62rem] font-semibold uppercase tracking-[0.1em]">Source</th>
                      <th className="px-2 py-1 text-left font-mono text-[0.62rem] font-semibold uppercase tracking-[0.1em]">Destination</th>
                      <th className="px-2 py-1 text-right font-mono text-[0.62rem] font-semibold uppercase tracking-[0.1em]">Volume</th>
                    </tr>
                  </thead>
                  <tbody>
                    {flows.map((f, i) => (
                      <tr key={i} style={{ borderTop: '1px solid var(--border)' }}>
                        <td className="px-2 py-1 font-mono text-xs" style={{ color: 'var(--muted)' }}>
                          {new Date(f.start).toLocaleString(undefined, { hour12: false })}
                        </td>
                        <td className="px-2 py-1 font-mono text-xs">
                          {f.src}:{f.src_port}
                        </td>
                        <td className="px-2 py-1 text-xs">
                          {f.dst_name || <span className="font-mono">{f.dst}</span>}
                          <span className="font-mono" style={{ color: 'var(--muted)' }}>
                            :{f.dst_port}
                          </span>
                        </td>
                        <td className="px-2 py-1 text-right font-mono text-xs tabnums">{formatBytes(f.bytes)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>
    </Card>
  )
}

function Field({
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
      <span className="font-mono text-[0.62rem] font-semibold uppercase tracking-[0.1em]" style={{ color: 'var(--muted)' }}>
        {label}
      </span>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="rounded-md border px-2.5 py-1.5 font-mono text-sm"
        style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text)' }}
      />
    </label>
  )
}
