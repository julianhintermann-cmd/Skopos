import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api, type LiveFlow, type LiveStats } from '../lib/api'
import { useSSE } from '../lib/sse'
import { Card, CardHeader, StatTile, Pill, TextInput } from '../components/ui'
import { Sparkline } from '../components/Sparkline'
import { useDeviceNames } from '../lib/deviceNames'
import { formatBits, formatBytes, formatPPS, formatCount } from '../lib/format'

const MAX_ROWS = 200
const MAX_SPARK = 120 // ~2 minutes at 1 Hz

interface Row extends LiveFlow {
  _id: number
  _fresh: boolean
}

export function Live({ onUnauthorized }: { onUnauthorized: () => void }) {
  const [live, setLive] = useState<LiveStats | null>(null)
  const [spark, setSpark] = useState<number[]>([])
  const [rows, setRows] = useState<Row[]>([])
  const [connected, setConnected] = useState(false)
  const [filter, setFilter] = useState('')
  const [paused, setPaused] = useState(false)
  const [bufferedCount, setBufferedCount] = useState(0)
  const idRef = useRef(0)
  const pausedRef = useRef(false)
  const bufferRef = useRef<Row[]>([])
  const names = useDeviceNames(onUnauthorized)

  // Initial back-fill so the table isn't empty while waiting for the next flush.
  useEffect(() => {
    let stop = false
    api
      .get<{ flows: LiveFlow[] | null }>('/api/live/flows')
      .then(({ flows }) => {
        if (stop || !flows?.length) return
        setRows(flows.slice(0, MAX_ROWS).map((f) => ({ ...f, _id: idRef.current++, _fresh: false })))
      })
      .catch((e) => {
        if ((e as { status?: number }).status === 401) onUnauthorized()
      })
    return () => {
      stop = true
    }
  }, [onUnauthorized])

  const onEvent = useCallback((type: string, data: unknown) => {
    if (type === 'live') {
      const s = data as LiveStats
      setLive(s)
      setSpark((prev) => [...prev, s.bits_per_second].slice(-MAX_SPARK))
    } else if (type === 'flows') {
      const batch = data as LiveFlow[]
      if (!batch?.length) return
      const sorted = [...batch].sort((a, b) => +new Date(b.end) - +new Date(a.end))
      const fresh = sorted.map((f) => ({ ...f, _id: idRef.current++, _fresh: true }))
      if (pausedRef.current) {
        // While paused, hold new flows aside so the table stays still; they
        // are merged (and counted on the button) when the user resumes.
        bufferRef.current = [...fresh, ...bufferRef.current].slice(0, MAX_ROWS)
        setBufferedCount(bufferRef.current.length)
        return
      }
      setRows((prev) => [...fresh, ...prev.map((r) => ({ ...r, _fresh: false }))].slice(0, MAX_ROWS))
    }
  }, [])

  useSSE(onEvent, setConnected)

  const togglePause = () => {
    if (paused) {
      const buffered = bufferRef.current
      bufferRef.current = []
      setBufferedCount(0)
      setRows((prev) => [...buffered, ...prev.map((r) => ({ ...r, _fresh: false }))].slice(0, MAX_ROWS))
    }
    pausedRef.current = !paused
    setPaused(!paused)
  }

  // The filter matches addresses, resolved device names, DNS names, ports,
  // protocol and direction — one box instead of a form.
  const visible = useMemo(() => {
    const q = filter.trim().toLowerCase()
    if (!q) return rows
    return rows.filter((r) => {
      const hay = [
        r.src, r.dst, r.dst_name ?? '',
        names.get(r.src) ?? '', names.get(r.dst) ?? '',
        String(r.src_port), String(r.dst_port),
        r.proto, r.dir, dirMeta[r.dir]?.label ?? '',
      ]
      return hay.some((h) => h.toLowerCase().includes(q))
    })
  }, [rows, filter, names])

  const bits = formatBits(live?.bits_per_second ?? 0)

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile label="Throughput" value={bits.split(' ')[0]} unit={bits.split(' ')[1]} tone="accent" />
        <StatTile label="Packets" value={formatPPS(live?.packets_per_second ?? 0).split(' ')[0]} unit="pkt/s" />
        <StatTile label="Live flows" value={formatCount(rows.length)} hint="in view" />
        <StatTile
          label="Capture"
          value={live?.sampling ? 'Sampling' : 'Full'}
          tone={live?.sampling ? 'warn' : 'good'}
          hint={live?.sampling ? `${formatCount(live.observed_pps)} pkt/s observed` : 'every packet'}
        />
      </div>

      <Card>
        <CardHeader
          title="Live throughput"
          sub="bits per second · updated every second"
          right={<LiveDot connected={connected} />}
        />
        <div className="px-3 pb-3">
          {spark.length > 1 ? (
            <Sparkline values={spark} />
          ) : (
            <div className="flex h-24 items-center justify-center text-sm" style={{ color: 'var(--muted)' }}>
              Waiting for the first reading…
            </div>
          )}
        </div>
      </Card>

      <Card>
        <CardHeader
          title="Traffic feed"
          sub="every conversation as it completes"
          right={
            <div className="flex items-center gap-2">
              <div className="w-48">
                <TextInput
                  value={filter}
                  onChange={setFilter}
                  placeholder="Filter: device, IP, port, proto…"
                  className="!px-2.5 !py-1 !text-xs"
                />
              </div>
              <button
                type="button"
                onClick={togglePause}
                className="rounded-md px-2.5 py-1 text-xs font-medium"
                style={
                  paused
                    ? { background: 'var(--warn-tint)', color: 'var(--warn)' }
                    : { background: 'var(--surface-2)', color: 'var(--muted)' }
                }
              >
                {paused ? `Resume${bufferedCount ? ` (+${bufferedCount})` : ''}` : 'Pause'}
              </button>
              <Pill tone="neutral">{formatCount(visible.length)} shown</Pill>
            </div>
          }
        />
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ color: 'var(--muted)' }}>
                <Hd>Time</Hd>
                <Hd>Source</Hd>
                <Hd>Destination</Hd>
                <Hd>Proto</Hd>
                <Hd right>Volume</Hd>
                <Hd right>Packets</Hd>
                <Hd>Direction</Hd>
              </tr>
            </thead>
            <tbody>
              {visible.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-10 text-center text-sm" style={{ color: 'var(--muted)' }}>
                    {rows.length > 0
                      ? 'No flows match the filter.'
                      : connected
                        ? 'Listening for traffic…'
                        : 'Connecting to the live stream…'}
                  </td>
                </tr>
              ) : (
                visible.map((r) => <FlowRow key={r._id} row={r} names={names} />)
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}

function FlowRow({ row, names }: { row: Row; names: Map<string, string> }) {
  const src = names.get(row.src)
  const dst = row.dst_name || names.get(row.dst)
  return (
    <tr
      style={{
        borderTop: '1px solid var(--border)',
        background: row._fresh ? 'var(--accent-tint)' : undefined,
        transition: 'background 1.2s ease-out',
      }}
    >
      <Cell muted>{clock(row.end)}</Cell>
      <Cell>
        <Endpoint name={src} addr={row.src} port={row.src_port} />
      </Cell>
      <Cell>
        <Endpoint name={dst} addr={row.dst} port={row.dst_port} />
      </Cell>
      <Cell mono>{row.proto}</Cell>
      <Cell right>{formatBytes(row.bytes)}</Cell>
      <Cell right muted>{formatCount(row.packets)}</Cell>
      <Cell>
        <DirectionBadge dir={row.dir} />
      </Cell>
    </tr>
  )
}

function Endpoint({ name, addr, port }: { name?: string; addr: string; port: number }) {
  return (
    <div className="min-w-0">
      <div className="truncate">
        {name ? <span>{name}</span> : <span className="font-mono text-xs">{addr}</span>}
        {port > 0 && <span className="font-mono text-xs" style={{ color: 'var(--muted)' }}>:{port}</span>}
      </div>
      {name && <div className="font-mono text-[0.7rem]" style={{ color: 'var(--muted)' }}>{addr}</div>}
    </div>
  )
}

const dirMeta: Record<string, { label: string; tone: 'neutral' | 'accent' | 'good' | 'warn' }> = {
  lan_wan: { label: 'Outbound', tone: 'accent' },
  wan_lan: { label: 'Inbound', tone: 'warn' },
  lan_lan: { label: 'Internal', tone: 'neutral' },
  wan_wan: { label: 'Transit', tone: 'neutral' },
}

function DirectionBadge({ dir }: { dir: string }) {
  const m = dirMeta[dir] ?? { label: dir, tone: 'neutral' as const }
  return <Pill tone={m.tone}>{m.label}</Pill>
}

function LiveDot({ connected }: { connected: boolean }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium" style={{ color: connected ? 'var(--good)' : 'var(--muted)' }}>
      <span
        className="inline-block h-2 w-2 rounded-full"
        style={{ background: connected ? 'var(--good)' : 'var(--muted)', animation: connected ? 'skopos-pulse 2s ease-in-out infinite' : undefined }}
      />
      {connected ? 'Live' : 'Reconnecting'}
    </span>
  )
}

function Hd({ children, right }: { children: React.ReactNode; right?: boolean }) {
  return (
    <th className={`px-4 py-2 font-mono text-[0.62rem] font-semibold uppercase tracking-[0.1em] ${right ? 'text-right' : 'text-left'}`}>
      {children}
    </th>
  )
}
function Cell({ children, mono, muted, right }: { children: React.ReactNode; mono?: boolean; muted?: boolean; right?: boolean }) {
  return (
    <td
      className={`px-4 py-1.5 align-top ${mono ? 'font-mono text-xs' : ''} ${right ? 'text-right tabnums' : ''}`}
      style={muted ? { color: 'var(--muted)' } : undefined}
    >
      {children}
    </td>
  )
}

function clock(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
}
