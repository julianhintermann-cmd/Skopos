import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useFetch } from '../lib/useFetch'
import { api, deviceName, type DeviceDetail as Detail } from '../lib/api'
import { bucketSecondsOf } from '../lib/contracts'
import { Card, CardHeader, StatTile, Spinner, EmptyState, Pill, ScrollArea, useToast } from '../components/ui'
import { humanError } from '../components/humanError'
import { ThroughputChart } from '../components/ThroughputChart'
import { RangeControl } from '../components/RangeControl'
import { TalkerRows } from '../components/entity'
import { useDeviceIndex } from '../lib/links'
import { apiWindow, useUrlRange, WINDOWS } from '../lib/useUrlState'
import { Th, Td } from './Devices'
import { formatBytes, formatCount, formatRelative, formatTime } from '../lib/format'

export function DeviceDetail({ onUnauthorized, canWrite }: { onUnauthorized: () => void; canWrite?: boolean }) {
  const { mac = '' } = useParams()
  const { range, setRange } = useUrlRange('24h', WINDOWS)
  const index = useDeviceIndex(onUnauthorized)
  const { data, loading, error, refresh } = useFetch<Detail>(
    `/api/devices/${encodeURIComponent(mac)}/detail?window=${apiWindow(range)}`,
    { pollMs: 15000, onUnauthorized },
  )

  if (loading && !data) return <Spinner />
  if (error && !data) return <EmptyState>Could not load device: {error}</EmptyState>
  if (!data) return null

  const d = data.device
  const name = deviceName(d)
  const series = data.series ?? []
  const destinations = data.destinations ?? []
  const ports = data.ports ?? []
  const domains = data.domains ?? []
  const fingerprints = data.fingerprints ?? []
  // Only buckets that carry a number are summed. A down or nodata bucket has
  // null, and treating that as zero would fold "we were not looking" into the
  // total as if it were a quiet minute — the sum would read as a complete
  // figure while silently missing whatever happened during the outage.
  const total = series.reduce((sum, p) => sum + (p.bytes ?? 0), 0)
  const flows = series.reduce((sum, p) => sum + (p.flows ?? 0), 0)
  const unmeasured = series.filter((p) => p.bytes == null).length
  const partial = unmeasured > 0 ? ` · ${unmeasured} buckets not captured` : ''

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--muted)' }}>
        <Link to="/devices" className="inline-flex items-center hover:underline pointer-coarse:min-h-11 pointer-coarse:pr-1">
          Devices
        </Link>
        <span>/</span>
        <span style={{ color: 'var(--text)' }}>{name || d.MAC}</span>
      </div>

      <Card className="px-4 py-3.5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-semibold tracking-tight">{name || 'Unnamed device'}</h1>
              {d.Label && <Pill tone="accent">named</Pill>}
              {d.WatchPresence && <Pill tone={d.Present ? 'good' : 'neutral'}>{d.Present ? 'home' : 'away'}</Pill>}
              {d.Policy === 'lan_only' && <Pill tone="warn">LAN only</Pill>}
              {d.Policy === 'quarantine' && <Pill tone="crit">quarantined</Pill>}
            </div>
            <div className="mt-0.5 flex flex-wrap gap-x-4 gap-y-0.5 font-mono text-xs" style={{ color: 'var(--muted)' }}>
              {d.IP && <span>{d.IP}</span>}
              {d.IP6 && <span>{d.IP6}</span>}
              <span>{d.MAC}</span>
              {d.Vendor && <span>{d.Vendor}</span>}
              {d.Hostname && d.Label && <span>{d.Hostname}</span>}
            </div>
          </div>
          {/* Left-aligned until there is room to sit beside the identity block.
              At 390px this wrapped underneath and stayed right-aligned, leaving
              two lines pinned to the opposite edge from everything above them. */}
          <div className="text-xs sm:text-right" style={{ color: 'var(--muted)' }}>
            <div>first seen {formatRelative(d.FirstSeen)}</div>
            <div>last seen {formatRelative(d.LastSeen)}</div>
          </div>
        </div>
      </Card>

      <DevicePolicyCard mac={mac} policy={d.Policy ?? ''} canWrite={!!canWrite} onChange={refresh} />

      <div className="flex flex-wrap items-center gap-2">
        <RangeControl range={range} setRange={setRange} allowed={WINDOWS} label="Time window" />
        <span className="font-mono text-xs" style={{ color: 'var(--muted)' }}>
          resolution {data.resolution}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile
          label="Volume"
          value={formatBytes(total).split(' ')[0]}
          unit={formatBytes(total).split(' ')[1]}
          tone="accent"
          hint={`last ${range}${partial}`}
        />
        <StatTile label="Flows" value={formatCount(flows)} />
        <StatTile label="Destinations" value={formatCount(destinations.length)} hint="distinct peers" />
        <StatTile label="Ports" value={formatCount(ports.length)} hint="distinct services" />
      </div>

      <Card>
        <CardHeader title="Throughput" sub={`${range} · average bits per second`} />
        <div className="px-2 pb-2">
          {series.length > 0 ? (
            <ThroughputChart points={series} bucketSeconds={bucketSecondsOf(data)} height={240} />
          ) : (
            <EmptyState>No traffic from this device in the window.</EmptyState>
          )}
        </div>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Top destinations" sub="where this device talks to" />
          <div className="px-4 pb-4">
            {destinations.length > 0 ? (
              <TalkerRows talkers={destinations} index={index} />
            ) : (
              <EmptyState>No destinations recorded.</EmptyState>
            )}
          </div>
        </Card>

        <Card>
          <CardHeader title="Ports & protocols" sub="services this device used" />
          {ports.length > 0 ? (
            // Measured at 0px hidden at both 390 and 768, so ScrollArea says
            // nothing here today. That is the point of using it: it measures
            // instead of assuming, so a sixth column added later announces
            // itself rather than clipping in silence.
            <ScrollArea label="Ports and protocols" className="pb-2">
              <table className="w-full text-sm">
                <thead>
                  <tr style={{ color: 'var(--muted)' }}>
                    <Th>Port</Th>
                    <Th>Proto</Th>
                    <Th>Service</Th>
                    <Th>Volume</Th>
                    <Th>Flows</Th>
                  </tr>
                </thead>
                <tbody>
                  {ports.map((p) => (
                    <tr key={`${p.port}-${p.proto}`} style={{ borderTop: '1px solid var(--border)' }}>
                      <Td mono>{p.port}</Td>
                      <Td mono>{p.proto}</Td>
                      <Td muted>{serviceName(p.port, p.proto)}</Td>
                      <Td muted>{formatBytes(p.bytes)}</Td>
                      <Td muted>{formatCount(p.flows)}</Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </ScrollArea>
          ) : (
            <EmptyState>No port data recorded.</EmptyState>
          )}
        </Card>
      </div>

      {/* Both of these panels come from data the endpoint already sends on
          every 15-second poll and the view used to throw away. */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader
            title="Domains this device asked for"
            sub="learned from its DNS answers and TLS handshakes, not a reverse lookup"
          />
          <div className="px-4 pb-4">
            {domains.length === 0 ? (
              <EmptyState>No names observed for this device in the window.</EmptyState>
            ) : (
              <ul className="flex flex-col gap-1.5">
                {domains.map((dom) => (
                  <li className="flex items-baseline justify-between gap-3 text-sm pointer-coarse:min-h-11" key={dom.name}>
                    {/* break-all rather than truncate: the domain is the whole
                        point of the row, and a clipped one is only recoverable
                        by opening the page behind it. */}
                    <Link
                      to={`/domain/${encodeURIComponent(dom.name)}`}
                      className="min-w-0 break-all hover:underline"
                      style={{ color: 'var(--accent-strong)' }}
                    >
                      {dom.name}
                    </Link>
                    <span className="shrink-0 font-mono text-xs tabnums" style={{ color: 'var(--muted)' }}>
                      {formatBytes(dom.bytes)} · {formatCount(dom.flows)} flows
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Card>

        <Card>
          <CardHeader
            title="Client fingerprints"
            sub="JA4 — which TLS client software this device runs, from the handshakes on the wire"
          />
          <div className="px-4 pb-4">
            {fingerprints.length === 0 ? (
              <EmptyState>No TLS handshakes fingerprinted for this device.</EmptyState>
            ) : (
              <ul className="flex flex-col gap-1.5">
                {fingerprints.map((f) => (
                  <li key={f.ja4} className="flex items-baseline justify-between gap-3 text-sm">
                    {/* break-all, not truncate. A JA4 is 36 characters with no
                        detail page behind it, so a clipped one is simply gone
                        — there is nothing to tap to get the rest back. */}
                    <span className="min-w-0 break-all font-mono text-xs">{f.ja4}</span>
                    <span className="shrink-0 text-xs" style={{ color: 'var(--muted)' }}>
                      {formatCount(f.hits)} × · last {formatTime(f.last_seen)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Card>
      </div>
    </div>
  )
}

// serviceName labels well-known ports so the table reads at a glance.
const knownServices: Record<string, string> = {
  '53/udp': 'DNS', '53/tcp': 'DNS', '80/tcp': 'HTTP', '443/tcp': 'HTTPS', '443/udp': 'QUIC',
  '22/tcp': 'SSH', '25/tcp': 'SMTP', '123/udp': 'NTP', '143/tcp': 'IMAP', '993/tcp': 'IMAPS',
  '1883/tcp': 'MQTT', '3389/tcp': 'RDP', '5353/udp': 'mDNS', '445/tcp': 'SMB', '8686/tcp': 'Skopos',
}

function serviceName(port: number, proto: string): string {
  return knownServices[`${port}/${proto}`] ?? '—'
}

// DevicePolicyCard confines a device. The hint is deliberately explicit about
// reach: these rules live in the kernel of the machine running Skopos, so a
// device's own route to the internet through the router is only affected when
// that traffic actually passes this machine. Promising more would be a
// security feature that quietly does nothing.
function DevicePolicyCard({
  mac,
  policy,
  canWrite,
  onChange,
}: {
  mac: string
  policy: string
  canWrite: boolean
  onChange: () => void
}) {
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const toast = useToast()

  const set = async (next: string) => {
    setBusy(true)
    setErr('')
    try {
      await api.post(`/api/devices/${encodeURIComponent(mac)}/policy`, { policy: next })
      // Confining a device is the most consequential control on this page and
      // it confirmed nothing: the chip restyled itself and that was all.
      toast.show({
        message: next === '' ? 'Restriction lifted — this device is unrestricted again.' : `Policy applied: ${next === 'lan_only' ? 'LAN only' : 'quarantined'}.`,
        tone: 'ok',
      })
      onChange()
    } catch (e) {
      setErr(humanError(e))
    } finally {
      setBusy(false)
    }
  }

  const options = [
    { value: '', label: 'Unrestricted', hint: 'No per-device rule.' },
    { value: 'lan_only', label: 'LAN only', hint: 'Drop this device\'s traffic to and from the internet.' },
    { value: 'quarantine', label: 'Quarantine', hint: 'Drop all of this device\'s traffic, local included.' },
  ]

  return (
    <Card>
      <CardHeader
        title="Device policy"
        sub="what this device is allowed to reach — applied in the kernel, enforced only where traffic passes this machine"
      />
      <div className="flex flex-col gap-2 px-4 pb-4">
        {/* aria-pressed, because which policy is in force was carried by a
            background colour and nothing else — unavailable to a screen
            reader, and between "Unrestricted" and the two restricted chips it
            is the difference between a device being on the network and not. */}
        <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Device policy">
          {options.map((o) => (
            <button
              key={o.value}
              onClick={() => canWrite && set(o.value)}
              disabled={!canWrite || busy}
              aria-pressed={policy === o.value}
              title={o.hint}
              className="rounded-md px-3 py-1.5 text-xs font-medium pointer-coarse:min-h-11 pointer-coarse:px-4"
              style={
                policy === o.value
                  ? {
                      background: o.value === '' ? 'var(--surface-2)' : 'var(--crit-tint)',
                      color: o.value === '' ? 'var(--text)' : 'var(--crit)',
                    }
                  : { background: 'var(--surface-2)', color: 'var(--muted)' }
              }
            >
              {o.label}
            </button>
          ))}
        </div>
        <p className="text-xs" style={{ color: 'var(--muted)' }}>
          {options.find((o) => o.value === policy)?.hint}{' '}
          {policy !== '' &&
            'Traffic that never reaches this machine — a device going straight out through your router — cannot be stopped from here.'}
        </p>
        {err && <p role="alert" className="text-xs" style={{ color: 'var(--crit)' }}>{err}</p>}
      </div>
    </Card>
  )
}
