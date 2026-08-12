import { useFetch } from '../lib/useFetch'
import type { Device } from '../lib/api'
import { Card, CardHeader, Spinner, EmptyState } from '../components/ui'
import { formatRelative } from '../lib/format'

export function Devices({ onUnauthorized }: { onUnauthorized: () => void }) {
  const { data, loading, error } = useFetch<{ devices: Device[] | null }>('/api/devices', {
    pollMs: 10000,
    onUnauthorized,
  })

  const devices = data?.devices ?? []

  return (
    <Card>
      <CardHeader title="Devices" sub={`${devices.length} seen on the network`} />
      {loading && !data ? (
        <Spinner />
      ) : error ? (
        <EmptyState>Could not load devices: {error}</EmptyState>
      ) : devices.length === 0 ? (
        <EmptyState>No devices inventoried yet.</EmptyState>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ color: 'var(--muted)' }}>
                <Th>Host</Th>
                <Th>IP</Th>
                <Th>MAC</Th>
                <Th>First seen</Th>
                <Th>Last seen</Th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.ID} style={{ borderTop: '1px solid var(--border)' }}>
                  <Td>{d.Hostname || <span style={{ color: 'var(--muted)' }}>unknown</span>}</Td>
                  <Td mono>{d.IP}</Td>
                  <Td mono>{d.MAC}</Td>
                  <Td muted>{formatRelative(d.FirstSeen)}</Td>
                  <Td muted>{formatRelative(d.LastSeen)}</Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}

export function Th({ children }: { children: React.ReactNode }) {
  return (
    <th className="px-4 py-2 text-left font-mono text-[0.62rem] font-semibold uppercase tracking-[0.1em]">
      {children}
    </th>
  )
}
export function Td({ children, mono, muted }: { children: React.ReactNode; mono?: boolean; muted?: boolean }) {
  return (
    <td
      className={`px-4 py-2 align-top ${mono ? 'font-mono text-xs' : ''}`}
      style={muted ? { color: 'var(--muted)' } : undefined}
    >
      {children}
    </td>
  )
}
