import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useFetch } from '../lib/useFetch'
import { api, deviceName, type Device } from '../lib/api'
import { Card, CardHeader, Spinner, EmptyState } from '../components/ui'
import { formatRelative } from '../lib/format'

export function Devices({ onUnauthorized, canWrite }: { onUnauthorized: () => void; canWrite: boolean }) {
  const { data, loading, error, refresh } = useFetch<{ devices: Device[] | null }>('/api/devices', {
    pollMs: 10000,
    onUnauthorized,
  })

  const devices = data?.devices ?? []
  const named = devices.filter((d) => d.Label).length

  return (
    <Card>
      <CardHeader
        title="Devices"
        sub={`${devices.length} seen on the network${named ? ` · ${named} named` : ''}`}
        right={
          <a
            href="/api/export/devices.csv"
            download
            className="rounded-md px-2.5 py-1 text-xs font-medium"
            style={{ background: 'var(--surface-2)', color: 'var(--muted)' }}
          >
            Export CSV
          </a>
        }
      />
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
                <Th>Name</Th>
                <Th>IP</Th>
                <Th>MAC</Th>
                <Th>Vendor</Th>
                <Th>First seen</Th>
                <Th>Last seen</Th>
                <Th> </Th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.ID} style={{ borderTop: '1px solid var(--border)' }}>
                  <Td>
                    <NameCell device={d} onSaved={refresh} onUnauthorized={onUnauthorized} />
                  </Td>
                  <Td mono>{d.IP}</Td>
                  <Td mono>{d.MAC}</Td>
                  <Td muted>{d.Vendor || '—'}</Td>
                  <Td muted>{formatRelative(d.FirstSeen)}</Td>
                  <Td muted>{formatRelative(d.LastSeen)}</Td>
                  <Td>
                    <div className="flex items-center justify-end gap-1">
                      {canWrite && <WakeButton mac={d.MAC} onUnauthorized={onUnauthorized} />}
                      <Link
                        to={`/devices/${encodeURIComponent(d.MAC)}`}
                        title="Device details"
                        aria-label="Device details"
                        className="rounded p-1"
                        style={{ color: 'var(--muted)' }}
                      >
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                          <path d="M9 18l6-6-6-6" />
                        </svg>
                      </Link>
                    </div>
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}

// WakeButton sends a Wake-on-LAN magic packet for the device and briefly
// confirms it. Fire-and-forget by nature: whether the machine actually wakes
// depends on its NIC and BIOS settings.
function WakeButton({ mac, onUnauthorized }: { mac: string; onUnauthorized: () => void }) {
  const [state, setState] = useState<'idle' | 'busy' | 'sent' | 'failed'>('idle')

  const wake = async () => {
    setState('busy')
    try {
      await api.post(`/api/devices/${encodeURIComponent(mac)}/wake`)
      setState('sent')
    } catch (e) {
      if ((e as { status?: number }).status === 401) return onUnauthorized()
      setState('failed')
    }
    setTimeout(() => setState('idle'), 2500)
  }

  if (state === 'sent') {
    return <span className="text-xs font-medium" style={{ color: 'var(--good)' }}>packet sent</span>
  }
  if (state === 'failed') {
    return <span className="text-xs font-medium" style={{ color: 'var(--crit)' }}>failed</span>
  }
  return (
    <IconButton label="Wake (Wake-on-LAN)" onClick={wake} disabled={state === 'busy'}>
      <path d="M12 2v10" />
      <path d="M18.4 6.6a9 9 0 1 1-12.77.04" />
    </IconButton>
  )
}

// NameCell shows a device's name and lets the operator rename it inline. The
// operator label wins over the discovered hostname; when a label is set the
// hostname is still shown beneath it, faintly, so nothing is hidden.
function NameCell({
  device,
  onSaved,
  onUnauthorized,
}: {
  device: Device
  onSaved: () => void
  onUnauthorized: () => void
}) {
  const [editing, setEditing] = useState(false)
  const [value, setValue] = useState(device.Label)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  const name = deviceName(device)

  const save = async () => {
    setBusy(true)
    setErr('')
    try {
      await api.post(`/api/devices/${encodeURIComponent(device.MAC)}/label`, { label: value.trim() })
      setEditing(false)
      onSaved()
    } catch (e) {
      const status = (e as { status?: number }).status
      if (status === 401) return onUnauthorized()
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const cancel = () => {
    setValue(device.Label)
    setErr('')
    setEditing(false)
  }

  if (editing) {
    return (
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-1.5">
          <input
            autoFocus
            value={value}
            disabled={busy}
            maxLength={64}
            placeholder={device.Hostname || 'device name'}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') save()
              if (e.key === 'Escape') cancel()
            }}
            className="w-44 rounded-md border px-2 py-1 text-sm outline-none"
            style={{ background: 'var(--surface-2)', borderColor: 'var(--border-strong)', color: 'var(--text)' }}
          />
          <IconButton label="Save" onClick={save} disabled={busy} tone="accent">
            <path d="M20 6L9 17l-5-5" />
          </IconButton>
          <IconButton label="Cancel" onClick={cancel} disabled={busy}>
            <path d="M18 6L6 18M6 6l12 12" />
          </IconButton>
        </div>
        {err && <span className="text-xs" style={{ color: 'var(--crit)' }}>{err}</span>}
      </div>
    )
  }

  return (
    <div className="group flex items-start gap-1.5">
      <div className="min-w-0">
        <div className="flex items-center gap-1.5">
          <Link
            to={`/devices/${encodeURIComponent(device.MAC)}`}
            className="hover:underline"
            style={name ? undefined : { color: 'var(--muted)' }}
          >
            {name || 'unknown'}
          </Link>
          {device.Label && (
            <span
              className="rounded-full px-1.5 py-0.5 font-mono text-[0.55rem] font-semibold uppercase tracking-wide"
              style={{ color: 'var(--accent-strong)', background: 'var(--accent-tint)' }}
            >
              named
            </span>
          )}
        </div>
        {device.Label && device.Hostname && (
          <div className="font-mono text-[0.7rem]" style={{ color: 'var(--muted)' }}>
            {device.Hostname}
          </div>
        )}
      </div>
      <IconButton
        label="Rename"
        onClick={() => {
          setValue(device.Label)
          setEditing(true)
        }}
        className="opacity-0 transition-opacity group-hover:opacity-100 focus:opacity-100"
      >
        <path d="M12 20h9" />
        <path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z" />
      </IconButton>
    </div>
  )
}

function IconButton({
  children,
  label,
  onClick,
  disabled,
  tone = 'neutral',
  className = '',
}: {
  children: React.ReactNode
  label: string
  onClick: () => void
  disabled?: boolean
  tone?: 'neutral' | 'accent'
  className?: string
}) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={onClick}
      disabled={disabled}
      className={`rounded p-1 transition-colors disabled:opacity-40 ${className}`}
      style={{ color: tone === 'accent' ? 'var(--accent-strong)' : 'var(--muted)' }}
    >
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
        {children}
      </svg>
    </button>
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
