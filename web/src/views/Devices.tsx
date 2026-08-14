import { useMemo, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useFetch } from '../lib/useFetch'
import { api, deviceName, randomizedMAC, type Device } from '../lib/api'
import { Card, Spinner, EmptyState, Button, IconButton, Modal, ScrollArea, useToast } from '../components/ui'
import { PageTitle } from '../components/PageTitle'
import { humanError } from '../components/humanError'
import { useIsMobile, useIsNarrow } from '../lib/useIsMobile'
import { useUrlState, useUrlText } from '../lib/useUrlState'
import { formatRelative } from '../lib/format'

// noiseThreshold is how many inventory entries have to share one address
// before the list calls them noise. One address means one machine; when
// several hardware addresses claim the same one, none of them is an identity.
const noiseThreshold = 3

// noiseMACs finds inventory entries that describe traffic rather than a
// device. Tunnels with synthetic hardware addresses, relays that re-frame
// other hosts' packets and NICs randomising their MAC each produce a fresh
// entry per sighting, so a single address can collect a dozen rows. Anything
// the operator has touched — named, restricted or watched — is never noise,
// whatever the traffic looks like.
function noiseMACs(devices: Device[]): Set<string> {
  const perAddress = new Map<string, Device[]>()
  for (const d of devices) {
    for (const addr of [d.IP, d.IP6]) {
      if (!addr) continue
      const group = perAddress.get(addr)
      if (group) group.push(d)
      else perAddress.set(addr, [d])
    }
  }
  const out = new Set<string>()
  for (const group of perAddress.values()) {
    if (group.length < noiseThreshold) continue
    for (const d of group) {
      if (!d.Label && !d.Policy && !d.WatchPresence) out.add(d.MAC)
    }
  }
  return out
}

function matches(d: Device, q: string): boolean {
  if (!q) return true
  const hay = [deviceName(d), d.Label, d.Hostname, d.IP, d.IP6, d.MAC, d.Vendor].join(' ').toLowerCase()
  return hay.includes(q.toLowerCase())
}

// A device's display name for a sentence or an accessible name, never blank.
// "Forget this entry" next to two other identical labels named nothing in
// particular; "Forget kitchen-pi" names the thing that is about to be deleted.
function label(d: Device): string {
  return deviceName(d) || d.IP || d.MAC
}

export function Devices({ onUnauthorized, canWrite }: { onUnauthorized: () => void; canWrite: boolean }) {
  const { data, loading, error, refresh } = useFetch<{ devices: Device[] | null }>('/api/devices', {
    pollMs: 10000,
    onUnauthorized,
  })
  // Both filters live in the URL: a filtered device list is a thing people
  // send each other, and Back should undo the filter rather than leave the
  // page with it still applied.
  const [queryDraft, setQueryDraft, query] = useUrlText('q')
  const [only, setOnly] = useUrlState('only', '', { valid: ['', 'noise'] as const, history: 'push' })
  const onlyNoise = only === 'noise'

  const devices = useMemo(() => data?.devices ?? [], [data])
  const noise = useMemo(() => noiseMACs(devices), [devices])
  const named = devices.filter((d) => d.Label).length
  // isMobile picks the shape of the confirmation; narrow picks the shape of
  // the list. They are different questions: a sheet is a phone answer, and a
  // table not fitting is an arithmetic one that an iPad shares with a small
  // laptop window.
  const isMobile = useIsMobile()
  const narrow = useIsNarrow()
  // Forget is hoisted to the view so its confirmation is not rendered inside a
  // table cell, where an inline panel would open hundreds of pixels away from
  // the row that was clicked.
  const [forgetting, setForgetting] = useState<Device | null>(null)

  const shown = devices.filter((d) => (onlyNoise ? noise.has(d.MAC) : true) && matches(d, query))

  return (
    <div className="flex flex-col gap-4">
      {/* The page had no h1 at any width: a screen reader arriving here found
          the list before it found out what the page was. The count re-polls
          every ten seconds, so it is announced rather than changed in silence. */}
      <PageTitle title="Devices">
        <span role="status">
          {devices.length} seen on the network
          {named ? ` · ${named} named` : ''}
        </span>
      </PageTitle>

      {forgetting && (
        <ForgetConfirm
          device={forgetting}
          isMobile={isMobile}
          onCancel={() => setForgetting(null)}
          onDone={() => {
            setForgetting(null)
            refresh()
          }}
          onUnauthorized={onUnauthorized}
        />
      )}

      <Card>
        <div className="flex flex-wrap items-center gap-2 px-4 pb-3 pt-3.5">
          {devices.length > 0 && (
            <>
              <input
                value={queryDraft}
                onChange={(e) => setQueryDraft(e.target.value)}
                placeholder="Search name, address, MAC…"
                aria-label="Search devices"
                className="min-w-0 flex-1 rounded-md border px-2.5 py-1.5 text-sm outline-none pointer-coarse:min-h-11 sm:max-w-xs"
                style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text)' }}
              />
              {(query || onlyNoise) && (
                <span role="status" className="text-xs" style={{ color: 'var(--muted)' }}>
                  {shown.length} of {devices.length}
                </span>
              )}
            </>
          )}
          <a
            href="/api/export/devices.csv"
            download
            className="ml-auto inline-flex items-center rounded-md px-2.5 py-1 text-xs font-medium pointer-coarse:min-h-11 pointer-coarse:px-3"
            style={{ background: 'var(--surface-2)', color: 'var(--muted)' }}
          >
            Export CSV
          </a>
        </div>

        {noise.size > 0 && canWrite && (
          <NoiseBanner
            macs={[...noise]}
            reviewing={onlyNoise}
            onReview={() => setOnly(onlyNoise ? '' : 'noise')}
            onDone={() => {
              setOnly('')
              refresh()
            }}
            onUnauthorized={onUnauthorized}
          />
        )}

        {loading && !data ? (
          <Spinner />
        ) : error ? (
          <EmptyState>Could not load devices: {error}</EmptyState>
        ) : devices.length === 0 ? (
          <EmptyState>No devices inventoried yet.</EmptyState>
        ) : shown.length === 0 ? (
          <EmptyState>Nothing matches “{query}”.</EmptyState>
        ) : narrow ? (
          // A real list, not a stack of divs. The desktop renders a <table>, so
          // a screen reader there is told how many devices exist and can move
          // between them; the phone rendering gave up both.
          <ul>
            {shown.map((d) => (
              <DeviceCard
                key={d.ID}
                device={d}
                noise={noise.has(d.MAC)}
                canWrite={canWrite}
                onChanged={refresh}
                onForget={() => setForgetting(d)}
                onUnauthorized={onUnauthorized}
              />
            ))}
          </ul>
        ) : (
          // Only rendered at 1280 and up, where the 994px table has 1006px to
          // sit in. ScrollArea is still the wrapper rather than a bare
          // overflow-x-auto: it measures, so a long vendor string or a browser
          // window dragged narrow gets named instead of clipped in silence.
          <ScrollArea label="Device list">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ color: 'var(--muted)' }}>
                  <Th>Name</Th>
                  <Th>Address</Th>
                  <Th>MAC</Th>
                  <Th>Vendor</Th>
                  <Th>First seen</Th>
                  <Th>Last seen</Th>
                  <Th>Actions</Th>
                </tr>
              </thead>
              <tbody>
                {shown.map((d) => (
                  <tr key={d.ID} style={{ borderTop: '1px solid var(--border)' }}>
                    <Td>
                      <NameCell device={d} onSaved={refresh} onUnauthorized={onUnauthorized} />
                    </Td>
                    <Td mono>
                      <AddressCell device={d} />
                    </Td>
                    <Td mono>
                      <div>{d.MAC}</div>
                      {randomizedMAC(d.MAC) && (
                        <div className="text-[0.62rem]" style={{ color: 'var(--muted)' }}>
                          randomized
                        </div>
                      )}
                    </Td>
                    <Td muted>{d.Vendor || '—'}</Td>
                    <Td muted>{formatRelative(d.FirstSeen)}</Td>
                    <Td muted>{formatRelative(d.LastSeen)}</Td>
                    <Td>
                      <div className="flex items-center justify-end gap-2">
                        {canWrite && <PresenceToggle device={d} onChanged={refresh} onUnauthorized={onUnauthorized} />}
                        {canWrite && <WakeButton device={d} onUnauthorized={onUnauthorized} />}
                        {canWrite && <ForgetButton device={d} onForget={() => setForgetting(d)} />}
                        <RowAction
                          as="link"
                          to={`/devices/${encodeURIComponent(d.MAC)}`}
                          label={`Details for ${label(d)}`}
                        >
                          <path d="M9 18l6-6-6-6" />
                        </RowAction>
                      </div>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </ScrollArea>
        )}
      </Card>
    </div>
  )
}

// AddressCell shows both of a device's addresses. The IPv4 one leads because
// it is the address an operator recognises; the IPv6 one sits underneath
// rather than replacing it, which is what used to happen whenever a device
// last spoke over IPv6.
function AddressCell({ device }: { device: Device }) {
  if (!device.IP && !device.IP6) return <span style={{ color: 'var(--muted)' }}>—</span>
  return (
    <div>
      {device.IP && <div>{device.IP}</div>}
      {device.IP6 && (
        <div className={device.IP ? 'text-[0.68rem]' : ''} style={device.IP ? { color: 'var(--muted)' } : undefined}>
          {device.IP6}
        </div>
      )}
    </div>
  )
}

// NoiseBanner offers the one-click cleanup for entries that never described a
// device. It names the count, lets the operator look at exactly which entries
// it means before agreeing, and says plainly that discovery is passive — a
// machine that is still on the network comes straight back.
function NoiseBanner({
  macs,
  reviewing,
  onReview,
  onDone,
  onUnauthorized,
}: {
  macs: string[]
  reviewing: boolean
  onReview: () => void
  onDone: () => void
  onUnauthorized: () => void
}) {
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  const forget = async () => {
    setBusy(true)
    setErr('')
    try {
      await api.post('/api/devices/forget', { macs })
      onDone()
    } catch (e) {
      if ((e as { status?: number }).status === 401) return onUnauthorized()
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mx-4 mb-3 rounded-lg border px-3 py-2.5" style={{ background: 'var(--warn-tint)', borderColor: 'var(--warn)' }}>
      <p className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
        {macs.length} {macs.length === 1 ? 'entry does' : 'entries do'} not look like a device
      </p>
      <p className="mt-0.5 text-sm" style={{ color: 'var(--muted)' }}>
        Several hardware addresses are claiming the same IP address. That happens with tunnels, relays and
        devices that randomise their MAC — each sighting became its own entry. Removing them is safe:
        discovery is passive, so anything still on the network reappears within seconds.
      </p>
      {err && <p role="alert" className="mt-1 text-xs" style={{ color: 'var(--crit)' }}>{err}</p>}
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <Button onClick={onReview} className="pointer-coarse:min-h-11">{reviewing ? 'Show all' : 'Review them'}</Button>
        <Button onClick={forget} disabled={busy} loading={busy} variant="danger" className="pointer-coarse:min-h-11">
          {busy ? 'Removing…' : `Remove ${macs.length}`}
        </Button>
      </div>
    </div>
  )
}

// ForgetButton opens the confirmation. It does not delete anything itself.
function ForgetButton({ device, onForget }: { device: Device; onForget: () => void }) {
  return (
    <RowAction label={`Forget ${label(device)}`} onClick={onForget} tone="crit">
      <path d="M3 6h18" />
      <path d="M8 6V4h8v2" />
      <path d="M19 6l-1 14H6L5 6" />
    </RowAction>
  )
}

// ForgetConfirm stands between a tap and a permanent deletion.
//
// Forget was the third of three identically sized grey icons, 23×23px and 4px
// apart, and it removed an inventory entry outright — no confirmation, and no
// message when the server refused. The reassuring half of the wording is
// NoiseBanner's because it is just as true here: discovery is passive.
function ForgetConfirm({
  device,
  isMobile,
  onCancel,
  onDone,
  onUnauthorized,
}: {
  device: Device
  isMobile: boolean
  onCancel: () => void
  onDone: () => void
  onUnauthorized: () => void
}) {
  const [busy, setBusy] = useState(false)
  const toast = useToast()
  const name = label(device)

  const forget = async () => {
    setBusy(true)
    try {
      await api.post('/api/devices/forget', { macs: [device.MAC] })
      toast.show({ message: `Forgot ${name}. It reappears if it is still on the network.`, tone: 'ok' })
      onDone()
    } catch (e) {
      if ((e as { status?: number }).status === 401) return onUnauthorized()
      // The old code swallowed this entirely, so a refused delete and a
      // successful one looked exactly alike.
      toast.show({ message: humanError(e), tone: 'crit', ttlMs: 9000 })
      onCancel()
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      open
      onClose={onCancel}
      title={`Forget ${name}?`}
      presentation={isMobile ? 'sheet' : 'overlay'}
      width="sm"
      footer={
        <>
          <Button onClick={onCancel} disabled={busy} className="pointer-coarse:min-h-11">
            Cancel
          </Button>
          <Button onClick={forget} variant="danger" disabled={busy} loading={busy} className="pointer-coarse:min-h-11">
            Forget it
          </Button>
        </>
      }
    >
      <p className="text-sm">
        This drops the inventory entry for <span className="font-mono">{device.MAC}</span>
        {device.IP ? <> at <span className="font-mono">{device.IP}</span></> : null}, along with its name, its
        presence watch and any per-device policy.
      </p>
      <p className="mt-2 text-sm" style={{ color: 'var(--muted)' }}>
        Discovery is passive, so if this device is still on the network it comes back as a new, unnamed entry
        within seconds. Traffic history already recorded against it is not deleted.
      </p>
    </Modal>
  )
}

// DeviceCard is the phone rendering of one device: identity block with the
// inline rename, meta lines, and a thumb-sized action row.
function DeviceCard({
  device,
  noise,
  canWrite,
  onChanged,
  onForget,
  onUnauthorized,
}: {
  device: Device
  noise: boolean
  canWrite: boolean
  onChanged: () => void
  onForget: () => void
  onUnauthorized: () => void
}) {
  return (
    <li className="px-4 py-3" style={{ borderTop: '1px solid var(--border)' }}>
      <div className="flex items-start justify-between gap-2">
        <NameCell device={device} onSaved={onChanged} onUnauthorized={onUnauthorized} />
        <Link
          to={`/devices/${encodeURIComponent(device.MAC)}`}
          aria-label={`Details for ${label(device)}`}
          className="flex shrink-0 items-center gap-0.5 rounded-md px-2 py-1 text-xs font-medium pointer-coarse:min-h-11 pointer-coarse:px-3"
          style={{ background: 'var(--surface-2)', color: 'var(--accent-strong)' }}
        >
          Details
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
            <path d="M9 18l6-6-6-6" />
          </svg>
        </Link>
      </div>
      <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 font-mono text-[0.7rem]" style={{ color: 'var(--muted)' }}>
        {device.IP && <span>{device.IP}</span>}
        {device.IP6 && <span>{device.IP6}</span>}
        <span>{device.MAC}</span>
        {randomizedMAC(device.MAC) && <span>randomized</span>}
        {device.Vendor && <span>{device.Vendor}</span>}
        <span>seen {formatRelative(device.LastSeen)}</span>
        {noise && <span style={{ color: 'var(--warn)' }}>shares its address</span>}
      </div>
      {canWrite && (
        // gap-2, not gap-1. Three 23px targets 4px apart, the third of which
        // deleted the entry, is a mis-tap waiting to happen.
        <div className="mt-2 flex items-center gap-2">
          <PresenceToggle device={device} onChanged={onChanged} onUnauthorized={onUnauthorized} />
          <WakeButton device={device} onUnauthorized={onUnauthorized} />
          <ForgetButton device={device} onForget={onForget} />
        </div>
      )}
    </li>
  )
}

// PresenceToggle turns arrive/leave notifications for a device on or off.
function PresenceToggle({
  device,
  onChanged,
  onUnauthorized,
}: {
  device: Device
  onChanged: () => void
  onUnauthorized: () => void
}) {
  const [busy, setBusy] = useState(false)
  const toast = useToast()
  const toggle = async () => {
    setBusy(true)
    try {
      await api.post(`/api/devices/${encodeURIComponent(device.MAC)}/presence`, { watch: !device.WatchPresence })
      onChanged()
    } catch (e) {
      if ((e as { status?: number }).status === 401) return onUnauthorized()
      toast.show({ message: humanError(e), tone: 'crit', ttlMs: 9000 })
    } finally {
      setBusy(false)
    }
  }
  return (
    <RowAction
      // The state is in the name, not only in the icon's colour and slash.
      label={
        device.WatchPresence
          ? `Presence alerts are on for ${label(device)} — turn them off`
          : `Notify me when ${label(device)} arrives or leaves`
      }
      onClick={toggle}
      disabled={busy}
      tone={device.WatchPresence ? 'accent' : 'neutral'}
    >
      <path d="M12 3a6 6 0 0 1 6 6c0 4 2 5.5 2 5.5H4S6 13 6 9a6 6 0 0 1 6-6z" />
      <path d="M10.3 20a2 2 0 0 0 3.4 0" />
      {!device.WatchPresence && <path d="M4 4l16 16" />}
    </RowAction>
  )
}

// WakeButton sends a Wake-on-LAN magic packet for the device. Fire-and-forget
// by nature: whether the machine actually wakes depends on its NIC and BIOS.
//
// The outcome used to replace this button with a <span> for 2.5 seconds. That
// unmounted the focused element in the middle of a row whose next control is
// Forget, dropping keyboard focus to <body>, and announced nothing at all. The
// button stays put; the toast is the live region that says what happened.
function WakeButton({ device, onUnauthorized }: { device: Device; onUnauthorized: () => void }) {
  const [busy, setBusy] = useState(false)
  const toast = useToast()

  const wake = async () => {
    setBusy(true)
    try {
      await api.post(`/api/devices/${encodeURIComponent(device.MAC)}/wake`)
      // Says what was observed — a packet left this machine — and not that the
      // device woke, which Skopos has no way to know.
      toast.show({ message: `Wake-on-LAN packet sent to ${label(device)}.`, tone: 'ok' })
    } catch (e) {
      if ((e as { status?: number }).status === 401) return onUnauthorized()
      toast.show({ message: humanError(e), tone: 'crit', ttlMs: 9000 })
    } finally {
      setBusy(false)
    }
  }

  return (
    <RowAction label={`Wake ${label(device)} (Wake-on-LAN)`} onClick={wake} disabled={busy}>
      <path d="M12 2v10" />
      <path d="M18.4 6.6a9 9 0 1 1-12.77.04" />
    </RowAction>
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
      setErr(humanError(e))
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
            aria-label={`Name for ${label(device)}`}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') save()
              if (e.key === 'Escape') cancel()
            }}
            className="w-44 rounded-md border px-2 py-1 text-sm outline-none pointer-coarse:min-h-11"
            style={{ background: 'var(--surface-2)', borderColor: 'var(--border-strong)', color: 'var(--text)' }}
          />
          <RowAction label="Save name" onClick={save} disabled={busy} tone="accent">
            <path d="M20 6L9 17l-5-5" />
          </RowAction>
          <RowAction label="Cancel rename" onClick={cancel} disabled={busy}>
            <path d="M18 6L6 18M6 6l12 12" />
          </RowAction>
        </div>
        {err && <span role="alert" className="text-xs" style={{ color: 'var(--crit)' }}>{err}</span>}
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
          {device.WatchPresence && (
            <span
              className="rounded-full px-1.5 py-0.5 font-mono text-[0.55rem] font-semibold uppercase tracking-wide"
              style={
                device.Present
                  ? { color: 'var(--good)', background: 'var(--good-tint)' }
                  : { color: 'var(--muted)', background: 'var(--surface-2)' }
              }
            >
              {device.Present ? 'home' : 'away'}
            </span>
          )}
        </div>
        {device.Label && device.Hostname && (
          <div className="font-mono text-[0.7rem]" style={{ color: 'var(--muted)' }}>
            {device.Hostname}
          </div>
        )}
      </div>
      <RowAction
        label={`Rename ${label(device)}`}
        onClick={() => {
          setValue(device.Label)
          setEditing(true)
        }}
        // Hover-to-reveal is a mouse idiom. A coarse pointer has no hover, so
        // the control was permanently invisible and permanently tappable.
        className="opacity-0 transition-opacity group-hover:opacity-100 focus:opacity-100 pointer-coarse:opacity-100"
      >
        <path d="M12 20h9" />
        <path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z" />
      </RowAction>
    </div>
  )
}

// RowAction is the shared IconButton sized for a thumb.
//
// The row's four controls measured 23×23px with 4px between them — below even
// WCAG 2.5.8's 24px floor, let alone the 44px both Apple's HIG and 2.5.5 ask
// for — and the third of them permanently deleted an inventory entry.
//
// 44px on a touch screen, where the mis-tap actually happens, and 24 — WCAG
// 2.5.8's floor, which 23 missed by a pixel — on a mouse. The mouse size is
// held down because these four cells set the width of the widest table in the
// app: at 44 throughout it grew from 990px to 1107 and began clipping even on
// a 1280px laptop, which would have traded a touch defect for a desktop one.
function RowAction({
  children,
  label: name,
  onClick,
  to,
  as = 'button',
  disabled,
  tone = 'neutral',
  className = '',
}: {
  children: ReactNode
  label: string
  onClick?: () => void
  to?: string
  as?: 'button' | 'link'
  disabled?: boolean
  tone?: 'neutral' | 'accent' | 'crit'
  className?: string
}) {
  const glyph = (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      {children}
    </svg>
  )

  if (as === 'link' && to) {
    return (
      <Link
        to={to}
        aria-label={name}
        title={name}
        className={`inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-md transition-colors pointer-coarse:h-11 pointer-coarse:w-11 ${className}`}
        style={{ color: 'var(--muted)' }}
      >
        {glyph}
      </Link>
    )
  }

  return (
    <IconButton
      label={name}
      onClick={onClick ?? (() => {})}
      disabled={disabled}
      tone={tone}
      size={14}
      className={`pointer-coarse:h-11 pointer-coarse:w-11 ${className}`}
    >
      {glyph}
    </IconButton>
  )
}

// Th and Td are imported by Firewall and System as well as by DeviceDetail, so
// they stay here and stay exported.
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
