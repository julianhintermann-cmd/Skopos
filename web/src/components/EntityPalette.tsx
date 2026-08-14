import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { deviceName } from '../lib/api'
import { BottomSheet } from './mobile'
import { NAV } from './nav'
import { entityHref, useDeviceIndex, isCIDR, isIP, isMAC, isHostname, type DeviceIndex } from '../lib/links'
import { useIsMobile } from '../lib/useIsMobile'

// One search box for everything Skopos has a page for: an IP, a CIDR, a MAC, a
// domain, a device name or a page name.
//
// One component, two shells — a centred overlay on ⌘K, and the same thing
// inside the existing bottom sheet on a phone, where there is no ⌘K and a
// magnifier in the header opens it. No new primitive either way.
//
// It invents nothing: device matches come from the inventory that is already
// polled, a typed address routes straight to its dossier with no round trip,
// and when nothing matches it says so rather than offering a guess.

interface Result {
  group: 'Pages' | 'Devices' | 'Go to'
  label: string
  hint?: string
  href: string
}

export function EntityPalette({
  open,
  onClose,
  initialQuery = '',
  onUnauthorized,
}: {
  open: boolean
  onClose: () => void
  initialQuery?: string
  onUnauthorized?: () => void
}) {
  const isMobile = useIsMobile()
  const navigate = useNavigate()
  const index = useDeviceIndex(onUnauthorized)
  const [query, setQuery] = useState(initialQuery)
  const [cursor, setCursor] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!open) return
    setQuery(initialQuery)
    setCursor(0)
    // The sheet animates in; focusing on the next frame avoids the phone
    // keyboard fighting the transition.
    const id = setTimeout(() => inputRef.current?.focus(), 30)
    return () => clearTimeout(id)
  }, [open, initialQuery])

  const results = useMemo(() => resultsFor(query, index), [query, index])

  useEffect(() => {
    setCursor((c) => (c >= results.length ? 0 : c))
  }, [results.length])

  if (!open) return null

  const go = (r: Result | undefined) => {
    if (!r) return
    onClose()
    navigate(r.href)
  }

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.preventDefault()
      onClose()
    } else if (e.key === 'ArrowDown') {
      e.preventDefault()
      setCursor((c) => Math.min(c + 1, results.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setCursor((c) => Math.max(c - 1, 0))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      go(results[cursor])
    }
  }

  const body = (
    <div className="flex flex-col">
      <input
        ref={inputRef}
        value={query}
        onChange={(e) => {
          setQuery(e.target.value)
          setCursor(0)
        }}
        onKeyDown={onKeyDown}
        placeholder="IP, CIDR, MAC, domain, device or page"
        aria-label="Search Skopos"
        className="w-full border-b bg-transparent px-4 py-3 text-[15px] outline-none"
        style={{ borderColor: 'var(--border)', color: 'var(--text)' }}
      />
      {results.length === 0 ? (
        <p className="px-4 py-6 text-sm" style={{ color: 'var(--muted)' }}>
          {query.trim()
            ? `Nothing in Skopos matches “${query.trim()}”.`
            : 'Type an address, a name, or the name of a page.'}
        </p>
      ) : (
        <ul className="max-h-[60vh] overflow-y-auto py-1">
          {results.map((r, i) => (
            <li key={`${r.group}-${r.href}-${r.label}`}>
              {(i === 0 || results[i - 1].group !== r.group) && (
                <div
                  className="px-4 pb-1 pt-2 font-mono text-[0.58rem] font-semibold uppercase tracking-[0.18em]"
                  style={{ color: 'var(--muted)' }}
                >
                  {r.group}
                </div>
              )}
              <button
                type="button"
                onMouseEnter={() => setCursor(i)}
                onClick={() => go(r)}
                className="flex w-full items-baseline gap-2 px-4 py-2 text-left text-sm"
                style={i === cursor ? { background: 'var(--accent-tint)', color: 'var(--accent-strong)' } : undefined}
              >
                <span className="min-w-0 truncate font-medium">{r.label}</span>
                {r.hint && (
                  <span className="min-w-0 truncate font-mono text-xs" style={{ color: 'var(--muted)' }}>
                    {r.hint}
                  </span>
                )}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )

  if (isMobile) {
    return (
      <BottomSheet open={open} onClose={onClose} title="Search">
        {body}
      </BottomSheet>
    )
  }

  return (
    <div className="fixed inset-0 z-50" role="dialog" aria-modal="true" aria-label="Search Skopos">
      <div className="absolute inset-0" style={{ background: 'rgba(0,0,0,0.45)' }} onClick={onClose} aria-hidden />
      <div
        className="absolute left-1/2 top-24 w-[min(34rem,92vw)] -translate-x-1/2 overflow-hidden rounded-xl border"
        style={{ background: 'var(--surface)', borderColor: 'var(--border-strong)', boxShadow: '0 24px 60px rgba(0,0,0,0.35)' }}
      >
        {body}
      </div>
    </div>
  )
}

function resultsFor(raw: string, index: DeviceIndex): Result[] {
  const q = raw.trim()
  if (!q) return NAV.map((n) => ({ group: 'Pages' as const, label: n.label, href: n.to }))
  const lower = q.toLowerCase()
  const out: Result[] = []

  for (const n of NAV) {
    const hay = [n.label.toLowerCase(), n.to, ...(n.aliases ?? [])]
    if (hay.some((h) => h.includes(lower))) out.push({ group: 'Pages', label: n.label, hint: n.to, href: n.to })
  }

  const devices: Result[] = []
  for (const d of index.byMAC.values()) {
    const name = deviceName(d)
    const hay = [name, d.Label, d.Hostname, d.IP, d.IP6, d.MAC, d.Vendor].filter(Boolean).join(' ').toLowerCase()
    if (!hay.includes(lower)) continue
    devices.push({
      group: 'Devices',
      label: name || d.MAC,
      hint: [d.IP || d.IP6, d.Vendor].filter(Boolean).join(' · '),
      href: `/devices/${encodeURIComponent(d.MAC)}`,
    })
    if (devices.length >= 8) break
  }
  out.push(...devices)

  // A typed address or name always offers its own page, even when the
  // inventory has never seen it — that is what the dossier is for. It goes
  // through the same resolver as every link in the app, so typing the address
  // of a known device lands on the device rather than the dossier.
  const href = entityHref(q, index)
  if (href && !out.some((r) => r.href === href)) {
    out.push({
      group: 'Go to',
      label: q,
      hint: isMAC(q) ? 'device' : isIP(q) || isCIDR(q) ? 'address dossier' : isHostname(q) ? 'domain' : '',
      href,
    })
  }

  return out
}
