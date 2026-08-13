import { useEffect, useState, type ReactNode } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { Logo } from './Logo'
import { ThemeToggle } from './ThemeToggle'
import { t } from '../lib/i18n'
import type { Me } from '../lib/api'

// The phone experience: a compact header, a thumb-reach bottom tab bar for the
// four everyday views, and a hand-built bottom sheet for the rest. Every
// control here is custom — no native select, no desktop leftovers.

// --- BottomSheet -----------------------------------------------------------

// BottomSheet slides a panel up from the bottom edge — the phone-native
// pattern for menus and pickers. Backdrop tap closes; body scroll is locked
// while open; content scrolls internally above the home-indicator safe area.
export function BottomSheet({
  open,
  onClose,
  title,
  children,
}: {
  open: boolean
  onClose: () => void
  title?: string
  children: ReactNode
}) {
  useEffect(() => {
    if (!open) return
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.body.style.overflow = prev
    }
  }, [open])

  if (!open) return null
  return (
    <div className="fixed inset-0 z-50">
      <div
        className="absolute inset-0"
        style={{ background: 'rgba(0,0,0,0.55)', animation: 'skopos-fade-in 0.18s ease-out' }}
        onClick={onClose}
        aria-hidden
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="absolute inset-x-0 bottom-0 rounded-t-2xl border-t"
        style={{
          background: 'var(--surface)',
          borderColor: 'var(--border)',
          animation: 'skopos-slide-up 0.22s ease-out',
          paddingBottom: 'env(safe-area-inset-bottom)',
        }}
      >
        <div className="mx-auto mt-2 h-1 w-9 rounded-full" style={{ background: 'var(--border-strong)' }} aria-hidden />
        {title && (
          <div className="px-5 pb-1 pt-3 text-sm font-semibold tracking-tight">{title}</div>
        )}
        <div className="max-h-[70vh] overflow-y-auto pb-2">{children}</div>
      </div>
    </div>
  )
}

// --- SheetSelect -----------------------------------------------------------

export interface SheetOption<T extends string> {
  value: T
  label: string
  hint?: string
}

// SheetSelect is the custom replacement for a dropdown: a chip showing the
// current choice that opens a bottom sheet of large, tappable options.
export function SheetSelect<T extends string>({
  value,
  options,
  onChange,
  label,
}: {
  value: T
  options: SheetOption<T>[]
  onChange: (v: T) => void
  label?: string
}) {
  const [open, setOpen] = useState(false)
  const current = options.find((o) => o.value === value)
  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium"
        style={{ background: 'var(--surface-2)', color: 'var(--text)' }}
      >
        {current?.label ?? value}
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
          <path d="M6 9l6 6 6-6" />
        </svg>
      </button>
      <BottomSheet open={open} onClose={() => setOpen(false)} title={label}>
        {options.map((o) => (
          <button
            key={o.value}
            type="button"
            onClick={() => {
              onChange(o.value)
              setOpen(false)
            }}
            className="flex w-full items-center justify-between px-5 py-3.5 text-left text-[15px]"
            style={{ borderTop: '1px solid var(--border)' }}
          >
            <span>
              {o.label}
              {o.hint && (
                <span className="block text-xs" style={{ color: 'var(--muted)' }}>
                  {o.hint}
                </span>
              )}
            </span>
            {o.value === value && (
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-strong)" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                <path d="M20 6L9 17l-5-5" />
              </svg>
            )}
          </button>
        ))}
      </BottomSheet>
    </>
  )
}

// --- MobileShell -----------------------------------------------------------

const tabs = [
  { to: '/', key: 'nav.overview' as const, icon: PulseIcon, end: true },
  { to: '/live', key: 'nav.live' as const, icon: BroadcastIcon },
  { to: '/devices', key: 'nav.devices' as const, icon: GridIcon },
  { to: '/alerts', key: 'nav.alerts' as const, icon: BellIcon },
]

const moreItems = [
  { to: '/traffic', key: 'nav.traffic' as const, icon: WaveIcon },
  { to: '/domains', key: 'nav.domains' as const, icon: GlobeIcon },
  { to: '/firewall', key: 'nav.firewall' as const, icon: ShieldIcon },
  { to: '/cloudflare', key: 'nav.cloudflare' as const, icon: CloudIcon },
  { to: '/settings', key: 'nav.settings' as const, icon: SlidersIcon },
  { to: '/system', key: 'nav.system' as const, icon: GearIcon },
]

// MobileShell is the phone chrome: sticky header, scrollable content, fixed
// bottom tab bar with a More sheet for the secondary views.
export function MobileShell({ me, onLogout, banner }: { me: Me | null; onLogout: () => void; banner?: ReactNode }) {
  const [moreOpen, setMoreOpen] = useState(false)
  const location = useLocation()

  // Navigating always dismisses the sheet.
  useEffect(() => {
    setMoreOpen(false)
  }, [location.pathname])

  const inMore = moreItems.some((i) => location.pathname.startsWith(i.to))

  return (
    <div className="flex min-h-screen flex-col">
      <header
        className="sticky top-0 z-40 flex items-center justify-between gap-2 border-b px-4 py-2.5"
        style={{ background: 'var(--surface)', borderColor: 'var(--border)', paddingTop: 'max(0.625rem, env(safe-area-inset-top))' }}
      >
        <div className="flex items-center gap-2">
          <Logo size={22} />
          <span className="font-mono text-xs font-semibold uppercase tracking-[0.25em]">Skopos</span>
        </div>
        <div className="flex items-center gap-2.5">
          {me?.enforcing !== undefined && (
            <span
              className="inline-block h-2 w-2 rounded-full"
              title={me.enforcing ? t('label.enforcing') : t('label.observing')}
              style={{ background: me.enforcing ? 'var(--good)' : 'var(--muted)' }}
            />
          )}
          <ThemeToggle />
        </div>
      </header>

      {banner}

      <main className="min-w-0 flex-1 px-3 py-3" style={{ paddingBottom: 'calc(4.5rem + env(safe-area-inset-bottom))' }}>
        <Outlet />
      </main>

      {/* Bottom tab bar — the thumb's home row. */}
      <nav
        className="fixed inset-x-0 bottom-0 z-40 border-t"
        style={{
          background: 'var(--surface)',
          borderColor: 'var(--border)',
          paddingBottom: 'env(safe-area-inset-bottom)',
        }}
        aria-label="Primary"
      >
        <div className="grid grid-cols-5">
          {tabs.map((tab) => (
            <NavLink
              key={tab.to}
              to={tab.to}
              end={tab.end}
              className="flex flex-col items-center gap-0.5 py-2"
              style={({ isActive }) => ({ color: isActive ? 'var(--accent-strong)' : 'var(--muted)' })}
            >
              <tab.icon />
              <span className="text-[0.62rem] font-medium">{t(tab.key)}</span>
            </NavLink>
          ))}
          <button
            type="button"
            onClick={() => setMoreOpen(true)}
            className="flex flex-col items-center gap-0.5 py-2"
            style={{ color: inMore ? 'var(--accent-strong)' : 'var(--muted)' }}
            aria-haspopup="dialog"
            aria-expanded={moreOpen}
          >
            <DotsIcon />
            <span className="text-[0.62rem] font-medium">More</span>
          </button>
        </div>
      </nav>

      <BottomSheet open={moreOpen} onClose={() => setMoreOpen(false)} title="More">
        {moreItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className="flex items-center gap-3 px-5 py-3.5 text-[15px] font-medium"
            style={({ isActive }) => ({
              borderTop: '1px solid var(--border)',
              color: isActive ? 'var(--accent-strong)' : 'var(--text)',
              background: isActive ? 'var(--accent-tint)' : undefined,
            })}
          >
            <item.icon />
            {t(item.key)}
            <ChevronIcon />
          </NavLink>
        ))}
        {me?.auth && (
          <button
            type="button"
            onClick={onLogout}
            className="flex w-full items-center gap-3 px-5 py-3.5 text-left text-[15px] font-medium"
            style={{ borderTop: '1px solid var(--border)', color: 'var(--crit)' }}
          >
            <LogoutIcon />
            {t('action.logout')}
          </button>
        )}
      </BottomSheet>
    </div>
  )
}

// --- icons (stroke = currentColor) ----------------------------------------

function icon(path: ReactNode, size = 20) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      {path}
    </svg>
  )
}
function PulseIcon() { return icon(<polyline points="3 12 8 12 11 4 14 20 17 12 21 12" />) }
function BroadcastIcon() { return icon(<><circle cx="12" cy="12" r="2" /><path d="M7.8 7.8a6 6 0 0 0 0 8.4M16.2 16.2a6 6 0 0 0 0-8.4M5 5a10 10 0 0 0 0 14M19 19a10 10 0 0 0 0-14" /></>) }
function WaveIcon() { return icon(<path d="M3 12c2-4 4-4 6 0s4 4 6 0 4-4 6 0" />) }
function GlobeIcon() { return icon(<><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c2.5 2.6 2.5 15.4 0 18M12 3c-2.5 2.6-2.5 15.4 0 18" /></>) }
function GridIcon() { return icon(<><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></>) }
function ShieldIcon() { return icon(<path d="M12 3l7 3v5c0 4-3 7-7 8-4-1-7-4-7-8V6z" />) }
function BellIcon() { return icon(<><path d="M18 8a6 6 0 1 0-12 0c0 7-3 9-3 9h18s-3-2-3-9" /><path d="M13.7 21a2 2 0 0 1-3.4 0" /></>) }
function CloudIcon() { return icon(<path d="M17.5 18H7a4 4 0 0 1-.5-7.97A5 5 0 0 1 16 9.5a3.5 3.5 0 0 1 1.5 8.5z" />) }
function SlidersIcon() { return icon(<><path d="M4 6h11M18 6h2M4 12h2M9 12h11M4 18h11M18 18h2" /><circle cx="16" cy="6" r="2" /><circle cx="7" cy="12" r="2" /><circle cx="16" cy="18" r="2" /></>) }
function GearIcon() { return icon(<><circle cx="12" cy="12" r="3" /><path d="M12 2v3M12 19v3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M2 12h3M19 12h3M4.9 19.1L7 17M17 7l2.1-2.1" /></>) }
function DotsIcon() { return icon(<><circle cx="5" cy="12" r="1.6" /><circle cx="12" cy="12" r="1.6" /><circle cx="19" cy="12" r="1.6" /></>) }
function ChevronIcon() {
  return (
    <svg className="ml-auto" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--muted)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d="M9 18l6-6-6-6" />
    </svg>
  )
}
function LogoutIcon() { return icon(<><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><path d="M16 17l5-5-5-5M21 12H9" /></>) }
