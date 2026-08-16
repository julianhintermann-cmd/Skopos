import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom'
import { Logo } from './Logo'
import { ThemeToggle } from './ThemeToggle'
import { MORE, TABS, DotsIcon, SearchIcon } from './nav'
import { useDialogFocus } from './ui/dialog'
import { useStatus, toneColor } from '../lib/status'
import { t } from '../lib/i18n'
import type { Me } from '../lib/api'

// The phone experience: a compact header, a thumb-reach bottom tab bar for the
// four everyday views, and a hand-built bottom sheet for the rest. Every
// control here is custom — no native select, no desktop leftovers.

// --- BottomSheet -----------------------------------------------------------

// BottomSheet slides a panel up from the bottom edge — the phone-native
// pattern for menus and pickers. Backdrop tap closes; body scroll is locked
// while open; content scrolls internally above the home-indicator safe area.
//
// It says aria-modal="true", so it now behaves like one: focus is trapped,
// Escape closes it, focus returns to whatever opened it, and there is a
// visible Close button. None of that was true before, on the component that
// holds six of the ten navigation destinations plus Log out.
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
  const panel = useRef<HTMLDivElement>(null)
  useDialogFocus(panel, open, onClose)

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
        className="absolute inset-0 animate-appear"
        style={{ background: 'var(--sk-scrim)' }}
        onClick={onClose}
        aria-hidden
      />
      <div
        ref={panel}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="absolute inset-x-0 bottom-0 animate-rise rounded-t-2xl border-t outline-none"
        style={{
          background: 'var(--surface)',
          borderColor: 'var(--border)',
          paddingBottom: 'env(safe-area-inset-bottom)',
        }}
      >
        <div className="mx-auto mt-2 h-1 w-9 rounded-full" style={{ background: 'var(--border-strong)' }} aria-hidden />
        <div className="flex items-center justify-between gap-3 px-5 pb-1 pt-2">
          {title ? <div className="text-sm font-semibold tracking-tight">{title}</div> : <span />}
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="-mr-2 flex h-11 w-11 items-center justify-center rounded-md"
            style={{ color: 'var(--muted)' }}
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden>
              <path d="M18 6L6 18M6 6l12 12" />
            </svg>
          </button>
        </div>
        {/* dvh, not vh: on iOS Safari 70vh is 70% of the URL-bar-collapsed
            viewport, so the sheet was taller than the screen it sat in. */}
        <div className="max-h-[70dvh] overflow-y-auto pb-2">{children}</div>
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

// MobileShell is the phone chrome: sticky header, scrollable content, fixed
// bottom tab bar with a More sheet for the secondary views. The tab list comes
// from the shared nav model — Now · Traffic · Devices · Alerts · More — so the
// phone and the sidebar cannot drift apart again.
export function MobileShell({
  me,
  onLogout,
  banner,
  onSearch,
}: {
  me: Me | null
  onLogout: () => void
  banner?: ReactNode
  onSearch: () => void
}) {
  const [moreOpen, setMoreOpen] = useState(false)
  const location = useLocation()

  // Navigating always dismisses the sheet.
  useEffect(() => {
    setMoreOpen(false)
  }, [location.pathname])

  const inMore = MORE.some((i) => location.pathname.startsWith(i.to))

  return (
    // dvh: 100vh on iOS Safari is the URL-bar-collapsed viewport, so every
    // short page carried ~90px of phantom scroll at the bottom.
    <div className="flex min-h-dvh flex-col">
      <header
        className="sticky top-0 z-40 flex items-center justify-between gap-2 border-b px-4 py-2.5"
        style={{ background: 'var(--surface)', borderColor: 'var(--border)', paddingTop: 'max(0.625rem, env(safe-area-inset-top))' }}
      >
        <div className="flex items-center gap-2">
          <Logo size={22} />
          <span className="font-mono text-xs font-semibold uppercase tracking-[0.25em]">Skopos</span>
        </div>
        <div className="flex items-center gap-2.5">
          <StatusDots />
          <button
            type="button"
            onClick={onSearch}
            aria-label="Search Skopos"
            className="flex h-11 w-11 items-center justify-center rounded-md"
            style={{ color: 'var(--muted)' }}
          >
            <SearchIcon size={20} />
          </button>
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
          {TABS.map((tab) => (
            <NavLink
              key={tab.to}
              to={tab.to}
              end={tab.end}
              className="flex flex-col items-center gap-0.5 py-2"
              style={({ isActive }) => ({ color: isActive ? 'var(--accent-strong)' : 'var(--muted)' })}
            >
              <tab.icon size={20} />
              <span className="text-[0.62rem] font-medium">{tab.label}</span>
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
            <DotsIcon size={20} />
            <span className="text-[0.62rem] font-medium">More</span>
          </button>
        </div>
      </nav>

      <BottomSheet open={moreOpen} onClose={() => setMoreOpen(false)} title="More">
        {MORE.map((item) => (
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
            <item.icon size={20} />
            {item.label}
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

// --- status dots -----------------------------------------------------------

// The phone form of the status strip: three dots, and a sheet with the three
// full sentences. Colour alone is unreadable at 8 px and unavailable to a
// colour-blind reader, so the sheet — not the dot — is where the answer lives.
function StatusDots() {
  const { chips } = useStatus()
  const [open, setOpen] = useState(false)
  const worst =
    chips.find((c) => c.tone === 'crit') ?? chips.find((c) => c.tone === 'unknown') ?? chips.find((c) => c.tone === 'warn')
  // The dots poll; the label has to move with them or the phone header claims
  // a state that stopped being true four seconds ago. Named in words either
  // way — three coloured dots are not a status for anyone reading them.
  const label = worst
    ? worst.detail
    : chips.length === 0 || chips.some((c) => c.tone === 'loading')
      ? 'Skopos status — still checking'
      : `Skopos status — ${chips.map((c) => c.label).join(', ')}`

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        aria-label={label}
        aria-haspopup="dialog"
        className="flex h-11 items-center gap-1 rounded-full px-2"
        style={{ background: 'var(--surface-2)' }}
      >
        {chips.map((c) => (
          <span
            key={c.key}
            className="inline-block h-2 w-2 rounded-full"
            style={{
              background: c.tone === 'loading' ? 'var(--surface-3)' : toneColor(c.tone).fg,
              opacity: c.asOf ? 0.45 : 1,
            }}
          />
        ))}
      </button>
      <BottomSheet open={open} onClose={() => setOpen(false)} title="Status">
        {chips.map((c) => (
          <Link
            key={c.key}
            to={c.href}
            onClick={() => setOpen(false)}
            className="flex items-start gap-3 px-5 py-3.5 text-[15px]"
            style={{ borderTop: '1px solid var(--border)' }}
          >
            <span
              className="mt-1.5 inline-block h-2.5 w-2.5 shrink-0 rounded-full"
              style={{ background: c.tone === 'loading' ? 'var(--surface-3)' : toneColor(c.tone).fg }}
              aria-hidden
            />
            <span className="min-w-0">
              <span className="block font-medium">{c.tone === 'loading' ? 'Checking…' : c.label}</span>
              <span className="block text-xs" style={{ color: 'var(--muted)' }}>
                {c.detail}
                {c.asOf && ` Last successful reading at ${c.asOf}.`}
              </span>
            </span>
          </Link>
        ))}
      </BottomSheet>
    </>
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
function ChevronIcon() {
  return (
    <svg className="ml-auto" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--muted)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d="M9 18l6-6-6-6" />
    </svg>
  )
}
function LogoutIcon() { return icon(<><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><path d="M16 17l5-5-5-5M21 12H9" /></>) }
