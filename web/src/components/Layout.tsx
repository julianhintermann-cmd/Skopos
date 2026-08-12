import { NavLink, Outlet } from 'react-router-dom'
import type { ReactNode } from 'react'
import { Logo } from './Logo'
import { ThemeToggle } from './ThemeToggle'
import { t } from '../lib/i18n'
import type { Me } from '../lib/api'

type NavItem = { to: string; key: Parameters<typeof t>[0]; icon: () => ReactNode; end?: boolean }

const sections: { title: Parameters<typeof t>[0]; items: NavItem[] }[] = [
  {
    title: 'section.monitor',
    items: [
      { to: '/', key: 'nav.overview', icon: PulseIcon, end: true },
      { to: '/live', key: 'nav.live', icon: BroadcastIcon },
      { to: '/traffic', key: 'nav.traffic', icon: WaveIcon },
      { to: '/devices', key: 'nav.devices', icon: GridIcon },
    ],
  },
  {
    title: 'section.protect',
    items: [
      { to: '/firewall', key: 'nav.firewall', icon: ShieldIcon },
      { to: '/alerts', key: 'nav.alerts', icon: BellIcon },
    ],
  },
  {
    title: 'section.manage',
    items: [
      { to: '/cloudflare', key: 'nav.cloudflare', icon: CloudIcon },
      { to: '/settings', key: 'nav.settings', icon: SlidersIcon },
      { to: '/system', key: 'nav.system', icon: GearIcon },
    ],
  },
]

const flatNav = sections.flatMap((s) => s.items)

export function Layout({ me, onLogout, banner }: { me: Me | null; onLogout: () => void; banner?: ReactNode }) {
  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <aside
        className="hidden w-56 shrink-0 flex-col border-r sm:flex"
        style={{ background: 'var(--surface)', borderColor: 'var(--border)' }}
      >
        <div className="flex items-center gap-2.5 px-5 py-4">
          <Logo size={26} />
          <div className="font-mono text-sm font-semibold uppercase tracking-[0.3em]">Skopos</div>
        </div>
        <nav className="flex flex-1 flex-col gap-3 overflow-y-auto px-3 py-2">
          {sections.map((section) => (
            <div key={section.title} className="flex flex-col gap-0.5">
              <div
                className="px-2.5 pb-1 pt-1 font-mono text-[0.58rem] font-semibold uppercase tracking-[0.18em]"
                style={{ color: 'var(--muted)' }}
              >
                {t(section.title)}
              </div>
              {section.items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  className="group flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm font-medium transition-colors"
                  style={({ isActive }) =>
                    isActive
                      ? { background: 'var(--accent-tint)', color: 'var(--accent-strong)' }
                      : { color: 'var(--muted)' }
                  }
                >
                  <item.icon />
                  {t(item.key)}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="px-4 py-3 text-xs" style={{ color: 'var(--muted)', borderTop: '1px solid var(--border)' }}>
          <div className="font-mono">σκοπός</div>
          <div>the watcher</div>
        </div>
      </aside>

      {/* Main */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header
          className="flex items-center justify-between gap-3 border-b px-4 py-2.5 sm:px-6"
          style={{ background: 'var(--surface)', borderColor: 'var(--border)' }}
        >
          <div className="flex items-center gap-2 sm:hidden">
            <Logo size={22} />
            <span className="font-mono text-xs font-semibold uppercase tracking-[0.25em]">Skopos</span>
          </div>
          <div className="hidden sm:block" />
          <div className="flex items-center gap-3">
            {me?.enforcing !== undefined && (
              <span
                className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium"
                style={
                  me.enforcing
                    ? { color: 'var(--good)', background: 'var(--good-tint)' }
                    : { color: 'var(--muted)', background: 'var(--surface-2)' }
                }
              >
                <span
                  className="inline-block h-1.5 w-1.5 rounded-full"
                  style={{ background: me.enforcing ? 'var(--good)' : 'var(--muted)' }}
                />
                {me.enforcing ? t('label.enforcing') : t('label.observing')}
              </span>
            )}
            <ThemeToggle />
            {me?.auth && (
              <button
                onClick={onLogout}
                className="rounded-md px-2 py-1 text-xs font-medium"
                style={{ color: 'var(--muted)' }}
              >
                {t('action.logout')}
              </button>
            )}
          </div>
        </header>

        {banner}

        {/* Mobile nav */}
        <nav
          className="flex gap-1 overflow-x-auto border-b px-2 py-1.5 sm:hidden"
          style={{ background: 'var(--surface)', borderColor: 'var(--border)' }}
        >
          {flatNav.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className="whitespace-nowrap rounded-md px-2.5 py-1 text-xs font-medium"
              style={({ isActive }) =>
                isActive
                  ? { background: 'var(--accent-tint)', color: 'var(--accent-strong)' }
                  : { color: 'var(--muted)' }
              }
            >
              {t(item.key)}
            </NavLink>
          ))}
        </nav>

        <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-5 sm:px-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}

// --- inline icons (stroke = currentColor) ---
function icon(path: ReactNode) {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      {path}
    </svg>
  )
}
function PulseIcon() { return icon(<polyline points="3 12 8 12 11 4 14 20 17 12 21 12" />) }
function BroadcastIcon() { return icon(<><circle cx="12" cy="12" r="2" /><path d="M7.8 7.8a6 6 0 0 0 0 8.4M16.2 16.2a6 6 0 0 0 0-8.4M5 5a10 10 0 0 0 0 14M19 19a10 10 0 0 0 0-14" /></>) }
function WaveIcon() { return icon(<><path d="M3 12c2-4 4-4 6 0s4 4 6 0 4-4 6 0" /></>) }
function GridIcon() { return icon(<><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></>) }
function ShieldIcon() { return icon(<path d="M12 3l7 3v5c0 4-3 7-7 8-4-1-7-4-7-8V6z" />) }
function BellIcon() { return icon(<><path d="M18 8a6 6 0 1 0-12 0c0 7-3 9-3 9h18s-3-2-3-9" /><path d="M13.7 21a2 2 0 0 1-3.4 0" /></>) }
function CloudIcon() { return icon(<path d="M17.5 18H7a4 4 0 0 1-.5-7.97A5 5 0 0 1 16 9.5a3.5 3.5 0 0 1 1.5 8.5z" />) }
function SlidersIcon() { return icon(<><path d="M4 6h11M18 6h2M4 12h2M9 12h11M4 18h11M18 18h2" /><circle cx="16" cy="6" r="2" /><circle cx="7" cy="12" r="2" /><circle cx="16" cy="18" r="2" /></>) }
function GearIcon() { return icon(<><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-2.7 1.1V21a2 2 0 1 1-4 0v-.1A1.6 1.6 0 0 0 7 19.4a1.6 1.6 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0-1.1-2.7H1a2 2 0 1 1 0-4h.1A1.6 1.6 0 0 0 2.6 7a1.6 1.6 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 1.8.3H7a1.6 1.6 0 0 0 1-1.5V1a2 2 0 1 1 4 0v.1a1.6 1.6 0 0 0 2.7 1.1 1.6 1.6 0 0 0 .3-1.8l-.1-.1" transform="scale(0.85) translate(2 2)" /></>) }
