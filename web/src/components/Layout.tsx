import { useCallback, useState, type ReactNode } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { Logo } from './Logo'
import { ThemeToggle } from './ThemeToggle'
import { MobileShell } from './mobile'
import { StatusStrip } from './StatusStrip'
import { EntityPalette } from './EntityPalette'
import { NAV, SECTIONS, SearchIcon } from './nav'
import { useIsMobile } from '../lib/useIsMobile'
import { StatusContext, useStatusValue } from '../lib/status'
import { CHORDS, useShortcuts } from '../lib/shortcuts'
import { t } from '../lib/i18n'
import type { Me } from '../lib/api'

export function Layout({
  me,
  onLogout,
  onUnauthorized,
  banner,
}: {
  me: Me | null
  onLogout: () => void
  onUnauthorized?: () => void
  banner?: ReactNode
}) {
  const isMobile = useIsMobile()
  // The strip and Now's verdict read the same three answers, so the shell does
  // the polling once and publishes it.
  const status = useStatusValue(onUnauthorized)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [helpOpen, setHelpOpen] = useState(false)
  const openPalette = useCallback(() => setPaletteOpen(true), [])
  const toggleHelp = useCallback(() => setHelpOpen((v) => !v), [])
  useShortcuts({ onPalette: openPalette, onHelp: toggleHelp })

  return (
    <StatusContext.Provider value={status}>
      {isMobile ? (
        // Phones get their own shell: bottom tabs, sheets, card layouts — not
        // a squeezed sidebar.
        <MobileShell me={me} onLogout={onLogout} banner={banner} onSearch={openPalette} />
      ) : (
        <DesktopShell me={me} onLogout={onLogout} banner={banner} onSearch={openPalette} />
      )}
      <EntityPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} onUnauthorized={onUnauthorized} />
      {helpOpen && <ShortcutHelp onClose={() => setHelpOpen(false)} />}
    </StatusContext.Provider>
  )
}

function DesktopShell({
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
  return (
    <div className="flex min-h-screen">
      <aside
        className="flex w-56 shrink-0 flex-col border-r"
        style={{ background: 'var(--surface)', borderColor: 'var(--border)' }}
      >
        <div className="flex items-center gap-2.5 px-5 py-4">
          <Logo size={26} />
          <div className="font-mono text-sm font-semibold uppercase tracking-[0.3em]">Skopos</div>
        </div>
        <nav className="flex flex-1 flex-col gap-3 overflow-y-auto px-3 py-2">
          {SECTIONS.map((section) => (
            <div key={section.id} className="flex flex-col gap-0.5">
              <div
                className="px-2.5 pb-1 pt-1 font-mono text-[0.58rem] font-semibold uppercase tracking-[0.18em]"
                style={{ color: 'var(--muted)' }}
              >
                {section.title}
              </div>
              {NAV.filter((i) => i.section === section.id).map((item) => (
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
                  {item.label}
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

      <div className="flex min-w-0 flex-1 flex-col">
        <header
          className="flex items-center justify-between gap-3 border-b px-6 py-2.5"
          style={{ background: 'var(--surface)', borderColor: 'var(--border)' }}
        >
          <button
            type="button"
            onClick={onSearch}
            className="flex items-center gap-2 rounded-md border px-2.5 py-1 text-xs"
            style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--muted)' }}
            aria-label="Search Skopos"
          >
            <SearchIcon />
            Search
            <kbd className="font-mono text-[0.62rem] opacity-70">⌘K</kbd>
          </button>
          <div className="flex items-center gap-3">
            <StatusStrip />
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

        <main className="mx-auto w-full max-w-6xl flex-1 px-6 py-5">
          <Outlet />
        </main>
      </div>
    </div>
  )
}

// The cheatsheet, on ?. It lists what exists and nothing else.
function ShortcutHelp({ onClose }: { onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50" role="dialog" aria-modal="true" aria-label="Keyboard shortcuts">
      <div className="absolute inset-0" style={{ background: 'rgba(0,0,0,0.45)' }} onClick={onClose} aria-hidden />
      <div
        className="absolute left-1/2 top-1/4 w-[min(24rem,92vw)] -translate-x-1/2 rounded-xl border px-5 py-4"
        style={{ background: 'var(--surface)', borderColor: 'var(--border-strong)' }}
      >
        <h2 className="text-sm font-semibold tracking-tight">Keyboard</h2>
        <ul className="mt-2 flex flex-col gap-1 text-sm">
          {[...CHORDS.map((c) => ({ keys: c.keys, label: c.label })), { keys: '⌘K', label: 'Search' }, { keys: 'Esc', label: 'Close' }].map(
            (row) => (
              <li key={row.keys} className="flex items-baseline justify-between gap-3">
                <span style={{ color: 'var(--muted)' }}>{row.label}</span>
                <kbd className="font-mono text-xs">{row.keys}</kbd>
              </li>
            ),
          )}
        </ul>
        <button
          type="button"
          onClick={onClose}
          className="mt-3 rounded-md px-2.5 py-1 text-xs font-medium"
          style={{ background: 'var(--surface-2)', color: 'var(--muted)' }}
        >
          Close
        </button>
      </div>
    </div>
  )
}
