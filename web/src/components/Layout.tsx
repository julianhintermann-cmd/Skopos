import { useCallback, useState, type ReactNode } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { Logo } from './Logo'
import { ThemeToggle } from './ThemeToggle'
import { MobileShell } from './mobile'
import { StatusStrip } from './StatusStrip'
import { EntityPalette } from './EntityPalette'
import { NAV, SECTIONS, SearchIcon } from './nav'
import { useLayoutTier } from '../lib/useIsMobile'
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
  const tier = useLayoutTier()
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
      {tier === 'phone' ? (
        // Phones get their own shell: bottom tabs, sheets, card layouts — not
        // a squeezed sidebar.
        <MobileShell me={me} onLogout={onLogout} banner={banner} onSearch={openPalette} />
      ) : (
        <DesktopShell rail={tier === 'rail'} me={me} onLogout={onLogout} banner={banner} onSearch={openPalette} />
      )}
      <EntityPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} onUnauthorized={onUnauthorized} />
      {helpOpen && <ShortcutHelp onClose={() => setHelpOpen(false)} />}
    </StatusContext.Provider>
  )
}

// The desktop shell in two widths.
//
// `rail` is the tier that was missing. Between 768 and 1023 this sidebar was
// still 224px — 29% of an iPad portrait, 27% of a phone in landscape — while
// every stat grid stayed two-up and every table stayed wider than the column
// it was given. Collapsing to a 56px icon rail returns 168px of content, which
// is what closes the gap between the phone design and the 1280px one.
function DesktopShell({
  rail,
  me,
  onLogout,
  banner,
  onSearch,
}: {
  rail: boolean
  me: Me | null
  onLogout: () => void
  banner?: ReactNode
  onSearch: () => void
}) {
  return (
    <div className="flex min-h-dvh">
      {/* Eight nav links stand between the top of the document and the content
          on every navigation. This is the way past them. */}
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded-md focus:px-3 focus:py-2 focus:text-sm focus:font-medium"
        style={{ background: 'var(--surface)', color: 'var(--accent-strong)' }}
      >
        Skip to content
      </a>
      <aside
        className={`flex shrink-0 flex-col border-r ${rail ? 'w-14' : 'w-56'}`}
        style={{ background: 'var(--surface)', borderColor: 'var(--border)' }}
      >
        <div className={`flex items-center gap-2.5 py-4 ${rail ? 'justify-center px-0' : 'px-5'}`}>
          <Logo size={26} />
          {!rail && <div className="font-mono text-sm font-semibold uppercase tracking-[0.3em]">Skopos</div>}
        </div>
        <nav className={`flex flex-1 flex-col gap-3 overflow-y-auto py-2 ${rail ? 'px-1.5' : 'px-3'}`}>
          {SECTIONS.map((section) => (
            <div key={section.id} className="flex flex-col gap-0.5">
              {rail ? (
                // The section heading is text the rail has no room for, so it
                // becomes a rule with the name still in the tree for a screen
                // reader — dropping it entirely would drop the grouping too.
                <div className="mx-2 my-1 h-px" style={{ background: 'var(--border)' }} role="separator" aria-label={section.title} />
              ) : (
                <div
                  className="px-2.5 pb-1 pt-1 font-mono text-[0.58rem] font-semibold uppercase tracking-[0.18em]"
                  style={{ color: 'var(--muted)' }}
                >
                  {section.title}
                </div>
              )}
              {NAV.filter((i) => i.section === section.id).map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  title={rail ? item.label : undefined}
                  aria-label={rail ? item.label : undefined}
                  className={`group flex items-center rounded-md text-sm font-medium transition-colors ${
                    rail ? 'h-11 justify-center' : 'gap-2.5 px-2.5 py-2'
                  }`}
                  style={({ isActive }) =>
                    isActive
                      ? { background: 'var(--accent-tint)', color: 'var(--accent-strong)' }
                      : { color: 'var(--muted)' }
                  }
                >
                  <item.icon size={rail ? 20 : 16} />
                  {!rail && item.label}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        {!rail && (
          <div className="px-4 py-3 text-xs" style={{ color: 'var(--muted)', borderTop: '1px solid var(--border)' }}>
            <div className="font-mono">σκοπός</div>
            <div>the watcher</div>
          </div>
        )}
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header
          className={`flex items-center justify-between gap-3 border-b py-2.5 ${rail ? 'px-4' : 'px-6'}`}
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
          <div className="flex min-w-0 items-center gap-3">
            <StatusStrip />
            <ThemeToggle />
            {me?.auth && (
              <button
                onClick={onLogout}
                className="shrink-0 rounded-md px-2 py-1 text-xs font-medium"
                style={{ color: 'var(--muted)' }}
              >
                {t('action.logout')}
              </button>
            )}
          </div>
        </header>

        {banner}

        <main id="main" className={`mx-auto w-full max-w-6xl flex-1 py-5 ${rail ? 'px-4' : 'px-6'}`}>
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
