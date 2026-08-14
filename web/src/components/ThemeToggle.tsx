import { useTheme } from '../lib/theme'

// Cycles system → light → dark. Shows the icon of the resolved appearance.
//
// 28px is a fine target for a mouse and half of one for a thumb, so the
// coarse-pointer floor is 44 and the desktop keeps its density.
export function ThemeToggle() {
  const { theme, setTheme, resolved } = useTheme()
  const next = theme === 'system' ? 'light' : theme === 'light' ? 'dark' : 'system'
  const label = `Theme: ${theme} (click for ${next})`
  return (
    <button
      onClick={() => setTheme(next)}
      title={label}
      aria-label={label}
      className="flex h-7 w-7 items-center justify-center rounded-md pointer-coarse:h-11 pointer-coarse:w-11"
      style={{ color: 'var(--muted)', background: 'var(--surface-2)' }}
    >
      {resolved === 'dark' ? <MoonIcon /> : <SunIcon />}
    </button>
  )
}

function SunIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
    </svg>
  )
}
function MoonIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" />
    </svg>
  )
}
