import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'

type Theme = 'light' | 'dark' | 'system'

interface ThemeCtx {
  theme: Theme
  setTheme: (t: Theme) => void
  resolved: 'light' | 'dark'
}

const Ctx = createContext<ThemeCtx | null>(null)

const STORAGE_KEY = 'skopos-theme'

// 'system' is the default: light and dark are separately tuned and each is
// held to the same contrast thresholds, so there is no reason to override the
// answer the operating system already has.
const DEFAULT: Theme = 'system'

function stored(): Theme {
  try {
    const v = localStorage.getItem(STORAGE_KEY)
    return v === 'light' || v === 'dark' || v === 'system' ? v : DEFAULT
  } catch {
    // Private-mode Safari throws on localStorage access rather than returning
    // null. A theme preference is not worth a blank screen.
    return DEFAULT
  }
}

function resolve(theme: Theme): 'light' | 'dark' {
  if (theme === 'system') {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  }
  return theme
}

// Always write an explicit data-theme, never remove it. Leaving the attribute
// off for 'system' pushed theme resolution into a `@media (prefers-color-scheme)`
// block, which duplicated the whole dark palette and — because `color-scheme`
// sat outside that block — painted dark browser chrome (checkboxes, selects,
// scrollbars) over light tokens for anyone on a light OS. One attribute, one
// palette, one `color-scheme`.
function apply(resolved: 'light' | 'dark') {
  document.documentElement.setAttribute('data-theme', resolved)

  // Keep the mobile browser chrome on the resolved theme. The two media-scoped
  // <meta> entries in index.html only track the OS, so an explicit light choice
  // on a dark OS would otherwise keep a dark address bar. Read the value back
  // out of the cascade so this cannot drift from index.css.
  const canvas = getComputedStyle(document.documentElement).getPropertyValue('--sk-canvas').trim()
  if (canvas) {
    document.querySelectorAll<HTMLMetaElement>('meta[name="theme-color"]').forEach((m) => {
      m.content = canvas
    })
  }
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(stored)
  const [resolved, setResolved] = useState<'light' | 'dark'>(() => resolve(theme))

  useEffect(() => {
    const next = resolve(theme)
    setResolved(next)
    apply(next)

    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const onChange = () => {
      if (theme !== 'system') return
      const r = resolve('system')
      setResolved(r)
      apply(r)
    }
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [theme])

  const setTheme = (t: Theme) => {
    try {
      localStorage.setItem(STORAGE_KEY, t)
    } catch {
      // Preference will not survive the reload; the session still switches.
    }
    setThemeState(t)
  }

  return <Ctx.Provider value={{ theme, setTheme, resolved }}>{children}</Ctx.Provider>
}

export function useTheme() {
  const c = useContext(Ctx)
  if (!c) throw new Error('useTheme outside provider')
  return c
}
