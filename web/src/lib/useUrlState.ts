// URL state: the address bar holds the user's intent, and nothing else.
//
// The rule this file exists to enforce is that intent is relative and a
// timestamp is not. Traffic used to freeze an absolute from/to at page open
// and poll it forever, so "Last hour" quietly became "that hour, a day ago"
// on any tab left open overnight. A window is therefore computed at fetch
// time from a token in the URL, never stored.

import { useCallback, useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'

type History = 'push' | 'replace'

// useUrlState reads and writes one query parameter.
//
// Reading never corrects: an unrecognised value falls back and is left in the
// URL untouched, because rewriting someone's address bar under them loses the
// evidence of what they actually asked for. Writing merges — a view never
// clobbers a parameter it does not own — and writing the fallback deletes the
// key, so a page at its defaults has a bare, shareable URL.
export function useUrlState<T extends string>(
  key: string,
  fallback: T,
  opts: { valid?: readonly T[]; history?: History } = {},
): [T, (next: T) => void] {
  const [params, setParams] = useSearchParams()
  const { valid, history = 'replace' } = opts

  const raw = params.get(key)
  const value = raw !== null && (!valid || (valid as readonly string[]).includes(raw)) ? (raw as T) : fallback

  const set = useCallback(
    (next: T) => {
      setParams(
        (prev) => {
          const merged = new URLSearchParams(prev)
          if (next === fallback || next === '') merged.delete(key)
          else merged.set(key, next)
          return merged
        },
        // push is for committed choices — a range, a lens, a tab. Back then
        // undoes the last deliberate act instead of walking backwards through
        // keystrokes, and never leaves the page while a filter is still set.
        { replace: history !== 'push' },
      )
    },
    [key, fallback, history, setParams],
  )

  return [value, set]
}

// useUrlText is the free-text variant: the input stays responsive while the
// URL — and therefore the fetch — is only updated once the typing stops. The
// debounce lives here rather than in useUrlState because the hook itself is
// synchronous and dumb by contract.
//
// Returns the draft the input should show, its setter, and the committed value
// the fetch should use.
export function useUrlText(key: string, delayMs = 300): [string, (v: string) => void, string] {
  const [params, setParams] = useSearchParams()
  const committed = params.get(key) ?? ''
  const [draft, setDraft] = useState(committed)
  // What we last wrote ourselves. Anything else arriving in `committed` came
  // from outside — Back, a pasted link, the palette — and the input adopts it.
  const written = useRef(committed)

  useEffect(() => {
    if (committed !== written.current) {
      written.current = committed
      setDraft(committed)
    }
  }, [committed])

  useEffect(() => {
    if (draft === committed) return
    const id = setTimeout(() => {
      written.current = draft
      setParams(
        (prev) => {
          const merged = new URLSearchParams(prev)
          if (draft === '') merged.delete(key)
          else merged.set(key, draft)
          return merged
        },
        { replace: true },
      )
    }, delayMs)
    return () => clearTimeout(id)
  }, [draft, committed, delayMs, key, setParams])

  return [draft, setDraft, committed]
}

// ---- the one time vocabulary ----

// live is not a sixth window. It is the zero-width position at the left end of
// the same control, which is why it lives in the same list: the user moves
// along one axis from "right now" to "the last 30 days".
export const RANGES = ['live', '1h', '6h', '24h', '7d', '30d'] as const
export type Range = (typeof RANGES)[number]

// WINDOWS is the vocabulary for views that have no live mode.
export const WINDOWS = ['1h', '6h', '24h', '7d', '30d'] as const

const RANGE_MS: Record<Exclude<Range, 'live'>, number> = {
  '1h': 3600_000,
  '6h': 6 * 3600_000,
  '24h': 24 * 3600_000,
  '7d': 7 * 24 * 3600_000,
  '30d': 30 * 24 * 3600_000,
}

export const RANGE_LABEL: Record<Range, string> = {
  live: 'Live',
  '1h': '1h',
  '6h': '6h',
  '24h': '24h',
  '7d': '7d',
  '30d': '30d',
}

export const RANGE_HINT: Record<Range, string> = {
  live: 'Right now, as it happens',
  '1h': 'Last hour',
  '6h': 'Last 6 hours',
  '24h': 'Last 24 hours',
  '7d': 'Last 7 days',
  '30d': 'Last 30 days',
}

// rangeWindow resolves a token to absolute times. Called at fetch time, once
// per poll — never at mount. `to` is always now, which is the whole point.
export function rangeWindow(r: Range): { from: Date; to: Date } {
  if (r === 'live') {
    // A live view has no window and must not be handed a fake one; a caller
    // asking for one has confused the two modes.
    throw new Error('rangeWindow: live has no window')
  }
  const to = new Date()
  return { from: new Date(to.getTime() - RANGE_MS[r]), to }
}

// apiWindow is the same token in the form the `window=` endpoints parse
// (config.ParseDuration understands 7d and 30d).
export function apiWindow(r: Range): string {
  if (r === 'live') throw new Error('apiWindow: live has no window')
  return r
}

// useUrlRange is the single time control, shared by every view that has one.
// A view that supports a subset passes `allowed`; a token outside it falls
// back and the control shows the fallback as selected, rather than silently
// clamping to a window nobody chose.
export function useUrlRange(
  fallback: Range = '1h',
  allowed: readonly Range[] = RANGES,
): { range: Range; setRange: (r: Range) => void; window: () => { from: Date; to: Date } } {
  const [range, setRange] = useUrlState<Range>('range', fallback, { valid: allowed, history: 'push' })
  const window = useCallback(() => rangeWindow(range), [range])
  return { range, setRange, window }
}
