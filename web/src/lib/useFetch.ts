import { useCallback, useEffect, useRef, useState } from 'react'
import { api, APIError } from './api'

interface State<T> {
  data: T | null
  error: string | null
  loading: boolean
}

// Freshness is the third fact a view needs, alongside the data and the error.
//
//   loading  nothing on screen yet, a first request is out
//   fresh    the last attempt succeeded
//   stale    data is on screen and the newest attempt did not land
//   failed   no data, and the attempt failed
//
// Without the distinction a view can only choose between hiding a failure —
// keep rendering old numbers as though they were current — and hiding the data,
// blanking the screen on one dropped poll. Both are wrong, and roughly two
// thirds of the call sites picked the first.
export type Freshness = 'loading' | 'fresh' | 'stale' | 'failed'

// staleAfter decides when quiet becomes suspicious: three missed polls, and
// never less than ten seconds.
//
// Age matters as much as errors. A hung request that eventually rejects is
// visible, but until it does, nothing has failed and nothing looks wrong — the
// screen simply stops changing, which is indistinguishable from a network
// where nothing is happening. Deriving staleness from the clock as well as
// from errors closes that: the numbers go grey because they are old, whatever
// the reason nobody has replaced them.
function staleAfter(pollMs: number | undefined): number {
  return Math.max(3 * (pollMs ?? 0), 10_000)
}

export function useFetch<T>(
  path: string,
  opts: { pollMs?: number; onUnauthorized?: () => void } = {},
): State<T> & {
  stale: boolean
  freshness: Freshness
  updatedAt: number | null
  refresh: () => void
} {
  const [state, setState] = useState<State<T>>({ data: null, error: null, loading: true })
  const [updatedAt, setUpdatedAt] = useState<number | null>(null)
  const onUnauth = useRef(opts.onUnauthorized)
  onUnauth.current = opts.onUnauthorized

  // Reset during render, not in an effect.
  //
  // An effect runs after the browser has been handed a frame, so switching
  // from 24h to 7d committed one paint of the old window's totals underneath
  // the new label. Nobody would call that a bug out loud, and it is exactly
  // the class this release exists to remove: a number on screen that is not
  // what the screen says it is.
  const shownPath = useRef(path)
  if (shownPath.current !== path) {
    shownPath.current = path
    setState({ data: null, error: null, loading: true })
    setUpdatedAt(null)
  }

  // Only the most recently started request may write state. `refresh` and the
  // poll timer share this function, so without a guard the winner is whichever
  // resolves last, not whichever was asked for last: acknowledge an alert, and
  // a poll already in flight from before the click lands afterwards and puts
  // the row back to unacknowledged. No error, no second click — it just looks
  // like the acknowledgement undid itself, on the one screen where "did that
  // register" is the whole question.
  const seq = useRef(0)

  const load = useCallback(async () => {
    const mine = ++seq.current
    try {
      const data = await api.get<T>(path)
      if (mine !== seq.current) return true
      setState({ data, error: null, loading: false })
      setUpdatedAt(Date.now())
      return true
    } catch (e) {
      if (mine !== seq.current) return true
      if (e instanceof APIError && e.status === 401) {
        onUnauth.current?.()
        return true
      }
      setState((s) => ({ ...s, error: (e as Error).message, loading: false }))
      return false
    }
  }, [path])

  // A chained timeout rather than setInterval, with one request in flight at a
  // time. An interval keeps firing while a request is still running, so a NAS
  // slower than the poll period accumulates overlapping requests against the
  // single SQLite connection they are all queued behind — the load rises
  // because the load is high.
  //
  // Failures back off, with jitter so several hooks that broke together do not
  // recover in lockstep.
  useEffect(() => {
    let timer: number | undefined
    let cancelled = false
    let failures = 0

    const tick = async () => {
      const ok = await load()
      if (cancelled || !opts.pollMs) return
      failures = ok ? 0 : failures + 1
      const backoff = Math.min(opts.pollMs * 2 ** failures, Math.max(opts.pollMs, 60_000))
      const jitter = failures > 0 ? Math.random() * 0.25 * backoff : 0
      timer = window.setTimeout(tick, backoff + jitter)
    }
    void tick()

    return () => {
      cancelled = true
      if (timer !== undefined) window.clearTimeout(timer)
    }
  }, [load, opts.pollMs])

  // Re-render on the staleness boundary so data goes grey on its own, instead
  // of waiting for a poll that may never come back to relabel it.
  const [, bumpClock] = useState(0)
  useEffect(() => {
    if (updatedAt === null) return
    const due = updatedAt + staleAfter(opts.pollMs) - Date.now()
    if (due <= 0) return
    const id = window.setTimeout(() => bumpClock((n) => n + 1), due)
    return () => window.clearTimeout(id)
  }, [updatedAt, opts.pollMs])

  const aged = updatedAt !== null && Date.now() - updatedAt > staleAfter(opts.pollMs)
  const stale = state.data !== null && (state.error !== null || aged)
  const freshness: Freshness = state.loading
    ? 'loading'
    : state.data === null
      ? 'failed'
      : stale
        ? 'stale'
        : 'fresh'

  return { ...state, stale, freshness, updatedAt, refresh: load }
}
