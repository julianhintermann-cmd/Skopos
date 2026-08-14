import { useCallback, useEffect, useRef, useState } from 'react'
import { api, APIError } from './api'

interface State<T> {
  data: T | null
  error: string | null
  loading: boolean
}

// useFetch GETs a path, optionally polling. It exposes a manual refresh and
// surfaces 401 by calling onUnauthorized so the app can show the login screen.
//
// `stale` is true when data is on screen but the most recent attempt to update
// it failed. Callers need that third state: without it, a view can only choose
// between hiding a failure (keep rendering old numbers as if they were fresh)
// and hiding the data (blank the screen on one dropped poll). Both are wrong,
// and roughly two thirds of the call sites picked the first.
export function useFetch<T>(
  path: string,
  opts: { pollMs?: number; onUnauthorized?: () => void } = {},
): State<T> & { stale: boolean; refresh: () => void } {
  const [state, setState] = useState<State<T>>({ data: null, error: null, loading: true })
  const onUnauth = useRef(opts.onUnauthorized)
  onUnauth.current = opts.onUnauthorized

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
      if (mine !== seq.current) return
      setState({ data, error: null, loading: false })
    } catch (e) {
      if (mine !== seq.current) return
      if (e instanceof APIError && e.status === 401) {
        onUnauth.current?.()
        return
      }
      setState((s) => ({ ...s, error: (e as Error).message, loading: false }))
    }
  }, [path])

  useEffect(() => {
    load()
    if (opts.pollMs) {
      const id = setInterval(load, opts.pollMs)
      return () => clearInterval(id)
    }
  }, [load, opts.pollMs])

  return { ...state, stale: state.error !== null && state.data !== null, refresh: load }
}
