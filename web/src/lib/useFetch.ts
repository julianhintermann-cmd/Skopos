import { useCallback, useEffect, useRef, useState } from 'react'
import { api, APIError } from './api'

interface State<T> {
  data: T | null
  error: string | null
  loading: boolean
}

// useFetch GETs a path, optionally polling. It exposes a manual refresh and
// surfaces 401 by calling onUnauthorized so the app can show the login screen.
export function useFetch<T>(
  path: string,
  opts: { pollMs?: number; onUnauthorized?: () => void } = {},
): State<T> & { refresh: () => void } {
  const [state, setState] = useState<State<T>>({ data: null, error: null, loading: true })
  const onUnauth = useRef(opts.onUnauthorized)
  onUnauth.current = opts.onUnauthorized

  const load = useCallback(async () => {
    try {
      const data = await api.get<T>(path)
      setState({ data, error: null, loading: false })
    } catch (e) {
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

  return { ...state, refresh: load }
}
