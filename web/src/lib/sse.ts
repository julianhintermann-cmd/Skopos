import { useEffect, useRef } from 'react'

// Named events the backend publishes on /api/stream. `live` (throughput, once a
// second) and `flows` (each completed batch) drive the live view; the rest are
// reserved for views that opt into push updates.
const NAMED_EVENTS = ['live', 'flows', 'overview', 'alert', 'system'] as const

// useSSE subscribes to the /api/stream event stream and invokes onEvent for
// each named event. It reconnects automatically and pauses when the tab has
// been hidden for a while, to spare the NAS. onStatus, if given, reports
// whether the stream is currently connected.
export function useSSE(
  onEvent: (type: string, data: unknown) => void,
  onStatus?: (connected: boolean) => void,
) {
  const handlerRef = useRef(onEvent)
  handlerRef.current = onEvent
  const statusRef = useRef(onStatus)
  statusRef.current = onStatus

  useEffect(() => {
    let es: EventSource | null = null
    let hiddenSince = 0
    let closed = false

    const connect = () => {
      if (closed) return
      es = new EventSource('/api/stream')
      es.onopen = () => statusRef.current?.(true)
      es.onmessage = (e) => dispatch('message', e.data)
      for (const type of NAMED_EVENTS) {
        es.addEventListener(type, (e) => dispatch(type, (e as MessageEvent).data))
      }
      es.onerror = () => {
        statusRef.current?.(false)
        es?.close()
        if (!closed) setTimeout(connect, 3000)
      }
    }

    const dispatch = (type: string, raw: string) => {
      try {
        handlerRef.current(type, JSON.parse(raw))
      } catch {
        /* ignore malformed frames */
      }
    }

    const onVisibility = () => {
      if (document.hidden) {
        hiddenSince = Date.now()
      } else if (hiddenSince && Date.now() - hiddenSince > 5 * 60 * 1000) {
        // Reconnect after a long hidden stretch.
        es?.close()
        connect()
      }
    }

    connect()
    document.addEventListener('visibilitychange', onVisibility)
    return () => {
      closed = true
      es?.close()
      document.removeEventListener('visibilitychange', onVisibility)
    }
  }, [])
}
