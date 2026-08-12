import { useEffect, useRef } from 'react'

// useSSE subscribes to the /api/stream event stream and invokes onEvent for
// each named event. It reconnects automatically and pauses when the tab has
// been hidden for a while, to spare the NAS.
export function useSSE(onEvent: (type: string, data: unknown) => void) {
  const handlerRef = useRef(onEvent)
  handlerRef.current = onEvent

  useEffect(() => {
    let es: EventSource | null = null
    let hiddenSince = 0
    let closed = false

    const connect = () => {
      if (closed) return
      es = new EventSource('/api/stream')
      es.onmessage = (e) => dispatch('message', e.data)
      // Named events.
      for (const type of ['overview', 'alert', 'system']) {
        es.addEventListener(type, (e) => dispatch(type, (e as MessageEvent).data))
      }
      es.onerror = () => {
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
