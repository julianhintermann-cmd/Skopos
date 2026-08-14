import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from './api'
import type { LiveFlow } from './api'
import type { LiveNow } from './contracts'
import type { FeedFlow } from '../components/FlowTable'
import { useSSE } from './sse'

const MAX_ROWS = 200
const MAX_SPARK = 120 // ~2 minutes at 1 Hz

// The live half of Traffic, as one subscription.
//
// Both the throughput reading and the flow feed arrive on the same event
// stream, so they are read by one hook: two useSSE calls would open two
// EventSources against a NAS to deliver frames it already sends together.
export function useLiveStream({
  flows = false,
  paused = false,
  onUnauthorized,
}: {
  flows?: boolean
  paused?: boolean
  onUnauthorized?: () => void
} = {}) {
  const [live, setLive] = useState<LiveNow | null>(null)
  const [spark, setSpark] = useState<number[]>([])
  // The timestamp of each kept reading, so the sparkline can space its points
  // by when they happened. Skipping an unmeasured second keeps the values
  // honest but silently closes the gap: three missing seconds become three
  // adjacent points, and a stalled capture draws as a continuous line at
  // whatever rate preceded it.
  const [sparkTimes, setSparkTimes] = useState<number[]>([])
  const [rows, setRows] = useState<FeedFlow[]>([])
  const [connected, setConnected] = useState(false)
  const [buffered, setBuffered] = useState(0)
  const idRef = useRef(0)
  const pausedRef = useRef(paused)
  pausedRef.current = paused
  const bufferRef = useRef<FeedFlow[]>([])

  // Initial back-fill so the table is not empty while waiting for the next
  // flush.
  useEffect(() => {
    if (!flows) return
    let stop = false
    api
      .get<{ flows: LiveFlow[] | null }>('/api/live/flows')
      .then(({ flows: batch }) => {
        if (stop || !batch?.length) return
        setRows(batch.slice(0, MAX_ROWS).map((f) => ({ ...f, _id: idRef.current++, _fresh: false })))
      })
      .catch((e) => {
        if ((e as { status?: number }).status === 401) onUnauthorized?.()
      })
    return () => {
      stop = true
    }
  }, [flows, onUnauthorized])

  const onEvent = useCallback(
    (type: string, data: unknown) => {
      if (type === 'live') {
        const s = data as LiveNow
        setLive(s)
        // Only a real reading extends the sparkline. An unmeasured second is
        // absent from the payload now, and pushing a zero for it would draw a
        // dead capture as a quiet network — the exact line this release is
        // getting rid of.
        if (typeof s.bits_per_second === 'number') {
          setSpark((prev) => [...prev, s.bits_per_second as number].slice(-MAX_SPARK))
          // measured_at is when the server took the reading. Falling back to
          // the browser's clock would put the point where it arrived rather
          // than where it happened, which is the same error at a smaller
          // scale.
          const at = s.measured_at ? new Date(s.measured_at).getTime() : Date.now()
          setSparkTimes((prev) => [...prev, at].slice(-MAX_SPARK))
        }
        return
      }
      if (type !== 'flows' || !flows) return
      const batch = data as LiveFlow[]
      if (!batch?.length) return
      const sorted = [...batch].sort((a, b) => +new Date(b.end) - +new Date(a.end))
      const fresh = sorted.map((f) => ({ ...f, _id: idRef.current++, _fresh: true }))
      if (pausedRef.current) {
        // While paused, hold new flows aside so the table stays still; they
        // are merged (and counted on the button) when the user resumes.
        bufferRef.current = [...fresh, ...bufferRef.current].slice(0, MAX_ROWS)
        setBuffered(bufferRef.current.length)
        return
      }
      setRows((prev) => [...fresh, ...prev.map((r) => ({ ...r, _fresh: false }))].slice(0, MAX_ROWS))
    },
    [flows],
  )

  useSSE(onEvent, setConnected)

  // flush merges what arrived while paused, in arrival order.
  const flush = useCallback(() => {
    const held = bufferRef.current
    bufferRef.current = []
    setBuffered(0)
    setRows((prev) => [...held, ...prev.map((r) => ({ ...r, _fresh: false }))].slice(0, MAX_ROWS))
  }, [])

  return { live, spark, sparkTimes, rows, connected, buffered, flush }
}
