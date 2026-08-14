import { useEffect, useState } from 'react'

// useTick re-renders on an interval so a caller can recompute a value that
// depends on the current time.
//
// It exists for the endpoints that take absolute from/to. A window computed
// once at mount and then polled forever is the defect this release is fixing:
// "Last hour" on a tab left open overnight was a day stale, because the path
// being polled still carried yesterday's timestamps. Recomputing the path on
// each tick makes every request mean what the control says it means.
export function useTick(ms: number): number {
  const [tick, setTick] = useState(0)
  useEffect(() => {
    if (!ms) return
    const id = setInterval(() => setTick((t) => t + 1), ms)
    return () => clearInterval(id)
  }, [ms])
  return tick
}
