import { useCallback, useMemo, useSyncExternalStore } from 'react'

// One time cursor for every chart on a page.
//
// Two charts stacked over the same window were two unrelated pictures: a spike
// in the throughput chart and the alert that came with it could only be lined
// up by eye, across a y-axis gutter of unknown width. uPlot's own cursor.sync
// joins uPlot to uPlot and nothing else, and half the marks on these pages —
// the sparklines, the event strip — are hand-drawn SVG that has to be told
// where the cursor is in terms it can use.
//
// So a group carries two facts, not one. The cursor's position in *time* is the
// obvious half. The publishing plot's drawing area in *pixels* is the half that
// is easy to assume away and wrong to: the y-axis reserves 48px on the left and
// the plot is padded 8px on the right, so a strip that spans its own
// container's full width is offset by exactly the amount that makes "the spike
// happened at the alert" a false statement. The publisher measures its own
// overlay and says where it is; subscribers do not guess.

// ChartFrame is where a published plot actually draws, in the coordinates a
// sibling element can use directly: CSS pixels from the left edge of a
// container of the same width, and the epoch seconds at each end of that span.
export interface ChartFrame {
  left: number
  width: number
  minX: number
  maxX: number
}

type Listener = () => void

interface GroupState {
  // Epoch seconds under the cursor, or null when no chart in the group is
  // hovered. Never a value the publisher had to invent — it is read off the
  // publishing plot's own x scale.
  cursor: number | null
  frame: ChartFrame | null
}

const groups = new Map<string, GroupState>()
const listeners = new Map<string, Set<Listener>>()

function stateOf(group: string): GroupState {
  let s = groups.get(group)
  if (!s) {
    s = { cursor: null, frame: null }
    groups.set(group, s)
  }
  return s
}

function emit(group: string) {
  const set = listeners.get(group)
  if (set) for (const l of set) l()
}

function subscriberFor(group: string | undefined) {
  return (listener: Listener) => {
    if (!group) return () => {}
    let set = listeners.get(group)
    if (!set) {
      set = new Set()
      listeners.set(group, set)
    }
    set.add(listener)
    return () => {
      set?.delete(listener)
    }
  }
}

// publishChartCursor announces where the cursor is, in epoch seconds. Pass null
// when the pointer leaves the plot: a stale crosshair left behind on a sibling
// chart claims a hover that is not happening.
export function publishChartCursor(group: string | undefined, t: number | null) {
  if (!group) return
  const s = stateOf(group)
  if (s.cursor === t) return
  s.cursor = t
  emit(group)
}

// publishChartFrame announces the publisher's drawing area. The shallow compare
// is load-bearing rather than an optimisation: this is called from uPlot's draw
// hook, which runs on every redraw, and a new object each time would rerender
// every subscriber at the frame rate of the cursor.
export function publishChartFrame(group: string | undefined, frame: ChartFrame) {
  if (!group) return
  const s = stateOf(group)
  const cur = s.frame
  if (
    cur &&
    cur.left === frame.left &&
    cur.width === frame.width &&
    cur.minX === frame.minX &&
    cur.maxX === frame.maxX
  ) {
    return
  }
  s.frame = frame
  emit(group)
}

// clearChartFrame drops a publisher's frame on unmount, so a strip does not go
// on aligning itself to a chart that is no longer on the page.
export function clearChartFrame(group: string | undefined) {
  if (!group) return
  const s = stateOf(group)
  if (s.frame === null && s.cursor === null) return
  s.frame = null
  s.cursor = null
  emit(group)
}

export function useChartCursor(group: string | undefined): number | null {
  const subscribe = useMemo(() => subscriberFor(group), [group])
  const snapshot = useCallback(() => (group ? stateOf(group).cursor : null), [group])
  return useSyncExternalStore(subscribe, snapshot, snapshot)
}

export function useChartFrame(group: string | undefined): ChartFrame | null {
  const subscribe = useMemo(() => subscriberFor(group), [group])
  const snapshot = useCallback(() => (group ? stateOf(group).frame : null), [group])
  return useSyncExternalStore(subscribe, snapshot, snapshot)
}

// uplotSync is the cursor.sync options object for a group. setSeries is off
// because these charts do not share a series list — syncing series focus
// between a throughput chart and a request-count chart would highlight
// whichever series happens to sit at the same index, which is a coincidence.
export function uplotSync(group: string | undefined) {
  return group ? { key: group, setSeries: false } : undefined
}

// nearestIndex finds the sample closest to t, or -1 when the closest one is
// further away than maxDistance.
//
// The bound is the whole point. A subscriber that always snaps to its nearest
// sample will happily label a hover in the middle of a four-hour hole with the
// reading from either side of it, which is the interpolation defect again in
// text form. Outside the bound there is no sample and the honest answer is to
// draw the crosshair and no value.
export function nearestIndex(times: number[], t: number, maxDistance: number): number {
  if (times.length === 0) return -1
  let lo = 0
  let hi = times.length - 1
  while (lo < hi) {
    const mid = (lo + hi) >> 1
    if (times[mid] < t) lo = mid + 1
    else hi = mid
  }
  const cands = lo > 0 ? [lo - 1, lo] : [lo]
  let best = -1
  let bestD = Infinity
  for (const i of cands) {
    const d = Math.abs(times[i] - t)
    if (d < bestD) {
      bestD = d
      best = i
    }
  }
  return bestD <= maxDistance ? best : -1
}
