import { useMemo, useRef, useState } from 'react'
import { publishChartCursor, useChartCursor, useChartFrame } from '../lib/chartSync'
import { formatTime } from '../lib/format'

// A one-row timeline that sits under a throughput chart and marks what
// happened: alerts, blocks, and spans nobody captured.
//
// It exists because "there was a spike at 03:12" and "the port-scan detector
// fired twice at 03:12" are currently two pages, and joining them is left to
// the operator's memory. On the same x-scale they are one sentence.
//
// Alignment is the whole trick, and it is not done by eye. The chart's y-axis
// reserves 48px on its left and the plot is padded on its right, so a strip
// that spans its own container is wrong by tens of pixels — enough to put a
// tick under the wrong five minutes of a 1h window. The chart publishes where
// it actually draws (lib/chartSync) and this reads it, which also means the
// two stay aligned through a resize without either measuring the other.
//
// Render it as a sibling of the chart, inside the same padded container, so
// both share a left origin and a width.

export type EventKind = 'alert' | 'block' | 'gap'
export type EventSeverity = 'info' | 'warn' | 'critical'

export interface StripEvent {
  // ISO timestamp of the moment, or of the start when `until` is set.
  time: string
  kind: EventKind
  severity?: EventSeverity
  label: string
  // Set for a span rather than an instant — a capture outage, a block's life.
  until?: string
}

export function EventStrip({
  events,
  from,
  to,
  syncGroup,
  height = 26,
}: {
  // null is "not loaded", and it is not the same picture as []. An empty strip
  // asserts that nothing happened in this window; only an answer from the
  // server can support that claim.
  events: StripEvent[] | null
  from: string
  to: string
  syncGroup?: string
  height?: number
}) {
  const host = useRef<HTMLDivElement>(null)
  const [hover, setHover] = useState<number | null>(null)
  const frame = useChartFrame(syncGroup)
  const cursorT = useChartCursor(syncGroup)

  // The chart's own x extent wins when it has published one: the series ends at
  // the last complete bucket, which is not `to`, and lining marks up with the
  // requested window instead of the drawn one reintroduces the offset this
  // component exists to remove.
  const minX = frame ? frame.minX : new Date(from).getTime() / 1000
  const maxX = frame ? frame.maxX : new Date(to).getTime() / 1000
  const span = maxX - minX

  const marks = useMemo(() => {
    if (!events || span <= 0) return []
    return events
      .map((e) => {
        const t = new Date(e.time).getTime() / 1000
        const end = e.until ? new Date(e.until).getTime() / 1000 : null
        return { e, t, end, frac: (t - minX) / span, endFrac: end != null ? (end - minX) / span : null }
      })
      .filter((m) => m.frac >= -0.02 && m.frac <= 1.02)
      .sort((a, b) => a.t - b.t)
  }, [events, minX, span])

  const inset = frame ? { marginLeft: frame.left, width: frame.width } : undefined

  const onMove = (e: { clientX: number }) => {
    const box = host.current
    if (!box || span <= 0) return
    const r = box.getBoundingClientRect()
    if (r.width === 0) return
    const frac = (e.clientX - r.left) / r.width
    publishChartCursor(syncGroup, minX + frac * span)
    // Nearest mark within six pixels. Beyond that the pointer is not on
    // anything and the caption says nothing rather than the closest thing.
    const tol = (6 / r.width) * span
    let best: number | null = null
    let bestD = Infinity
    marks.forEach((m, i) => {
      const d = Math.abs(m.t - (minX + frac * span))
      if (d < bestD && d <= tol) {
        bestD = d
        best = i
      }
    })
    setHover(best)
  }

  const summary = events
    ? events.length === 0
      ? 'No alerts or blocks recorded in this window.'
      : `${events.length} ${events.length === 1 ? 'event' : 'events'} — hover a mark to name it`
    : 'Alerts and blocks were not loaded for this window, so this row is empty for a reason that is not "nothing happened".'

  const hovered = hover != null ? marks[hover] : undefined
  const cursorFrac = cursorT != null && span > 0 ? (cursorT - minX) / span : null

  return (
    <div className="w-full">
      <div
        ref={host}
        className="relative"
        style={{ height, ...inset }}
        onPointerMove={onMove}
        onPointerLeave={() => {
          setHover(null)
          publishChartCursor(syncGroup, null)
        }}
        role="img"
        aria-label={summary}
      >
        <div
          className="absolute right-0 left-0"
          style={{ top: height / 2, height: 1, background: 'var(--border)' }}
        />
        {cursorFrac != null && cursorFrac >= 0 && cursorFrac <= 1 && (
          <div
            className="pointer-events-none absolute top-0 bottom-0"
            style={{ left: `${cursorFrac * 100}%`, width: 1, background: 'var(--border-strong)' }}
          />
        )}
        {marks.map((m, i) => (
          <Mark key={`${m.e.time}-${i}`} m={m} height={height} active={i === hover} />
        ))}
      </div>
      <div
        className="overflow-hidden text-xs text-ellipsis whitespace-nowrap"
        style={{ height: '1.25rem', color: hovered ? 'var(--text)' : 'var(--muted)', ...inset }}
      >
        {hovered ? (
          <>
            <span className="tabnums font-mono" style={{ color: 'var(--muted)' }}>
              {formatTime(hovered.e.time)}
            </span>{' '}
            {hovered.e.label}
          </>
        ) : (
          summary
        )}
      </div>
    </div>
  )
}

interface PlacedEvent {
  e: StripEvent
  frac: number
  endFrac: number | null
}

// Shape carries the kind and colour carries the severity, so neither is doing
// the job alone: an alert is a triangle whatever its tone, and a block stays a
// square on a monochrome display or to an eye that cannot separate the two
// hues.
function Mark({ m, height, active }: { m: PlacedEvent; height: number; active: boolean }) {
  const left = `${m.frac * 100}%`
  const color = kindColor(m.e)

  if (m.e.kind === 'gap' && m.endFrac != null) {
    return (
      <div
        className="sk-nodata absolute top-0 bottom-0"
        style={{ left, width: `${Math.max(m.endFrac - m.frac, 0) * 100}%` }}
        title={m.e.label}
      />
    )
  }

  const size = active ? 9 : 7
  const top = height / 2 - size / 2
  if (m.e.kind === 'block') {
    return (
      <div
        className="absolute"
        style={{ left, top, width: size, height: size, marginLeft: -size / 2, background: color }}
        title={m.e.label}
      />
    )
  }
  return (
    <div
      className="absolute"
      style={{
        left,
        top,
        marginLeft: -size / 2,
        width: 0,
        height: 0,
        borderLeft: `${size / 2}px solid transparent`,
        borderRight: `${size / 2}px solid transparent`,
        borderBottom: `${size}px solid ${color}`,
      }}
      title={m.e.label}
    />
  )
}

function kindColor(e: StripEvent): string {
  if (e.kind === 'block') return 'var(--sk-series-3)'
  if (e.kind === 'gap') return 'var(--sk-nodata-stripe)'
  switch (e.severity) {
    case 'critical':
      return 'var(--crit)'
    case 'warn':
      return 'var(--warn)'
    default:
      return 'var(--muted)'
  }
}
