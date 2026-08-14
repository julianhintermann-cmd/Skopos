import { useEffect, useMemo, useRef, useState } from 'react'
import uPlot from 'uplot'
import 'uplot/dist/uPlot.min.css'
import type { Point } from '../lib/contracts'
import { formatBits } from '../lib/format'
import { useTheme } from '../lib/theme'
import { clearChartFrame, publishChartCursor, publishChartFrame, uplotSync } from '../lib/chartSync'

// A throughput chart: bits/s over time, on a recessive grid, with a crosshair
// and a live readout of every series under it.
//
// bucketSeconds is how much time one point covers, and it is required rather
// than assumed: the server picks the rollup resolution per request, so a
// hardcoded divisor silently overstates the rate by 60x as soon as the range
// crosses into hourly buckets. Pass null when the resolution is unknown and
// the chart declines to draw instead of scaling by a guess.

// DirectionalPoint is a series point plus the upload/download split that landed
// with migration 0011. It is declared here rather than in contracts.ts because
// that file belongs to another engineer this cycle; both fields are optional,
// so a plain Point[] is assignable and no call site has to change for the split
// to light up the moment the server sends it.
export interface DirectionalPoint extends Point {
  // Nil together, and nil means the split was not recorded — never that it was
  // zero. A bucket holding one pre-0011 rollup row cannot be told apart from a
  // bucket that really was all inbound, so neither band is drawn there.
  out_bytes?: number | null
  in_bytes?: number | null
}

export function ThroughputChart({
  points,
  bucketSeconds,
  height = 220,
  direction = 'auto',
  syncGroup,
}: {
  points: DirectionalPoint[]
  bucketSeconds: number | null
  height?: number
  // 'auto' draws the split wherever the series carries one; 'off' keeps the
  // single-series chart for a card too small to read three lines on.
  direction?: 'auto' | 'off'
  // Charts sharing a group share a time cursor. See lib/chartSync.
  syncGroup?: string
}) {
  const el = useRef<HTMLDivElement>(null)
  const plot = useRef<uPlot | null>(null)
  const { resolved } = useTheme()
  const [hoverIdx, setHoverIdx] = useState<number | null>(null)

  // Whether the pointer is over *this* plot. Charts in a sync group all receive
  // a cursor from uPlot, so without this every chart in the group would publish
  // its own rounding of the same hover and they would take turns overwriting
  // each other.
  const hovering = useRef(false)

  const split = useMemo(
    () => direction !== 'off' && points.some((p) => p.out_bytes != null && p.in_bytes != null),
    [points, direction],
  )

  // The floor is what was measured. Under sampling it is a fraction of the
  // truth — the sampler drops packets before the aggregator ever sees them —
  // so drawing it alone understates a flood at exactly the moment the flood is
  // the thing worth seeing. Scaling it up instead would be worse: the result
  // looks like a measurement and is an inference.
  //
  // So both are drawn. Solid is what was counted and is exact as a lower
  // bound; dashed is measured/keep_rate, which under the sampler's 1-in-N
  // stride is the estimate, not a ceiling; the space between them is the part
  // nobody can resolve. Where nothing was captured the value is null and uPlot
  // breaks the line, because a gap in the data has to look like a gap — the
  // old chart joined the points either side with a straight line and invented
  // a plausible three hours of traffic across an outage.
  //
  // The two direction series break on the same principle for a different fact:
  // a bucket that folded in a pre-0011 rollup row knows its total and does not
  // know the split, and a zero-height band there would manufacture the exact
  // distinction the column was added to preserve.
  const data = useMemo<uPlot.AlignedData>(() => {
    const xs: number[] = []
    const floor: (number | null)[] = []
    const estimate: (number | null)[] = []
    const out: (number | null)[] = []
    const inb: (number | null)[] = []
    if (bucketSeconds && bucketSeconds > 0) {
      for (const p of points) {
        xs.push(new Date(p.time).getTime() / 1000)
        if (p.bytes == null) {
          // down or nodata: no measurement exists. Not a zero.
          floor.push(null)
          estimate.push(null)
          out.push(null)
          inb.push(null)
          continue
        }
        // bytes over one bucket → average bits/s across that bucket.
        const bps = (p.bytes * 8) / bucketSeconds
        floor.push(bps)
        estimate.push(
          p.state === 'sampled' && p.keep_rate && p.keep_rate > 0 ? bps / p.keep_rate : null,
        )
        // Both halves or neither. One half alone would be a contract the server
        // does not promise, and half a split rendered as a whole one is the
        // failure directionSum() exists upstream to prevent.
        const known = p.out_bytes != null && p.in_bytes != null
        out.push(known ? (p.out_bytes! * 8) / bucketSeconds : null)
        inb.push(known ? (p.in_bytes! * 8) / bucketSeconds : null)
      }
    }
    return split ? [xs, floor, estimate, out, inb] : [xs, floor, estimate]
  }, [points, bucketSeconds, split])

  useEffect(() => {
    if (!el.current) return
    const cssVar = (name: string) =>
      getComputedStyle(document.documentElement).getPropertyValue(name).trim()

    const accent = cssVar('--accent')
    const grid = cssVar('--chart-grid')
    const muted = cssVar('--muted')
    const outHue = cssVar('--sk-series-out')
    const inHue = cssVar('--sk-series-in')

    // In split mode the total steps back to a hairline: it is context for the
    // two lines that answer the question, and three saturated areas stacked on
    // one axis is a picture nobody can read a number off.
    const totalStroke = split ? muted : accent
    const totalWidth = split ? 1 : 2

    const series: uPlot.Series[] = [
      {},
      {
        label: split ? 'Total' : 'Measured',
        stroke: totalStroke,
        width: totalWidth,
        fill: split ? undefined : fillGradient(accent, resolved),
        points: { show: false },
      },
      {
        label: 'Estimated',
        stroke: totalStroke,
        width: 1,
        dash: [4, 3],
        points: { show: false },
      },
    ]
    if (split) {
      series.push(
        { label: 'Out', stroke: outHue, width: 2, points: { show: false } },
        { label: 'In', stroke: inHue, width: 2, points: { show: false } },
      )
    }

    const opts: uPlot.Options = {
      width: el.current.clientWidth,
      height,
      padding: [12, 8, 4, 8],
      cursor: { y: false, points: { size: 7 }, sync: uplotSync(syncGroup) },
      scales: { x: { time: true } },
      axes: [
        {
          stroke: muted,
          grid: { stroke: grid, width: 1 },
          ticks: { stroke: grid, width: 1 },
          font: '11px "IBM Plex Mono", monospace',
        },
        {
          stroke: muted,
          grid: { stroke: grid, width: 1 },
          ticks: { stroke: grid, width: 1 },
          font: '11px "IBM Plex Mono", monospace',
          size: 48,
          // Compact numbers on the axis; the unit lives in the card subtitle
          // and, now, in the readout above the plot.
          values: (_u, splits) => splits.map((v) => compactNum(v)),
        },
      ],
      series,
      // The unresolved span between what was counted and what the keep rate
      // implies. It appears only where sampling was active, because the
      // estimate series is null everywhere else.
      bands: [
        {
          series: [2, 1],
          fill: hexA(split ? muted : accent, resolved === 'dark' ? 0.16 : 0.12),
        },
      ],
      // uPlot's own legend is a hidden element in this app (index.css sets
      // .u-legend { display: none }) and could not carry what this readout has
      // to carry anyway: the bucket's span, the name of its state, and a value
      // for a series that is null here for a reason worth spelling out. It
      // stays off and the readout below is React.
      legend: { show: false },
      hooks: {
        setCursor: [
          (u) => {
            const i = u.cursor.idx ?? null
            setHoverIdx((prev) => (prev === i ? prev : i))
            if (!hovering.current) return
            const left = u.cursor.left
            publishChartCursor(
              syncGroup,
              left != null && left >= 0 ? u.posToVal(left, 'x') : null,
            )
          },
        ],
        draw: [
          (u) => {
            const { min, max } = u.scales.x
            if (min == null || max == null) return
            publishChartFrame(syncGroup, {
              left: u.over.offsetLeft,
              width: u.over.offsetWidth,
              minX: min,
              maxX: max,
            })
          },
        ],
      },
    }

    plot.current = new uPlot(opts, data, el.current)

    const node = el.current
    const enter = () => {
      hovering.current = true
    }
    const leave = () => {
      hovering.current = false
      setHoverIdx(null)
      publishChartCursor(syncGroup, null)
    }
    node.addEventListener('pointerenter', enter)
    node.addEventListener('pointerleave', leave)

    const ro = new ResizeObserver(() => {
      if (plot.current && node) plot.current.setSize({ width: node.clientWidth, height })
    })
    ro.observe(node)

    return () => {
      ro.disconnect()
      node.removeEventListener('pointerenter', enter)
      node.removeEventListener('pointerleave', leave)
      clearChartFrame(syncGroup)
      plot.current?.destroy()
      plot.current = null
    }
    // Rebuilt only when the picture's shape changes: theme (colors are read out
    // of the cascade), height, series count, sync group. Not on new data —
    // setData below handles that without dropping the cursor.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resolved, height, split, syncGroup])

  useEffect(() => {
    plot.current?.setData(data)
  }, [data])

  // How many buckets carry a measurement but no split. It is counted here
  // rather than read off coverage.direction_unrecorded so the sentence cannot
  // disagree with the lines: both come from the same array.
  const dirNote = useMemo(() => directionNote(points), [points])

  // Which keys the readout carries is a property of the whole series, not of
  // the bucket under the pointer. Deciding per bucket made rows appear and
  // vanish as the cursor moved, which is both a jitter and a lie of omission:
  // the dashed estimate is on the picture somewhere, so it needs naming even
  // while the cursor sits on a bucket that was fully captured.
  const shape = useMemo(() => seriesShape(points), [points])

  if (!bucketSeconds || bucketSeconds <= 0) {
    return (
      <div
        className="flex w-full items-center justify-center text-sm text-[var(--muted)]"
        style={{ minHeight: height }}
      >
        Cannot chart this range — the server reported a bucket size this build does not know.
      </div>
    )
  }

  const hovered = hoverIdx != null ? points[hoverIdx] : undefined

  return (
    <div className="w-full">
      <Readout point={hovered} bucketSeconds={bucketSeconds} split={split} shape={shape} />
      <div ref={el} className="w-full" style={{ minHeight: height }} />
      {dirNote && (
        <p className="px-2 pt-1 text-xs" style={{ color: 'var(--muted)' }}>
          {dirNote}
        </p>
      )}
    </div>
  )
}

// Readout is the live legend: a fixed-height row above the plot naming every
// line, and filling in its value when the cursor is over a bucket.
//
// It is present when idle rather than appearing on hover, for two reasons. Two
// or three series is past the point where a card title can say which mark is
// which, and a row that appears and disappears reflows the chart under the
// pointer that summoned it.
function Readout({
  point,
  bucketSeconds,
  split,
  shape,
}: {
  point: DirectionalPoint | undefined
  bucketSeconds: number
  split: boolean
  shape: SeriesShape
}) {
  const rate = (bytes: number) => formatBits((bytes * 8) / bucketSeconds)
  const totalHue = split ? 'var(--muted)' : 'var(--accent)'
  const keys: { label: string; color: string; dash?: boolean; value: string | null }[] = []

  keys.push({
    label: split ? 'Total' : 'Measured',
    color: totalHue,
    value: point?.bytes != null ? rate(point.bytes) : null,
  })
  if (shape.hasEstimate) {
    const est =
      point?.state === 'sampled' && point.keep_rate && point.bytes != null
        ? `≈ ${formatBits((point.bytes * 8) / bucketSeconds / point.keep_rate)}`
        : null
    keys.push({ label: 'Estimated', color: totalHue, dash: true, value: est })
  }
  if (split) {
    const out = point?.out_bytes
    const inb = point?.in_bytes
    const known = out != null && inb != null
    // The layer-1 token, not the Tailwind namespace: `@theme inline` substitutes
    // --color-series-* into generated utilities and never emits them as custom
    // properties, so var(--color-series-out) resolves to nothing at runtime.
    keys.push({ label: 'Out', color: 'var(--sk-series-out)', value: known ? rate(out) : null })
    keys.push({ label: 'In', color: 'var(--sk-series-in)', value: known ? rate(inb) : null })
    // On the network-wide series the two halves can sum to less than the total:
    // traffic that never crossed the boundary belongs to neither side. Naming
    // the remainder is cheaper than letting the reader discover that the lines
    // do not add up and conclude one of them is wrong.
    if (shape.hasRemainder) {
      const rest = known && point?.bytes != null ? point.bytes - out - inb : null
      keys.push({
        label: 'Neither',
        color: 'var(--sk-series-unknown)',
        value: rest != null ? rate(Math.max(rest, 0)) : null,
      })
    }
  }

  return (
    <div
      className="flex flex-wrap items-center gap-x-4 gap-y-1 px-2 pb-1.5 text-xs"
      style={{ minHeight: '1.75rem' }}
    >
      <span className="font-mono tabnums" style={{ color: 'var(--muted)' }}>
        {point ? bucketSpan(point.time, bucketSeconds) : 'Hover the chart to read a bucket'}
      </span>
      {point && (
        <span style={{ color: point.state === 'measured' ? 'var(--muted)' : 'var(--warn)' }}>
          {stateText(point)}
        </span>
      )}
      <span className="ml-auto flex flex-wrap items-center gap-x-3 gap-y-1">
        {keys.map((k) => (
          <span key={k.label} className="inline-flex items-center gap-1.5 whitespace-nowrap">
            <span
              aria-hidden
              className="inline-block"
              style={{
                width: 10,
                height: k.dash ? 0 : 2,
                borderTop: k.dash ? `2px dashed ${k.color}` : undefined,
                background: k.dash ? undefined : k.color,
              }}
            />
            <span style={{ color: 'var(--muted)' }}>{k.label}</span>
            <span className="tabnums font-medium" style={{ color: 'var(--text)' }}>
              {k.value ?? '—'}
            </span>
          </span>
        ))}
      </span>
    </div>
  )
}

// stateText names what the bucket's numbers mean. Two buckets at the same
// height can mean different things: one counted every packet, the next counted
// a tenth of them, and a third kept its numbers from before Skopos recorded
// whether the capture was complete.
function stateText(p: DirectionalPoint): string {
  switch (p.state) {
    case 'measured':
      return 'measured'
    case 'sampled':
      return p.keep_rate && p.keep_rate > 0
        ? `sampled · 1 in ${Math.round(1 / p.keep_rate)} packets kept — a floor`
        : 'sampled — a floor'
    case 'down':
      return 'capture down — nothing was measured'
    case 'nodata':
      return 'outside recorded history'
    case 'unverified':
      return 'recorded before coverage was tracked'
  }
}

// SeriesShape is which keys the readout carries for the whole window.
interface SeriesShape {
  hasEstimate: boolean
  hasRemainder: boolean
}

function seriesShape(points: DirectionalPoint[]): SeriesShape {
  let hasEstimate = false
  let hasRemainder = false
  for (const p of points) {
    if (p.bytes == null) continue
    if (p.state === 'sampled' && p.keep_rate && p.keep_rate > 0) hasEstimate = true
    if (p.out_bytes != null && p.in_bytes != null) {
      // Half a percent, because a device series sums exactly and a network-wide
      // one does not; below that the difference is the rollup's own rounding
      // rather than local and transit traffic worth a row of its own.
      if (p.bytes - p.out_bytes - p.in_bytes > p.bytes * 0.005) hasRemainder = true
    }
  }
  return { hasEstimate, hasRemainder }
}

// directionNote is the sentence the missing band cannot say for itself.
function directionNote(points: DirectionalPoint[]): string | null {
  let measured = 0
  let withoutSplit = 0
  let sampledSplit = 0
  for (const p of points) {
    if (p.bytes == null) continue
    measured++
    if (p.out_bytes == null || p.in_bytes == null) withoutSplit++
    else if (p.state === 'sampled') sampledSplit++
  }
  const parts: string[] = []
  if (withoutSplit > 0) {
    parts.push(
      withoutSplit === measured
        ? 'Direction was not recorded for this window — these rollups predate the split, so no up/down line is drawn.'
        : `Direction not recorded for ${withoutSplit} of ${measured} measured buckets; the Out and In lines break there rather than reading zero.`,
    )
  }
  if (sampledSplit > 0) {
    parts.push(
      `${sampledSplit} sampled — the ratio between Out and In holds, the two numbers themselves are floors.`,
    )
  }
  return parts.length > 0 ? parts.join(' ') : null
}

// bucketSpan is the window one point covers, not the instant it is drawn at.
// A reader who takes an hourly point for a reading at 14:00 will read a peak
// off it; it is the mean of everything from 14:00 to 15:00.
function bucketSpan(iso: string, seconds: number): string {
  const start = new Date(iso)
  const end = new Date(start.getTime() + seconds * 1000)
  const day: Intl.DateTimeFormatOptions = { month: 'short', day: '2-digit' }
  const clock: Intl.DateTimeFormatOptions = { hour: '2-digit', minute: '2-digit', hour12: false }
  if (seconds >= 86400) {
    return start.toLocaleDateString(undefined, day)
  }
  const sameDay = start.toDateString() === end.toDateString()
  const head = `${start.toLocaleDateString(undefined, day)} ${start.toLocaleTimeString(undefined, clock)}`
  const tail = sameDay
    ? end.toLocaleTimeString(undefined, clock)
    : `${end.toLocaleDateString(undefined, day)} ${end.toLocaleTimeString(undefined, clock)}`
  return `${head}–${tail}`
}

// A soft vertical gradient under the line.
function fillGradient(accent: string, mode: 'light' | 'dark') {
  return (u: uPlot) => {
    const ctx = u.ctx
    const g = ctx.createLinearGradient(0, u.bbox.top, 0, u.bbox.top + u.bbox.height)
    g.addColorStop(0, hexA(accent, mode === 'dark' ? 0.35 : 0.22))
    g.addColorStop(1, hexA(accent, 0))
    return g
  }
}

// compactNum renders a bits/s tick as a short SI-suffixed number (no unit).
function compactNum(v: number): string {
  if (v >= 1e9) return `${(v / 1e9).toFixed(v < 1e10 ? 1 : 0)}G`
  if (v >= 1e6) return `${(v / 1e6).toFixed(v < 1e7 ? 1 : 0)}M`
  if (v >= 1e3) return `${(v / 1e3).toFixed(0)}k`
  return `${Math.round(v)}`
}

function hexA(hex: string, alpha: number): string {
  const h = hex.replace('#', '')
  if (h.length !== 6) return hex
  const r = parseInt(h.slice(0, 2), 16)
  const gg = parseInt(h.slice(2, 4), 16)
  const b = parseInt(h.slice(4, 6), 16)
  return `rgba(${r}, ${gg}, ${b}, ${alpha})`
}
