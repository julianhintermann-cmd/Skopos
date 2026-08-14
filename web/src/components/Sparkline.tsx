import { useMemo, useRef } from 'react'
import { nearestIndex, publishChartCursor, useChartCursor } from '../lib/chartSync'

// A dependency-free SVG sparkline for fast-updating series (the live view
// pushes a new point every second). uPlot is the right tool for the historical
// charts; here a plain path is smoother and far cheaper to re-render at 1 Hz.
//
// Three things this used to get wrong, all of them the same mistake — treating
// the array as the measurement:
//
//   - x was the array index. The live stream reconnects three seconds after a
//     drop and the array simply continues, so three missing seconds were drawn
//     as three adjacent pixels. Pass `times` and x becomes time; the gap is a
//     gap. Index spacing survives only for callers with no clock to offer, and
//     it is a fallback, not a mode to choose.
//   - y renormalised to the series max on every render, with no label. A
//     500 Mbit/s line with 1% jitter and a 10 Mbit/s line with 1% jitter drew
//     the identical sawtooth. The baseline is pinned to zero now and the
//     ceiling is written on the picture, so jitter looks like jitter; `yMax`
//     shares one ceiling across rows so rows can be compared at all.
//   - the SVG was aria-hidden, which is right for decoration and wrong for the
//     only rendering of a measurement on the card.
export function Sparkline({
  values,
  times,
  from,
  to,
  gapMs,
  yMax,
  baseline = 'zero',
  label,
  syncGroup,
  formatValue = compact,
  showScale = true,
  width = 600,
  height = 96,
  stroke = 'var(--accent)',
  fill = 'var(--accent-tint)',
}: {
  // null is "no reading here", and it breaks the path. It is never a zero: a
  // dead capture drawn on the baseline is a quiet network.
  values: (number | null)[]
  // Epoch ms per sample. Same length as values.
  times?: number[]
  // The window the row covers, epoch ms. Without these the line is scaled to
  // its own first and last sample, so a row that stopped reporting early looks
  // like a row that reported all the way across.
  from?: number
  to?: number
  // The cadence the caller expects, in ms. A step longer than this is a hole
  // and gets hatched. Omitted means the series is irregular by nature (manual
  // speed tests among scheduled ones) and no cadence may be assumed.
  gapMs?: number
  // A ceiling shared across sibling rows. Without it each row scales to itself
  // and a 2 KiB/h device draws the same picture as a 2 GiB/h one.
  yMax?: number
  baseline?: 'zero' | 'auto'
  label?: string
  syncGroup?: string
  formatValue?: (v: number) => string
  showScale?: boolean
  width?: number
  height?: number
  stroke?: string
  fill?: string
}) {
  const host = useRef<HTMLDivElement>(null)

  const geom = useMemo(() => {
    const pad = 3
    const h = height
    const n = values.length

    let lo = 0
    let hi = -Infinity
    let any = false
    let min = Infinity
    for (const v of values) {
      if (v == null) continue
      any = true
      if (v > hi) hi = v
      if (v < min) min = v
    }
    if (!any) return null
    if (baseline === 'auto') lo = min
    let top = yMax ?? hi
    // A flat series of measured zeros still has to draw its line on the
    // baseline rather than divide by zero into NaN.
    if (!(top > lo)) top = lo + 1

    // x0/x1 bound the drawing. With times the row is placed on a clock; without
    // them the index is all there is, and the caller is told so in the label.
    const timed = times != null && times.length === n && n > 0
    const x0 = timed ? (from ?? times![0]) : 0
    const x1 = timed ? (to ?? times![n - 1]) : n - 1
    const spanX = x1 - x0 || 1
    const at = (i: number) => (timed ? (times![i] - x0) / spanX : n > 1 ? i / (n - 1) : 0)
    const px = (f: number) => pad + f * (width - pad * 2)
    const py = (v: number) => h - pad - ((v - lo) / (top - lo)) * (h - pad * 2)

    // Segments break on a null and, when a cadence was declared, on a step
    // longer than that cadence. Both are the same rule: no mark may span two
    // samples that are not adjacent in time.
    type Seg = { d: string; first: number; last: number }
    const segs: Seg[] = []
    const holes: { a: number; b: number }[] = []
    let cur: string[] = []
    let firstI = -1
    let lastI = -1
    const flush = () => {
      if (cur.length > 0 && firstI >= 0) segs.push({ d: cur.join(' '), first: firstI, last: lastI })
      cur = []
      firstI = -1
      lastI = -1
    }
    for (let i = 0; i < n; i++) {
      const v = values[i]
      if (v == null) {
        if (lastI >= 0) holes.push({ a: at(lastI), b: at(nextKnown(values, i)) })
        flush()
        continue
      }
      if (timed && gapMs != null && lastI >= 0 && times![i] - times![lastI] > gapMs) {
        holes.push({ a: at(lastI), b: at(i) })
        flush()
      }
      cur.push(`${cur.length === 0 ? 'M' : 'L'}${px(at(i)).toFixed(1)},${py(v).toFixed(1)}`)
      if (firstI < 0) firstI = i
      lastI = i
    }
    flush()

    // A run of nulls before the first reading is a hole like any other. The
    // loop cannot see it — it only breaks a segment that had started — and
    // leaving it blank draws a row that began reporting late as one that was
    // simply narrower.
    const firstKnown = values.findIndex((v) => v != null)
    if (firstKnown > 0) holes.unshift({ a: at(0), b: at(firstKnown) })

    const areas = segs
      .filter((s) => s.first !== s.last)
      .map(
        (s) =>
          `${s.d} L${px(at(s.last)).toFixed(1)},${h - pad} L${px(at(s.first)).toFixed(1)},${h - pad} Z`,
      )
    // A lone sample has no line to draw, so it is drawn as a dot. The old code
    // rendered nothing at all, which is indistinguishable from no data.
    const dots = segs.filter((s) => s.first === s.last).map((s) => ({ x: px(at(s.first)), y: py(values[s.first]!) }))

    return { segs, areas, dots, holes, top, lo, x0, x1, timed, at, px, py, pad }
  }, [values, times, from, to, gapMs, yMax, baseline, width, height])

  // Only a timed row can take part in a shared cursor: a cursor is a moment,
  // and a row plotted against its own index has no opinion about moments.
  const cursorT = useChartCursor(geom?.timed ? syncGroup : undefined)
  const hover = useMemo(() => {
    if (!geom || !geom.timed || cursorT == null || !times) return null
    const ms = cursorT * 1000
    if (ms < geom.x0 || ms > geom.x1) return null
    const tol = gapMs ?? (geom.x1 - geom.x0) / Math.max(values.length - 1, 1)
    const i = nearestIndex(times, ms, tol)
    return { frac: (ms - geom.x0) / (geom.x1 - geom.x0 || 1), value: i >= 0 ? values[i] : null }
  }, [geom, cursorT, times, values, gapMs])

  const onMove = (e: { clientX: number }) => {
    if (!syncGroup || !geom?.timed || !host.current) return
    const r = host.current.getBoundingClientRect()
    if (r.width === 0) return
    const frac = (e.clientX - r.left) / r.width
    publishChartCursor(syncGroup, (geom.x0 + frac * (geom.x1 - geom.x0)) / 1000)
  }

  const described =
    label ??
    (geom
      ? `Sparkline, ${values.length} readings, peak ${formatValue(geom.top)}${geom.timed ? '' : ', evenly spaced by reading rather than by time'}`
      : 'Sparkline, no readings')

  return (
    <div
      ref={host}
      className="relative w-full"
      style={{ height }}
      onPointerMove={onMove}
      onPointerLeave={() => publishChartCursor(syncGroup, null)}
    >
      {/* No reading is not a zero. The hatch has no baseline and no height, so
          it cannot be read as a magnitude the way a flat line can. */}
      {geom?.holes.map((g, i) => (
        <div
          key={i}
          className="sk-nodata absolute top-0 bottom-0"
          style={{ left: `${g.a * 100}%`, width: `${Math.max(g.b - g.a, 0) * 100}%` }}
        />
      ))}

      <svg
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        className="relative w-full"
        style={{ height, display: 'block' }}
        role="img"
        aria-label={described}
      >
        {geom?.areas.map((d, i) => (
          <path key={`a${i}`} d={d} fill={fill} opacity={0.5} />
        ))}
        {geom?.segs.map((s, i) => (
          <path
            key={`l${i}`}
            d={s.d}
            fill="none"
            stroke={stroke}
            strokeWidth={2}
            strokeLinejoin="round"
            strokeLinecap="round"
            vectorEffect="non-scaling-stroke"
          />
        ))}
        {geom?.dots.map((p, i) => (
          <circle key={`d${i}`} cx={p.x} cy={p.y} r={2.5} fill={stroke} vectorEffect="non-scaling-stroke" />
        ))}
      </svg>

      {/* The ceiling in words. Without it the shape is all there is, and every
          shape looks the same. */}
      {geom && showScale && height >= 48 && (
        <>
          <span
            className="tabnums pointer-events-none absolute top-0 right-0 font-mono text-[0.62rem]"
            style={{ color: 'var(--muted)' }}
          >
            {formatValue(geom.top)}
            {yMax != null ? ' max (shared)' : ''}
          </span>
          <span
            className="tabnums pointer-events-none absolute right-0 bottom-0 font-mono text-[0.62rem]"
            style={{ color: 'var(--muted)' }}
          >
            {baseline === 'zero' ? formatValue(0) : formatValue(geom.lo)}
          </span>
        </>
      )}

      {hover && (
        <div
          className="pointer-events-none absolute top-0 bottom-0"
          style={{ left: `${hover.frac * 100}%`, width: 1, background: 'var(--border-strong)' }}
        >
          {hover.value != null && (
            <span
              className="tabnums absolute -top-0.5 left-1 font-mono text-[0.62rem] whitespace-nowrap"
              style={{ color: 'var(--text)' }}
            >
              {formatValue(hover.value)}
            </span>
          )}
        </div>
      )}
    </div>
  )
}

function nextKnown(values: (number | null)[], from: number): number {
  for (let i = from; i < values.length; i++) if (values[i] != null) return i
  return values.length - 1
}

// A short SI number with no unit, matching the axis convention of the uPlot
// charts: the unit lives in the card subtitle, which is the only place it can
// be stated once for a whole card.
function compact(v: number): string {
  const a = Math.abs(v)
  if (a >= 1e9) return `${(v / 1e9).toFixed(a < 1e10 ? 1 : 0)}G`
  if (a >= 1e6) return `${(v / 1e6).toFixed(a < 1e7 ? 1 : 0)}M`
  if (a >= 1e3) return `${(v / 1e3).toFixed(0)}k`
  return `${Math.round(v)}`
}
