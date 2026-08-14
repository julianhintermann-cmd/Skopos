import { useEffect, useMemo, useRef } from 'react'
import uPlot from 'uplot'
import 'uplot/dist/uPlot.min.css'
import type { Point } from '../lib/contracts'
import { formatBits } from '../lib/format'
import { useTheme } from '../lib/theme'

// A single-series throughput chart: bits/s over time, teal area on a recessive
// grid, with a crosshair + tooltip. One series → no legend box; the card title
// names it (per the dataviz method).
//
// bucketSeconds is how much time one point covers, and it is required rather
// than assumed: the server picks the rollup resolution per request, so a
// hardcoded divisor silently overstates the rate by 60x as soon as the range
// crosses into hourly buckets. Pass null when the resolution is unknown and
// the chart declines to draw instead of scaling by a guess.
export function ThroughputChart({
  points,
  bucketSeconds,
  height = 220,
}: {
  points: Point[]
  bucketSeconds: number | null
  height?: number
}) {
  const el = useRef<HTMLDivElement>(null)
  const plot = useRef<uPlot | null>(null)
  const { resolved } = useTheme()

  // Two series, and the second one is the point of this component.
  //
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
  const data = useMemo<uPlot.AlignedData>(() => {
    const xs: number[] = []
    const floor: (number | null)[] = []
    const estimate: (number | null)[] = []
    if (bucketSeconds && bucketSeconds > 0) {
      for (const p of points) {
        xs.push(new Date(p.time).getTime() / 1000)
        if (p.bytes == null) {
          // down or nodata: no measurement exists. Not a zero.
          floor.push(null)
          estimate.push(null)
          continue
        }
        // bytes over one bucket → average bits/s across that bucket.
        const bps = (p.bytes * 8) / bucketSeconds
        floor.push(bps)
        estimate.push(
          p.state === 'sampled' && p.keep_rate && p.keep_rate > 0 ? bps / p.keep_rate : null,
        )
      }
    }
    return [xs, floor, estimate]
  }, [points, bucketSeconds])

  // The tooltip has to name the state, because two buckets at the same height
  // can mean different things: one counted every packet, the next counted a
  // tenth of them, and a third kept its numbers from before Skopos recorded
  // whether the capture was complete.
  const states = useMemo(() => points.map((p) => p.state), [points])
  const rates = useMemo(() => points.map((p) => p.keep_rate), [points])

  useEffect(() => {
    if (!el.current) return
    const cssVar = (name: string) =>
      getComputedStyle(document.documentElement).getPropertyValue(name).trim()

    const accent = cssVar('--accent')
    const grid = cssVar('--chart-grid')
    const muted = cssVar('--muted')

    const opts: uPlot.Options = {
      width: el.current.clientWidth,
      height,
      padding: [12, 8, 4, 8],
      cursor: { y: false, points: { size: 7 } },
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
          // Compact numbers on the axis; the unit lives in the card subtitle.
          values: (_u, splits) => splits.map((v) => compactNum(v)),
        },
      ],
      series: [
        {},
        {
          label: 'Measured',
          stroke: accent,
          width: 2,
          fill: fillGradient(accent, resolved),
          points: { show: false },
          value: (u, v) => {
            const i = u.cursor.idx
            if (v == null) {
              return i != null && states[i] === 'down' ? 'capture down' : 'not recorded'
            }
            if (i == null) return formatBits(v)
            const rate = rates[i]
            if (states[i] === 'sampled' && rate) {
              return `${formatBits(v)} counted (1 in ${Math.round(1 / rate)} kept)`
            }
            if (states[i] === 'unverified') return `${formatBits(v)} · coverage not recorded`
            return formatBits(v)
          },
        },
        {
          label: 'Estimated',
          stroke: accent,
          width: 1,
          dash: [4, 3],
          points: { show: false },
          value: (_u, v) => (v == null ? '' : `≈ ${formatBits(v)} before sampling`),
        },
      ],
      // The unresolved span between what was counted and what the keep rate
      // implies. It appears only where sampling was active, because the
      // estimate series is null everywhere else.
      bands: [{ series: [2, 1], fill: hexA(accent, resolved === 'dark' ? 0.16 : 0.12) }],
      legend: { show: false },
    }

    plot.current = new uPlot(opts, data, el.current)

    const ro = new ResizeObserver(() => {
      if (plot.current && el.current) plot.current.setSize({ width: el.current.clientWidth, height })
    })
    ro.observe(el.current)

    return () => {
      ro.disconnect()
      plot.current?.destroy()
      plot.current = null
    }
    // Recreate on theme change so colors update.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resolved, height, states, rates])

  useEffect(() => {
    plot.current?.setData(data)
  }, [data])

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

  return <div ref={el} className="w-full" style={{ minHeight: height }} />
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
