import { useEffect, useMemo, useRef } from 'react'
import uPlot from 'uplot'
import 'uplot/dist/uPlot.min.css'
import type { TimePoint } from '../lib/api'
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
  points: TimePoint[]
  bucketSeconds: number | null
  height?: number
}) {
  const el = useRef<HTMLDivElement>(null)
  const plot = useRef<uPlot | null>(null)
  const { resolved } = useTheme()

  const data = useMemo<uPlot.AlignedData>(() => {
    const xs: number[] = []
    const ys: number[] = []
    if (bucketSeconds && bucketSeconds > 0) {
      for (const p of points) {
        xs.push(new Date(p.time).getTime() / 1000)
        // bytes over one bucket → average bits/s across that bucket.
        ys.push((p.bytes * 8) / bucketSeconds)
      }
    }
    return [xs, ys]
  }, [points, bucketSeconds])

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
          label: 'Throughput',
          stroke: accent,
          width: 2,
          fill: fillGradient(accent, resolved),
          points: { show: false },
          value: (_u, v) => (v == null ? '—' : formatBits(v)),
        },
      ],
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
  }, [resolved, height])

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
