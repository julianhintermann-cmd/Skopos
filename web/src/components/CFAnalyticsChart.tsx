import { useEffect, useMemo, useRef, useState } from 'react'
import uPlot from 'uplot'
import 'uplot/dist/uPlot.min.css'
import type { CFPoint } from '../lib/api'
import { useTheme } from '../lib/theme'
import { formatCount } from '../lib/format'
import { clearChartFrame, publishChartCursor, publishChartFrame, uplotSync } from '../lib/chartSync'

// Requests over time for one Cloudflare zone: total requests as a teal area,
// cached requests as a recessive dashed line on top, so the gap between them
// reads as "served from origin".
export function CFAnalyticsChart({
  points,
  height = 260,
  syncGroup,
}: {
  points: CFPoint[]
  height?: number
  syncGroup?: string
}) {
  const el = useRef<HTMLDivElement>(null)
  const plot = useRef<uPlot | null>(null)
  const { resolved } = useTheme()
  const [hoverIdx, setHoverIdx] = useState<number | null>(null)
  const hovering = useRef(false)

  // Cloudflare's httpRequests1hGroups omits an hour it has nothing to say
  // about, so consecutive array entries are not consecutive hours and joining
  // them drew a straight line across the hole — the same invention the
  // throughput chart was rebuilt to stop making.
  //
  // The grid step is measured, not assumed: the smallest gap between reported
  // hours is the grid, because a reported pair one slot apart is the only pair
  // that can be. Absent slots become null rather than zero. A zero here would
  // be a claim about Cloudflare's traffic made by this component, and the two
  // reasons an hour can be missing — no requests, or outside what the plan's
  // retention returned — are not distinguishable from the client.
  const grid = useMemo(() => buildGrid(points), [points])

  const data = useMemo<uPlot.AlignedData>(
    () => [grid.xs, grid.total, grid.cached],
    [grid],
  )

  useEffect(() => {
    if (!el.current) return
    const cssVar = (name: string) => getComputedStyle(document.documentElement).getPropertyValue(name).trim()
    const accent = cssVar('--accent')
    const gridColor = cssVar('--chart-grid')
    const muted = cssVar('--muted')

    const opts: uPlot.Options = {
      width: el.current.clientWidth,
      height,
      padding: [12, 8, 4, 8],
      cursor: { y: false, points: { size: 7 }, sync: uplotSync(syncGroup) },
      scales: { x: { time: true } },
      axes: [
        { stroke: muted, grid: { stroke: gridColor, width: 1 }, ticks: { stroke: gridColor, width: 1 }, font: '11px "IBM Plex Mono", monospace' },
        {
          stroke: muted,
          grid: { stroke: gridColor, width: 1 },
          ticks: { stroke: gridColor, width: 1 },
          font: '11px "IBM Plex Mono", monospace',
          size: 48,
          values: (_u, splits) => splits.map((v) => compact(v)),
        },
      ],
      series: [
        {},
        {
          label: 'Requests',
          stroke: accent,
          width: 2,
          fill: fillGradient(accent, resolved),
          points: { show: false },
        },
        {
          label: 'Cached',
          stroke: muted,
          width: 1.5,
          dash: [4, 3],
          points: { show: false },
        },
      ],
      // Hidden globally by index.css, and too coarse for what the readout has
      // to say. The readout below is React.
      legend: { show: false },
      hooks: {
        setCursor: [
          (u) => {
            const i = u.cursor.idx ?? null
            setHoverIdx((prev) => (prev === i ? prev : i))
            if (!hovering.current) return
            const left = u.cursor.left
            publishChartCursor(syncGroup, left != null && left >= 0 ? u.posToVal(left, 'x') : null)
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resolved, height, syncGroup])

  useEffect(() => {
    plot.current?.setData(data)
  }, [data])

  const missing = grid.total.filter((v) => v == null).length

  return (
    <div className="w-full">
      <Readout grid={grid} idx={hoverIdx} />
      <div ref={el} className="w-full" style={{ minHeight: height }} />
      {missing > 0 && (
        <p className="px-2 pt-1 text-xs" style={{ color: 'var(--muted)' }}>
          {missing} {missing === 1 ? 'hour' : 'hours'} in this window came back with no figures at
          all. The line breaks there — Cloudflare does not distinguish an hour with no requests
          from an hour outside what the plan retains.
        </p>
      )}
    </div>
  )
}

function Readout({ grid, idx }: { grid: Grid; idx: number | null }) {
  const at = idx != null ? idx : -1
  const total = at >= 0 ? grid.total[at] : null
  const cached = at >= 0 ? grid.cached[at] : null
  const known = at >= 0 && total != null && cached != null

  const rows: { label: string; color?: string; dash?: boolean; value: string }[] = [
    { label: 'Requests', color: 'var(--accent)', value: total != null ? formatCount(total) : '—' },
    { label: 'Cached', color: 'var(--muted)', dash: true, value: cached != null ? formatCount(cached) : '—' },
    { label: 'From origin', value: known ? formatCount(Math.max(total - cached, 0)) : '—' },
  ]

  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 px-2 pb-1.5 text-xs" style={{ minHeight: '1.75rem' }}>
      <span className="tabnums font-mono" style={{ color: 'var(--muted)' }}>
        {at >= 0 ? slotSpan(grid.xs[at], grid.stepSeconds) : 'Hover the chart to read an hour'}
      </span>
      {at >= 0 && total == null && (
        <span style={{ color: 'var(--warn)' }}>no figures returned for this hour</span>
      )}
      <span className="ml-auto flex flex-wrap items-center gap-x-3 gap-y-1">
        {rows.map((r) => (
          <span key={r.label} className="inline-flex items-center gap-1.5 whitespace-nowrap">
            {r.color && (
              <span
                aria-hidden
                className="inline-block"
                style={{
                  width: 10,
                  height: r.dash ? 0 : 2,
                  borderTop: r.dash ? `2px dashed ${r.color}` : undefined,
                  background: r.dash ? undefined : r.color,
                }}
              />
            )}
            <span style={{ color: 'var(--muted)' }}>{r.label}</span>
            <span className="tabnums font-medium" style={{ color: 'var(--text)' }}>
              {r.value}
            </span>
          </span>
        ))}
      </span>
    </div>
  )
}

interface Grid {
  xs: number[]
  total: (number | null)[]
  cached: (number | null)[]
  stepSeconds: number | null
}

function buildGrid(points: CFPoint[]): Grid {
  const xs: number[] = []
  const total: (number | null)[] = []
  const cached: (number | null)[] = []
  if (points.length === 0) return { xs, total, cached, stepSeconds: null }

  const ts = points.map((p) => new Date(p.time).getTime() / 1000)
  let step = Infinity
  for (let i = 1; i < ts.length; i++) {
    const d = ts[i] - ts[i - 1]
    if (d > 0 && d < step) step = d
  }
  const stepSeconds = Number.isFinite(step) ? step : null

  for (let i = 0; i < points.length; i++) {
    if (stepSeconds != null && i > 0) {
      // Every whole slot the payload skipped, as an explicit hole. The 1.5
      // tolerance keeps a clock that drifts a few seconds from manufacturing
      // one.
      for (let t = ts[i - 1] + stepSeconds; t < ts[i] - stepSeconds * 0.5; t += stepSeconds) {
        xs.push(t)
        total.push(null)
        cached.push(null)
      }
    }
    xs.push(ts[i])
    total.push(points[i].requests)
    cached.push(points[i].cached_requests)
  }
  return { xs, total, cached, stepSeconds }
}

// The slot a point covers. An hourly figure stamped 14:00 is everything up to
// 15:00, and reading it as a level at 14:00 overstates a spike.
function slotSpan(seconds: number, step: number | null): string {
  const start = new Date(seconds * 1000)
  const day: Intl.DateTimeFormatOptions = { month: 'short', day: '2-digit' }
  const clock: Intl.DateTimeFormatOptions = { hour: '2-digit', minute: '2-digit', hour12: false }
  const head = `${start.toLocaleDateString(undefined, day)} ${start.toLocaleTimeString(undefined, clock)}`
  if (step == null) return head
  const end = new Date((seconds + step) * 1000)
  return `${head}–${end.toLocaleTimeString(undefined, clock)}`
}

function fillGradient(accent: string, mode: 'light' | 'dark') {
  return (u: uPlot) => {
    const ctx = u.ctx
    const g = ctx.createLinearGradient(0, u.bbox.top, 0, u.bbox.top + u.bbox.height)
    g.addColorStop(0, hexA(accent, mode === 'dark' ? 0.35 : 0.22))
    g.addColorStop(1, hexA(accent, 0))
    return g
  }
}

function compact(v: number): string {
  if (v >= 1e9) return `${(v / 1e9).toFixed(v < 1e10 ? 1 : 0)}G`
  if (v >= 1e6) return `${(v / 1e6).toFixed(v < 1e7 ? 1 : 0)}M`
  if (v >= 1e3) return `${(v / 1e3).toFixed(0)}k`
  return `${Math.round(v)}`
}

function hexA(hex: string, alpha: number): string {
  const h = hex.replace('#', '')
  if (h.length !== 6) return hex
  const r = parseInt(h.slice(0, 2), 16)
  const g = parseInt(h.slice(2, 4), 16)
  const b = parseInt(h.slice(4, 6), 16)
  return `rgba(${r}, ${g}, ${b}, ${alpha})`
}
