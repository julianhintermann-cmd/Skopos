import { useEffect, useMemo, useRef } from 'react'
import uPlot from 'uplot'
import 'uplot/dist/uPlot.min.css'
import type { CFPoint } from '../lib/api'
import { useTheme } from '../lib/theme'
import { formatCount } from '../lib/format'

// Requests over time for one Cloudflare zone: total requests as a teal area,
// cached requests as a recessive line on top, so the gap between them reads as
// "served from origin". Two series → the card title names them; no legend box.
export function CFAnalyticsChart({ points, height = 260 }: { points: CFPoint[]; height?: number }) {
  const el = useRef<HTMLDivElement>(null)
  const plot = useRef<uPlot | null>(null)
  const { resolved } = useTheme()

  const data = useMemo<uPlot.AlignedData>(() => {
    const xs: number[] = []
    const total: number[] = []
    const cached: number[] = []
    for (const p of points) {
      xs.push(new Date(p.time).getTime() / 1000)
      total.push(p.requests)
      cached.push(p.cached_requests)
    }
    return [xs, total, cached]
  }, [points])

  useEffect(() => {
    if (!el.current) return
    const cssVar = (name: string) => getComputedStyle(document.documentElement).getPropertyValue(name).trim()
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
        { stroke: muted, grid: { stroke: grid, width: 1 }, ticks: { stroke: grid, width: 1 }, font: '11px "IBM Plex Mono", monospace' },
        {
          stroke: muted,
          grid: { stroke: grid, width: 1 },
          ticks: { stroke: grid, width: 1 },
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
          value: (_u, v) => (v == null ? '—' : formatCount(v)),
        },
        {
          label: 'Cached',
          stroke: muted,
          width: 1.5,
          dash: [4, 3],
          points: { show: false },
          value: (_u, v) => (v == null ? '—' : formatCount(v)),
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resolved, height])

  useEffect(() => {
    plot.current?.setData(data)
  }, [data])

  return <div ref={el} className="w-full" style={{ minHeight: height }} />
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
