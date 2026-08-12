import { useMemo } from 'react'

// A dependency-free SVG sparkline for fast-updating series (the live view
// pushes a new point every second). uPlot is the right tool for the historical
// charts; here a plain path is smoother and far cheaper to re-render at 1 Hz.
export function Sparkline({
  values,
  width = 600,
  height = 96,
  stroke = 'var(--accent)',
  fill = 'var(--accent-tint)',
}: {
  values: number[]
  width?: number
  height?: number
  stroke?: string
  fill?: string
}) {
  const { line, area } = useMemo(() => {
    if (values.length < 2) return { line: '', area: '' }
    const max = Math.max(...values, 1)
    const pad = 3
    const w = width
    const h = height
    const stepX = (w - pad * 2) / (values.length - 1)
    const y = (v: number) => h - pad - (v / max) * (h - pad * 2)
    const pts = values.map((v, i) => [pad + i * stepX, y(v)] as const)
    const line = pts.map(([x, yy], i) => `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${yy.toFixed(1)}`).join(' ')
    const area = `${line} L${pts[pts.length - 1][0].toFixed(1)},${h - pad} L${pts[0][0].toFixed(1)},${h - pad} Z`
    return { line, area }
  }, [values, width, height])

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      className="w-full"
      style={{ height, display: 'block' }}
      aria-hidden
    >
      {area && <path d={area} fill={fill} opacity={0.5} />}
      {line && <path d={line} fill="none" stroke={stroke} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />}
    </svg>
  )
}
