import type { ReactNode } from 'react'

// Card owns the surface, the border and the elevation. `pad` defaults to none
// because most cards hold a table or a list that must bleed to the edge; the
// padded variants exist so a caller stops hand-writing `px-4 py-3`.
export function Card({
  children,
  pad = 'none',
  as = 'div',
  href,
  className = '',
}: {
  children: ReactNode
  pad?: 'none' | 'tight' | 'default'
  as?: 'div' | 'section' | 'a'
  href?: string
  className?: string
}) {
  const padding = pad === 'tight' ? 'p-3' : pad === 'default' ? 'p-4' : ''
  const base = `rounded-lg border border-line bg-surface shadow-card ${padding} ${className}`

  if (as === 'a' && href) {
    // Cards are opaque, so the translucent --sk-hover overlay would composite
    // against the canvas rather than the card. A whole-card link announces
    // itself with its edge instead.
    return (
      <a href={href} className={`block transition-colors hover:border-line-strong ${base}`}>
        {children}
      </a>
    )
  }
  if (as === 'section') return <section className={base}>{children}</section>
  return <div className={base}>{children}</div>
}

export function CardHeader({
  title,
  sub,
  right,
  level = 2,
}: {
  title: ReactNode
  sub?: ReactNode
  right?: ReactNode
  level?: 2 | 3
}) {
  // text-lg carries its own negative tracking from the type scale, so there is
  // no tracking-tight here to double up on it.
  const heading =
    level === 3 ? (
      <h3 className="text-lg font-semibold">{title}</h3>
    ) : (
      <h2 className="text-lg font-semibold">{title}</h2>
    )
  return (
    <div className="flex items-baseline justify-between gap-3 px-4 pt-3.5 pb-2">
      <div className="min-w-0">
        {heading}
        {sub && <p className="text-xs text-fg-muted">{sub}</p>}
      </div>
      {right}
    </div>
  )
}

export function Divider({ className = '' }: { className?: string }) {
  return <div role="separator" className={`h-px bg-line ${className}`} />
}
