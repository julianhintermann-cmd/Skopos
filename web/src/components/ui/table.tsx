import type { ReactNode } from 'react'

// Table owns its own row dividers. Nineteen inline
// `style={{ borderTop: '1px solid var(--border)' }}` declarations existed
// across the views, applied per-cell in some tables and per-row in others,
// which is why no two tables lined up.
export function Table({
  children,
  dense,
  className = '',
}: {
  children: ReactNode
  dense?: boolean
  className?: string
}) {
  return (
    <div className="overflow-x-auto">
      <table
        className={`w-full border-collapse text-sm [&_tbody_tr]:border-t [&_tbody_tr]:border-line ${
          dense ? '[&_td]:py-1 [&_th]:py-1' : ''
        } ${className}`}
      >
        {children}
      </table>
    </div>
  )
}

export function Th({
  children,
  align = 'left',
  width,
}: {
  children: ReactNode
  align?: 'left' | 'right'
  width?: string
}) {
  return (
    <th
      style={width ? { width } : undefined}
      className={`px-4 py-2 font-mono text-label uppercase text-fg-muted ${
        align === 'right' ? 'text-right' : 'text-left'
      }`}
    >
      {children}
    </th>
  )
}

export function Td({
  children,
  mono,
  muted,
  align = 'left',
  sub,
}: {
  children: ReactNode
  mono?: boolean
  muted?: boolean
  align?: 'left' | 'right'
  // The two-line cell — a value and its qualifier — written out often enough
  // by hand that the second line kept drifting between text-xs and text-[11px].
  sub?: ReactNode
}) {
  return (
    <td
      className={`px-4 py-2 align-top ${align === 'right' ? 'text-right' : ''} ${
        mono ? 'font-mono text-xs' : ''
      } ${muted ? 'text-fg-muted' : ''}`}
    >
      {children}
      {sub && <div className="text-xs text-fg-muted">{sub}</div>}
    </td>
  )
}
