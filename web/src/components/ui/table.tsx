import { useEffect, useRef, useState, type ReactNode } from 'react'

// ScrollArea is a horizontally scrolling region that admits it.
//
// `overflow-x-auto` on a touch screen paints no scrollbar at all, so the
// Firewall blocks table hid 42% of every row and the System audit table 49%,
// silently — and inside the Firewall's 42% was the Unblock button, the only
// undo for a block. A table that hides part of a row without saying so is the
// same class of lie as a number that is not measured.
//
// It measures rather than guesses, so it stays silent when the table fits:
// DeviceDetail's ports table needs no warning and must not get one.
export function ScrollArea({
  label,
  children,
  className = '',
}: {
  // What is scrolling, for the region's accessible name: "Active blocks".
  label: string
  children: ReactNode
  className?: string
}) {
  const ref = useRef<HTMLDivElement>(null)
  const [offscreen, setOffscreen] = useState(0)
  const [atEnd, setAtEnd] = useState(true)

  useEffect(() => {
    const el = ref.current
    if (!el) return
    const measure = () => {
      const over = el.scrollWidth - el.clientWidth
      setOffscreen(el.scrollWidth > 0 ? Math.max(0, over) / el.scrollWidth : 0)
      setAtEnd(over - el.scrollLeft <= 1)
    }
    measure()
    const ro = new ResizeObserver(measure)
    ro.observe(el)
    // The wrapper's own box does not change when a poll adds rows, so the
    // table itself has to be watched too or the hint goes stale.
    if (el.firstElementChild) ro.observe(el.firstElementChild)
    el.addEventListener('scroll', measure, { passive: true })
    return () => {
      ro.disconnect()
      el.removeEventListener('scroll', measure)
    }
  }, [])

  // Below 2% is sub-pixel rounding, not a hidden column.
  const clipped = offscreen >= 0.02
  const pct = Math.round(offscreen * 100)

  return (
    <div className={`relative ${className}`}>
      {clipped && (
        <p className="px-4 pb-1.5 text-xs text-fg-muted">
          {pct}% of each row is past the right edge — scroll sideways to reach it.
        </p>
      )}
      <div
        ref={ref}
        className="overflow-x-auto"
        // A scroll container is only reachable by keyboard if something in it
        // can hold focus, and a table of text has nothing. Tabbable only while
        // there is somewhere to scroll to.
        tabIndex={clipped ? 0 : undefined}
        role={clipped ? 'region' : undefined}
        aria-label={clipped ? `${label} — scrolls horizontally` : undefined}
      >
        {children}
      </div>
      {clipped && !atEnd && (
        <div
          aria-hidden
          className="pointer-events-none absolute bottom-0 right-0 top-0 w-8"
          style={{ background: 'linear-gradient(to left, var(--surface), transparent)' }}
        />
      )}
    </div>
  )
}

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
    <ScrollArea label="Table">
      <table
        className={`w-full border-collapse text-sm [&_tbody_tr]:border-t [&_tbody_tr]:border-line ${
          dense ? '[&_td]:py-1 [&_th]:py-1' : ''
        } ${className}`}
      >
        {children}
      </table>
    </ScrollArea>
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
