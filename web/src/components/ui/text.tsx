import type { ReactNode } from 'react'

// NoData is the zero-fake-data primitive.
//
// Eight sites rendered `—` for "we do not know". An em-dash is a glyph in the
// slot where a value goes: it looks like formatting, it is unreadable to a
// screen reader, and it says nothing about why the value is missing. This
// renders the reason in words instead.
//
// `reason` is required, and deliberately so: if you cannot say why the data is
// missing, you do not yet understand the state you are rendering.
export function NoData({ reason, inline }: { reason: string; inline?: boolean }) {
  return (
    <span className={`italic text-fg-muted ${inline ? '' : 'text-xs'}`}>{reason}</span>
  )
}

// The eyebrow, once. Twenty verbatim copies of
// `font-mono text-[0.62rem] font-semibold uppercase tracking-[0.1em]` existed,
// at four different sizes, none of which was deliberate.
export function Label({
  children,
  as = 'span',
  className = '',
}: {
  children: ReactNode
  as?: 'span' | 'div' | 'th'
  className?: string
}) {
  const cls = `font-mono text-label uppercase text-fg-muted ${className}`
  if (as === 'div') return <div className={cls}>{children}</div>
  if (as === 'th') return <th className={cls}>{children}</th>
  return <span className={cls}>{children}</span>
}

// Inline code: addresses, interface names, nft expressions.
export function Code({ children }: { children: ReactNode }) {
  return <code className="rounded-sm bg-raised px-1 py-0.5 font-mono text-xs">{children}</code>
}

// StaleBadge finally consumes useFetch's `stale` flag, which had no readers at
// all across ~20 call sites. Without it a view could only hide a failed poll or
// blank the screen, and nearly all of them hid it — so the last good numbers
// stayed on screen looking current.
export function StaleBadge({ since, error }: { since?: string; error?: string }) {
  return (
    <span
      className="inline-flex items-center gap-1 rounded-full bg-unknown-quiet px-2 py-0.5 text-label uppercase text-unknown"
      title={error ? `The last update failed: ${error}` : 'The last update attempt failed.'}
    >
      <span aria-hidden className="font-mono">↺</span>
      {since ? `as of ${since}` : 'not updating'}
    </span>
  )
}
