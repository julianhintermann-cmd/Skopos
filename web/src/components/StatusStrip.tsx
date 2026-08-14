import { Link } from 'react-router-dom'
import { useStatus, toneColor, type Chip } from '../lib/status'

// The persistent status strip: capture, enforcement, outstanding — on every
// page, in both shells. (The phone renders the same three states as dots in
// mobile.tsx; the model behind both is lib/status.ts.)
//
// It replaces a single pill that read `me.enforcing` once at login and then
// claimed to describe the firewall forever. Each chip here has four states and
// the fourth one is "unknown", rendered as itself: grey, named, with the
// endpoint that failed. A monitoring tool that reports a failed request as
// health is worse than one that reports nothing at all.

export function StatusStrip() {
  const { chips } = useStatus()
  return (
    <div className="flex items-center gap-1.5">
      {chips.map((c) => (
        <ChipPill key={c.key} chip={c} />
      ))}
    </div>
  )
}

function ChipPill({ chip }: { chip: Chip }) {
  if (chip.tone === 'loading') {
    // No colour, no text, no claim.
    return <span className="inline-block h-6 w-24 rounded-full" style={{ background: 'var(--surface-2)', opacity: 0.6 }} aria-hidden />
  }
  const { fg, bg } = toneColor(chip.tone)
  return (
    <Link
      to={chip.href}
      title={`${chip.detail}${chip.asOf ? ` Last successful reading at ${chip.asOf}.` : ''}`}
      className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium"
      style={{ color: fg, background: bg }}
    >
      <span
        className="inline-block h-1.5 w-1.5 shrink-0 rounded-full"
        style={{ background: fg, opacity: chip.asOf ? 0.45 : 1 }}
        aria-hidden
      />
      {chip.label}
      {chip.asOf && <span style={{ opacity: 0.75 }}>· as of {chip.asOf}</span>}
    </Link>
  )
}
