import type { ReactNode } from 'react'
import { Card } from './card'
import { NoData } from './text'
import { toneFill, toneOf, toneText, type Size, type ToneInput } from './tone'

// `value: string | null` is mandatory, not optional.
//
// The old signature was `value: string`, so four call sites in LivePulse and
// three in DomainDetail passed the literal '—' when there was no reading. A
// required nullable forces the question at the call site: either you have a
// measurement or you say why you do not. Never '—', never a substituted 0.
//
// Absorbs SpeedStat, HealthItem and Meta, which were three near-identical
// tiles in three views.
export function StatTile({
  label,
  value,
  unit,
  hint,
  tone = 'neutral',
  size = 'md',
  dot,
  unavailable,
}: {
  label: string
  value: string | null
  unit?: string
  hint?: string
  tone?: ToneInput
  size?: Size
  dot?: boolean
  // Why there is no value. Shown verbatim: "no reading yet", "not reported".
  unavailable?: string
}) {
  const t = toneOf(tone)
  return (
    <Card className="px-4 py-3">
      <div className="font-mono text-label uppercase text-fg-muted">{label}</div>
      <div className="mt-1 flex items-baseline gap-1.5">
        {dot && (
          <span
            aria-hidden
            className={`mb-0.5 inline-block h-2 w-2 shrink-0 self-center rounded-full ${toneFill[t]}`}
          />
        )}
        {value === null ? (
          <NoData reason={unavailable ?? 'no reading'} />
        ) : (
          <span
            className={`tabnums font-semibold leading-none ${size === 'sm' ? 'text-xl' : 'text-2xl'} ${toneText[t]}`}
          >
            {value}
          </span>
        )}
        {value !== null && unit && <span className="text-xs text-fg-muted">{unit}</span>}
      </div>
      {hint && <div className="mt-1 text-xs text-fg-muted">{hint}</div>}
    </Card>
  )
}

// The meta strip: label/value pairs where a value may legitimately be unknown.
// A null item renders NoData rather than an em-dash, for the same reason.
export function KeyValue({
  items,
  columns = 2,
}: {
  items: { label: string; value: ReactNode | null; tone?: ToneInput }[]
  columns?: 2 | 3
}) {
  return (
    <dl className={`grid gap-x-4 gap-y-2 ${columns === 3 ? 'grid-cols-3' : 'grid-cols-2'}`}>
      {items.map((it) => (
        <div key={it.label} className="min-w-0">
          <dt className="font-mono text-label uppercase text-fg-muted">{it.label}</dt>
          <dd className={`mt-0.5 text-sm font-medium ${toneText[toneOf(it.tone)]}`}>
            {it.value === null || it.value === undefined ? (
              <NoData reason="not reported" inline />
            ) : (
              it.value
            )}
          </dd>
        </div>
      ))}
    </dl>
  )
}
