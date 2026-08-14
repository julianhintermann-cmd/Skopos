import { SheetSelect } from './mobile'
import { useIsMobile } from '../lib/useIsMobile'
import { RANGES, RANGE_HINT, RANGE_LABEL, type Range } from '../lib/useUrlState'

// The one time control. Every view that has a time position renders this and
// nothing else, which is what retires the four competing vocabularies that
// used to disagree about whether a week was "7d" or "168h".
//
// Live, where allowed, is the leftmost position on the same control rather
// than a separate tab: the user moves along one axis from right now to the
// last thirty days.
export function RangeControl({
  range,
  setRange,
  allowed = RANGES,
  label = 'Time range',
}: {
  range: Range
  setRange: (r: Range) => void
  allowed?: readonly Range[]
  label?: string
}) {
  const isMobile = useIsMobile()

  if (isMobile) {
    return (
      <SheetSelect
        value={range}
        label={label}
        options={allowed.map((r) => ({ value: r, label: RANGE_LABEL[r], hint: RANGE_HINT[r] }))}
        onChange={setRange}
      />
    )
  }

  return (
    <div className="flex items-center gap-1" role="group" aria-label={label}>
      {allowed.map((r) => (
        <button
          key={r}
          type="button"
          onClick={() => setRange(r)}
          title={RANGE_HINT[r]}
          aria-pressed={r === range}
          className="rounded-md px-3 py-1 text-xs font-medium"
          style={
            r === range
              ? { background: 'var(--accent-tint)', color: 'var(--accent-strong)' }
              : { background: 'var(--surface-2)', color: 'var(--muted)' }
          }
        >
          {RANGE_LABEL[r]}
        </button>
      ))}
    </div>
  )
}

// SegmentedControl is the same shape for any other committed choice — the
// lens on Traffic, the tab on Firewall — so a page's controls read as one row
// of the same thing.
export function SegmentedControl<T extends string>({
  value,
  options,
  onChange,
  label,
}: {
  value: T
  options: { value: T; label: string; hint?: string }[]
  onChange: (v: T) => void
  label: string
}) {
  const isMobile = useIsMobile()
  if (isMobile) {
    return <SheetSelect value={value} label={label} options={options} onChange={onChange} />
  }
  return (
    <div className="flex items-center gap-1" role="group" aria-label={label}>
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          onClick={() => onChange(o.value)}
          title={o.hint}
          aria-pressed={o.value === value}
          className="rounded-md px-3 py-1 text-xs font-medium"
          style={
            o.value === value
              ? { background: 'var(--accent-tint)', color: 'var(--accent-strong)' }
              : { background: 'var(--surface-2)', color: 'var(--muted)' }
          }
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}
