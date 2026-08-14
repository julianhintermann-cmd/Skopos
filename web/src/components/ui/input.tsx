import { type KeyboardEvent, type ReactNode } from 'react'
import { SheetSelect } from '../mobile'
import { useIsMobile } from '../../lib/useIsMobile'
import { toneOf, type Size, type Tone, type ToneInput } from './tone'

export function TextInput({
  value,
  onChange,
  placeholder,
  type = 'text',
  mono,
  disabled,
  invalid,
  size = 'md',
  onKeyDown,
  className = '',
}: {
  value: string
  onChange: (v: string) => void
  // Placeholders in this app are documentation — "192.168.1.10 or 10.0.0.0/8",
  // "24h · blank = permanent". All 18 of them carry a format instruction, which
  // is why placeholder text uses --fg-muted at 4.5:1 and not a dimmer token.
  placeholder?: string
  type?: string
  mono?: boolean
  disabled?: boolean
  invalid?: boolean
  size?: Size
  onKeyDown?: (e: KeyboardEvent) => void
  className?: string
}) {
  const pad = size === 'sm' ? 'px-2 py-1 text-xs' : 'px-3 py-2 text-sm'
  return (
    <input
      type={type}
      value={value}
      disabled={disabled}
      placeholder={placeholder}
      aria-invalid={invalid || undefined}
      onChange={(e) => onChange(e.target.value)}
      onKeyDown={onKeyDown}
      className={`w-full rounded-md border bg-raised text-fg transition-colors placeholder:text-fg-muted disabled:opacity-50 ${
        invalid ? 'border-crit' : 'border-line-strong focus:border-line-focus'
      } ${mono ? 'font-mono' : ''} ${pad} ${className}`}
    />
  )
}

// One labelled form row, replacing Traffic.Field, Firewall.Field and
// Alerts.FieldLabel — three copies that had drifted to three different label
// sizes.
export function Field({
  label,
  children,
  hint,
  error,
  width,
  htmlFor,
}: {
  label: string
  children: ReactNode
  hint?: string
  error?: string
  width?: string
  htmlFor?: string
}) {
  return (
    <div className="flex flex-col gap-1" style={width ? { width } : undefined}>
      <label htmlFor={htmlFor} className="font-mono text-label uppercase text-fg-muted">
        {label}
      </label>
      {children}
      {error ? (
        <span className="text-xs text-crit">{error}</span>
      ) : hint ? (
        <span className="text-xs text-fg-muted">{hint}</span>
      ) : null}
    </div>
  )
}

export function Toggle({
  checked,
  onChange,
  disabled,
  label,
}: {
  checked: boolean
  onChange: (v: boolean) => void
  disabled?: boolean
  label?: string
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors disabled:opacity-40 ${
        checked ? 'bg-accent' : 'bg-sunken'
      }`}
    >
      {/* The knob keeps a ring when off: surface-on-sunken is 1.35:1, which is
          not a visible edge. On, it sits on the accent at ~6.4:1 and needs none. */}
      <span
        className={`inline-block h-3.5 w-3.5 rounded-full bg-surface transition-transform ${
          checked ? 'translate-x-[19px]' : 'translate-x-[3px] ring-1 ring-line-strong'
        }`}
      />
    </button>
  )
}

export interface SegmentedOption<T extends string> {
  value: T
  label: ReactNode
  hint?: string
  tone?: ToneInput
}

// Nine hand-rolled copies of this row existed. Selected state is carried by
// background AND a ring AND the accent foreground, so it survives independently
// of the option's own tone — in DeviceDetail the selected and unselected chips
// were rendering identically once a tone was involved.
export function Segmented<T extends string>({
  value,
  options,
  onChange,
  size = 'md',
  mono,
  ariaLabel,
}: {
  value: T
  options: SegmentedOption<T>[]
  onChange: (v: T) => void
  size?: Size
  mono?: boolean
  ariaLabel: string
}) {
  const isMobile = useIsMobile()

  // A row of small targets is the wrong control on a phone. The sheet needs
  // plain strings, so an option whose label is a node falls back to its value
  // rather than rendering "[object Object]".
  if (isMobile) {
    return (
      <SheetSelect
        value={value}
        label={ariaLabel}
        onChange={onChange}
        options={options.map((o) => ({
          value: o.value,
          label: typeof o.label === 'string' ? o.label : o.value,
          hint: o.hint,
        }))}
      />
    )
  }

  const pad = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-sm'
  return (
    <div role="radiogroup" aria-label={ariaLabel} className="inline-flex gap-0.5 rounded-md bg-raised p-0.5">
      {options.map((o) => {
        const selected = o.value === value
        return (
          <button
            key={o.value}
            type="button"
            role="radio"
            aria-checked={selected}
            title={o.hint}
            onClick={() => onChange(o.value)}
            className={`rounded-md font-medium transition-colors ${pad} ${mono ? 'font-mono' : ''} ${
              selected
                ? 'bg-selected text-accent ring-1 ring-accent/25'
                : `hover:bg-hover active:bg-active ${unselectedTone[toneOf(o.tone)]}`
            }`}
          >
            {o.label}
          </button>
        )
      })}
    </div>
  )
}

const unselectedTone: Record<Tone, string> = {
  neutral: 'text-fg-muted hover:text-fg',
  accent: 'text-accent',
  ok: 'text-ok',
  warn: 'text-warn',
  crit: 'text-crit',
  unknown: 'text-unknown',
}
