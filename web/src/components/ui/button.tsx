import type { ReactNode } from 'react'
import type { Size } from './tone'

// The variants exist as classes, not inline styles, for one reason: an inline
// style cannot express `hover:` / `active:` / `disabled:`. The app had five
// hover rules in 6,346 lines and no active state anywhere, which is what that
// limitation looks like from the outside.
//
// `primary` is the P0: it painted #fff on the teal accent at 2.30:1 in dark.
// text-on-accent is 7.55:1 there and 6.38:1 in light.
const variants = {
  default:
    'border-line bg-raised text-fg hover:bg-sunken active:bg-sunken',
  primary:
    'border-accent bg-accent text-on-accent hover:border-accent-hover hover:bg-accent-hover active:bg-accent-hover',
  danger:
    'border-crit bg-transparent text-crit hover:bg-crit-quiet active:bg-crit-quiet',
  // ghost replaces the 32 raw <button>s that had no shared behaviour at all.
  ghost:
    'border-transparent bg-transparent text-fg-muted hover:bg-hover hover:text-fg active:bg-active',
}

export function Button({
  children,
  onClick,
  variant = 'default',
  size = 'md',
  type = 'button',
  disabled,
  loading,
  iconOnly,
  'aria-label': ariaLabel,
  className = '',
}: {
  children: ReactNode
  onClick?: () => void
  variant?: 'default' | 'primary' | 'danger' | 'ghost'
  size?: Size
  type?: 'button' | 'submit'
  disabled?: boolean
  loading?: boolean
  iconOnly?: boolean
  'aria-label'?: string
  className?: string
}) {
  const pad = iconOnly
    ? size === 'sm'
      ? 'p-1'
      : 'p-1.5'
    : size === 'sm'
      ? 'px-2 py-1 text-xs'
      : 'px-3 py-1.5 text-sm'

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled || loading}
      aria-label={ariaLabel}
      aria-busy={loading || undefined}
      className={`inline-flex items-center justify-center gap-1.5 rounded-md border font-medium transition-colors disabled:opacity-50 ${variants[variant]} ${pad} ${className}`}
    >
      {/* A spinner beside the unchanged label, rather than swapping the label
          for "Blocking…". The button keeps its width, so the row it sits in
          does not jump at the exact moment the user is watching it. */}
      {loading && <Spin />}
      {children}
    </button>
  )
}

function Spin() {
  return (
    <svg
      className="animate-[skopos-spin_0.7s_linear_infinite]"
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="3"
      strokeLinecap="round"
      aria-hidden
    >
      <path d="M12 3a9 9 0 0 1 9 9" />
    </svg>
  )
}

const iconTones = {
  neutral: 'text-fg-muted hover:bg-hover hover:text-fg active:bg-active',
  accent: 'text-accent hover:bg-accent-quiet active:bg-active',
  crit: 'text-crit hover:bg-crit-quiet active:bg-active',
}

// `label` is required and becomes both aria-label and title. An icon button
// with neither is a button whose purpose is a guess.
export function IconButton({
  label,
  onClick,
  children,
  tone = 'neutral',
  disabled,
  size = 16,
  className = '',
}: {
  label: string
  onClick: () => void
  children: ReactNode
  tone?: 'neutral' | 'accent' | 'crit'
  disabled?: boolean
  size?: 14 | 16 | 20
  className?: string
}) {
  const box = size === 14 ? 'h-6 w-6' : size === 20 ? 'h-8 w-8' : 'h-7 w-7'
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      aria-label={label}
      title={label}
      className={`inline-flex shrink-0 items-center justify-center rounded-md transition-colors disabled:opacity-40 ${iconTones[tone]} ${box} ${className}`}
    >
      {children}
    </button>
  )
}
