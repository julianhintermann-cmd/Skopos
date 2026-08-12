import type { ReactNode } from 'react'
import type { Severity } from '../lib/api'

// Reusable primitives styled through the design tokens. Kept small and
// hand-built rather than pulling in a component library.

export function Card({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={`rounded-lg border ${className}`}
      style={{ background: 'var(--surface)', borderColor: 'var(--border)' }}
    >
      {children}
    </div>
  )
}

export function CardHeader({ title, sub, right }: { title: string; sub?: string; right?: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3 px-4 pt-3.5 pb-2">
      <div>
        <h2 className="text-[0.95rem] font-semibold tracking-tight">{title}</h2>
        {sub && <p className="text-xs" style={{ color: 'var(--muted)' }}>{sub}</p>}
      </div>
      {right}
    </div>
  )
}

export function StatTile({
  label,
  value,
  unit,
  hint,
  tone = 'neutral',
}: {
  label: string
  value: string
  unit?: string
  hint?: string
  tone?: 'neutral' | 'accent' | 'good' | 'warn' | 'crit'
}) {
  const toneColor = {
    neutral: 'var(--text)',
    accent: 'var(--accent-strong)',
    good: 'var(--good)',
    warn: 'var(--warn)',
    crit: 'var(--crit)',
  }[tone]
  return (
    <Card className="px-4 py-3">
      <div
        className="font-mono text-[0.62rem] font-semibold uppercase tracking-[0.12em]"
        style={{ color: 'var(--muted)' }}
      >
        {label}
      </div>
      <div className="mt-1 flex items-baseline gap-1.5">
        <span className="tabnums text-2xl font-semibold leading-none" style={{ color: toneColor }}>
          {value}
        </span>
        {unit && <span className="text-xs" style={{ color: 'var(--muted)' }}>{unit}</span>}
      </div>
      {hint && <div className="mt-1 text-xs" style={{ color: 'var(--muted)' }}>{hint}</div>}
    </Card>
  )
}

const severityStyle: Record<Severity, { fg: string; bg: string; label: string; icon: string }> = {
  info: { fg: 'var(--accent-strong)', bg: 'var(--accent-tint)', label: 'Info', icon: 'i' },
  warning: { fg: 'var(--warn)', bg: 'var(--warn-tint)', label: 'Warning', icon: '!' },
  critical: { fg: 'var(--crit)', bg: 'var(--crit-tint)', label: 'Critical', icon: '×' },
}

// SeverityBadge carries an icon + label, never color alone (accessibility).
export function SeverityBadge({ severity }: { severity: Severity }) {
  const s = severityStyle[severity] ?? severityStyle.info
  return (
    <span
      className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium"
      style={{ color: s.fg, background: s.bg }}
    >
      <span aria-hidden className="font-mono font-semibold">{s.icon}</span>
      {s.label}
    </span>
  )
}

export function Pill({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'neutral' | 'accent' | 'good' | 'warn' }) {
  const style = {
    neutral: { color: 'var(--muted)', background: 'var(--surface-2)' },
    accent: { color: 'var(--accent-strong)', background: 'var(--accent-tint)' },
    good: { color: 'var(--good)', background: 'var(--good-tint)' },
    warn: { color: 'var(--warn)', background: 'var(--warn-tint)' },
  }[tone]
  return (
    <span className="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium" style={style}>
      {children}
    </span>
  )
}

export function Button({
  children,
  onClick,
  variant = 'default',
  type = 'button',
  disabled,
  className = '',
}: {
  children: ReactNode
  onClick?: () => void
  variant?: 'default' | 'primary' | 'danger'
  type?: 'button' | 'submit'
  disabled?: boolean
  className?: string
}) {
  const style =
    variant === 'primary'
      ? { background: 'var(--accent)', color: '#fff', borderColor: 'var(--accent)' }
      : variant === 'danger'
        ? { background: 'transparent', color: 'var(--crit)', borderColor: 'var(--crit)' }
        : { background: 'var(--surface-2)', color: 'var(--text)', borderColor: 'var(--border)' }
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`rounded-md border px-3 py-1.5 text-sm font-medium transition-opacity disabled:opacity-50 hover:opacity-90 ${className}`}
      style={style}
    >
      {children}
    </button>
  )
}

export function EmptyState({ children }: { children: ReactNode }) {
  return (
    <div className="px-4 py-10 text-center text-sm" style={{ color: 'var(--muted)' }}>
      {children}
    </div>
  )
}

export function Spinner() {
  return (
    <div className="flex items-center justify-center py-10" style={{ color: 'var(--muted)' }}>
      <span className="text-sm">Loading…</span>
    </div>
  )
}
