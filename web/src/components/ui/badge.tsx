import type { ReactNode } from 'react'
import type { Severity } from '../../lib/api'
import { toneOf, toneQuiet, type ToneInput } from './tone'

export function Pill({
  children,
  tone = 'neutral',
  icon,
  onRemove,
  title,
}: {
  children: ReactNode
  tone?: ToneInput
  icon?: ReactNode
  onRemove?: () => void
  title?: string
}) {
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${toneQuiet[toneOf(tone)]}`}
    >
      {icon}
      {children}
      {onRemove && (
        <button
          type="button"
          onClick={onRemove}
          aria-label="Remove"
          className="-mr-0.5 ml-0.5 rounded-full px-0.5 leading-none opacity-70 transition-opacity hover:opacity-100"
        >
          <span aria-hidden>×</span>
        </button>
      )}
    </span>
  )
}

const severityStyle: Record<Severity, { tone: ToneInput; label: string; icon: string }> = {
  info: { tone: 'accent', label: 'Info', icon: 'i' },
  warning: { tone: 'warn', label: 'Warning', icon: '!' },
  critical: { tone: 'crit', label: 'Critical', icon: '×' },
}

// Icon plus label, never colour alone. This is the rule the whole palette is
// held to, and it is also why the tritanopia margin between the direction hues
// is acceptable rather than load-bearing.
export function SeverityBadge({ severity }: { severity: Severity }) {
  const s = severityStyle[severity] ?? severityStyle.info
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${toneQuiet[toneOf(s.tone)]}`}
    >
      <span aria-hidden className="font-mono font-semibold">{s.icon}</span>
      {s.label}
    </span>
  )
}

const bannerTone = {
  info: 'border-line bg-raised text-fg',
  accent: 'border-accent/30 bg-accent-quiet text-fg',
  warn: 'border-warn/30 bg-warn-quiet text-fg',
  crit: 'border-crit/30 bg-crit-quiet text-fg',
}

const bannerTitle = {
  info: 'text-fg',
  accent: 'text-accent',
  warn: 'text-warn',
  crit: 'text-crit',
}

// Kills Firewall.Banner and four inline copies. `crit` announces itself; the
// quieter tones do not interrupt a screen reader mid-task.
export function Banner({
  tone,
  title,
  children,
  action,
  href,
  onDismiss,
}: {
  tone: 'info' | 'warn' | 'crit' | 'accent'
  title: string
  children?: ReactNode
  action?: ReactNode
  href?: string
  onDismiss?: () => void
}) {
  const body = (
    <>
      <div className="min-w-0 flex-1">
        <div className={`text-sm font-semibold ${bannerTitle[tone]}`}>{title}</div>
        {children && <div className="mt-0.5 text-xs text-fg-muted">{children}</div>}
      </div>
      {action}
      {onDismiss && (
        <button
          type="button"
          onClick={onDismiss}
          aria-label="Dismiss"
          className="shrink-0 rounded-md px-1 text-fg-muted transition-colors hover:bg-hover hover:text-fg"
        >
          <span aria-hidden>×</span>
        </button>
      )}
    </>
  )

  const cls = `flex items-start gap-3 rounded-lg border px-4 py-3 ${bannerTone[tone]}`

  if (href) {
    return (
      <a
        href={href}
        role={tone === 'crit' ? 'alert' : undefined}
        className={`${cls} transition-colors hover:border-line-strong`}
      >
        {body}
      </a>
    )
  }
  return (
    <div role={tone === 'crit' ? 'alert' : undefined} className={cls}>
      {body}
    </div>
  )
}
