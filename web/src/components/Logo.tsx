// The Skopos mark: concentric sonar rings with a sweep and a blip — σκοπός,
// the watcher. Uses currentColor so it inherits the accent wherever placed.
export function Logo({ size = 28, animate = true }: { size?: number; animate?: boolean }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 44 44"
      fill="none"
      aria-hidden="true"
      style={{ color: 'var(--accent)' }}
    >
      <circle cx="22" cy="22" r="20" stroke="currentColor" strokeWidth="1.5" opacity="0.2" />
      <circle cx="22" cy="22" r="13.5" stroke="currentColor" strokeWidth="1.5" opacity="0.45" />
      <circle cx="22" cy="22" r="7" stroke="currentColor" strokeWidth="1.5" opacity="0.9" />
      <line x1="22" y1="22" x2="36" y2="8" stroke="currentColor" strokeWidth="1" opacity="0.35" />
      <circle cx="31" cy="13" r="2.4" fill="currentColor">
        {animate && (
          <animate attributeName="opacity" values="0.9;0.25;0.9" dur="3.2s" repeatCount="indefinite" />
        )}
      </circle>
      <circle cx="22" cy="22" r="1.6" fill="currentColor" />
    </svg>
  )
}
