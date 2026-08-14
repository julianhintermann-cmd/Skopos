import { useSyncExternalStore, type ReactNode } from 'react'
import { toneOf, toneQuiet, type ToneInput } from './tone'

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="px-4 py-10 text-center text-sm text-fg-muted">{children}</div>
}

// Retained for the call sites Skeleton has not reached yet. New code should
// use Skeleton: this collapses the layout to a single centred line and then
// expands it again, so every load is also a reflow.
export function Spinner() {
  return (
    <div className="flex items-center justify-center py-10 text-fg-muted">
      <span className="text-sm">Loading…</span>
    </div>
  )
}

// Skeleton holds the shape of the thing being loaded. It is decoration for a
// sighted reader and silence for a screen reader — the status is announced
// once, in words, instead of thirteen shimmering boxes.
export function Skeleton({
  variant,
  rows = 3,
  className = '',
}: {
  variant: 'text' | 'row' | 'tile' | 'chart'
  rows?: number
  className?: string
}) {
  const bar = 'sk-skeleton rounded-sm'

  let body: ReactNode
  if (variant === 'chart') {
    body = <div className={`${bar} h-40 w-full rounded-md`} />
  } else if (variant === 'tile') {
    body = (
      <div className="flex flex-col gap-2">
        <div className={`${bar} h-2.5 w-16`} />
        <div className={`${bar} h-6 w-24`} />
      </div>
    )
  } else if (variant === 'row') {
    body = (
      <div className="flex flex-col gap-2.5">
        {Array.from({ length: rows }, (_, i) => (
          <div key={i} className="flex items-center gap-3">
            <div className={`${bar} h-3 w-1/4`} />
            <div className={`${bar} h-3 flex-1`} />
            <div className={`${bar} h-3 w-16`} />
          </div>
        ))}
      </div>
    )
  } else {
    body = (
      <div className="flex flex-col gap-2">
        {Array.from({ length: rows }, (_, i) => (
          <div key={i} className={`${bar} h-3`} style={{ width: i === rows - 1 ? '60%' : '100%' }} />
        ))}
      </div>
    )
  }

  return (
    <div className={`px-4 py-3 ${className}`}>
      <span className="sr-only" role="status">Loading</span>
      <div aria-hidden>{body}</div>
    </div>
  )
}

// --- toasts ----------------------------------------------------------------

// Replaces the ad-hoc confirmations: `setResult('sent ✓')` in two views and
// WakeButton's 2.5-second label swap. Those wrote the outcome into the control
// that caused it, so the control stopped saying what it does, and a screen
// reader was told nothing at all.

export interface ToastSpec {
  tone: ToneInput
  message: string
  ttlMs?: number
}

interface Toast extends ToastSpec {
  id: number
}

let snapshot: Toast[] = []
let seq = 0
const listeners = new Set<() => void>()

function emit() {
  for (const l of listeners) l()
}

function subscribe(l: () => void) {
  listeners.add(l)
  return () => {
    listeners.delete(l)
  }
}

// A module-level store rather than a context, so `useToast` works from any
// depth without ToastHost having to wrap the tree.
const toast = {
  show(t: ToastSpec) {
    const id = ++seq
    snapshot = [...snapshot, { ...t, id }]
    emit()
    window.setTimeout(() => {
      snapshot = snapshot.filter((x) => x.id !== id)
      emit()
    }, t.ttlMs ?? 4000)
  },
}

export function useToast() {
  return toast
}

// Mounted once, near the root.
export function ToastHost() {
  const items = useSyncExternalStore(subscribe, () => snapshot)
  if (items.length === 0) return null
  return (
    <div className="pointer-events-none fixed inset-x-0 bottom-4 z-[60] flex flex-col items-center gap-2 px-4">
      {items.map((t) => {
        const tone = toneOf(t.tone)
        return (
          <div
            key={t.id}
            // crit interrupts; everything else waits for a gap.
            role={tone === 'crit' ? 'alert' : 'status'}
            aria-live={tone === 'crit' ? 'assertive' : 'polite'}
            className={`pointer-events-auto max-w-md rounded-md border border-line px-3 py-2 text-sm shadow-overlay ${toneQuiet[tone]}`}
          >
            {t.message}
          </div>
        )
      })}
    </div>
  )
}
