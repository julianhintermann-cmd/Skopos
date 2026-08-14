import { useRef, type ReactNode } from 'react'
import { BottomSheet } from './mobile'
import { useDialogFocus } from './ui/dialog'
import { useIsMobile } from '../lib/useIsMobile'
import { Button } from './ui'

// The interruption, for the actions where undo alone is not enough.
//
// Undo is the default in this release and confirmation is the exception,
// added only where the inverse is not exact or where the damage lands faster
// than a hand can reach the Undo button: cutting established connections,
// unloading tens of thousands of country prefixes, and any action aimed at
// more than one target at once.
//
// It is a true modal because there is no context to preserve — unlike the
// block and mute panels, which belong to the row they came from. What it must
// do is name the targets and state the consequence in the sentence the
// operator reads before agreeing, not after.
export function ConfirmDialog({
  open,
  title,
  lead,
  consequence,
  targets,
  confirmLabel,
  busy,
  onConfirm,
  onCancel,
}: {
  open: boolean
  title: string
  // What is about to happen, in one sentence.
  lead: ReactNode
  // What it costs. The half an operator cannot reconstruct from the button.
  consequence?: ReactNode
  // The exact list this acts on. A count with no list is a promise the
  // operator has to take on faith.
  targets?: string[]
  confirmLabel: string
  busy?: boolean
  onConfirm: () => void
  onCancel: () => void
}) {
  const isMobile = useIsMobile()
  const panel = useRef<HTMLDivElement>(null)
  // BottomSheet traps focus itself; the desktop overlay has to be told to.
  useDialogFocus(panel, open && !isMobile, onCancel)

  if (!open) return null

  const body = (
    <>
      <div className="text-sm text-fg">{lead}</div>
      {consequence && <div className="mt-1.5 text-sm text-fg-muted">{consequence}</div>}
      {targets && targets.length > 0 && (
        <ul className="mt-2 max-h-56 overflow-y-auto rounded-md border border-line bg-raised px-3 py-2">
          {targets.map((t) => (
            <li key={t} className="break-all py-0.5 font-mono text-xs text-fg">
              {t}
            </li>
          ))}
        </ul>
      )}
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Button variant="danger" onClick={onConfirm} loading={busy} className="pointer-coarse:min-h-11">
          {confirmLabel}
        </Button>
        <Button onClick={onCancel} className="pointer-coarse:min-h-11">
          Cancel
        </Button>
      </div>
    </>
  )

  if (isMobile) {
    return (
      <BottomSheet open={open} onClose={onCancel} title={title}>
        <div className="px-5 pb-4 pt-1">{body}</div>
      </BottomSheet>
    )
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-scrim" onClick={onCancel} aria-hidden />
      <div
        ref={panel}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="relative w-full max-w-lg rounded-lg border border-line bg-surface p-4 shadow-overlay outline-none"
      >
        <h2 className="mb-2 text-lg font-semibold">{title}</h2>
        {body}
      </div>
    </div>
  )
}
