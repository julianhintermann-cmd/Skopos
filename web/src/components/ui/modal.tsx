import { useRef, type ReactNode } from 'react'
import { BottomSheet } from '../mobile'
import { useDialogFocus } from './dialog'
import { useIsMobile } from '../../lib/useIsMobile'
import { Card } from './card'
import { IconButton } from './button'
import type { Size } from './tone'

// `presentation` is a prop rather than a hard-coded form because the shape of
// the block/mute dialogs is still being arbitrated. Whichever way that lands,
// no primitive has to be rewritten.
export function Modal({
  open,
  onClose,
  title,
  children,
  footer,
  width = 'md',
  presentation = 'auto',
}: {
  open: boolean
  onClose: () => void
  title: string
  children: ReactNode
  footer?: ReactNode
  width?: Size
  presentation?: 'auto' | 'inline' | 'overlay' | 'sheet'
}) {
  const isMobile = useIsMobile()
  const mode = presentation === 'auto' ? (isMobile ? 'sheet' : 'inline') : presentation
  const panel = useRef<HTMLDivElement>(null)

  // The overlay says aria-modal="true" and, until now, did not behave like one:
  // Escape and the scrim worked, but Tab walked straight out of the dialog into
  // the page behind it (measured focusInside: false). That is a promise made to
  // assistive technology and not kept — the same class of defect as a green
  // pill over an unverified kernel, told to a screen reader instead of to the
  // eye. It is on the destructive path too: the Forget confirmation uses this.
  //
  // Escape now comes from the same hook, which also returns focus to whatever
  // opened the dialog. The sheet branch gets all of it from BottomSheet, and an
  // inline panel does not trap the page so it never claims the key.
  useDialogFocus(panel, open && mode === 'overlay', onClose)

  if (!open) return null

  const body = (
    <>
      {children}
      {footer && <div className="mt-3 flex items-center justify-end gap-2">{footer}</div>}
    </>
  )

  if (mode === 'sheet') {
    return (
      <BottomSheet open={open} onClose={onClose} title={title}>
        <div className="px-5 pb-4 pt-2">{body}</div>
      </BottomSheet>
    )
  }

  if (mode === 'inline') {
    return (
      <Card pad="default" className={width === 'sm' ? 'max-w-sm' : 'max-w-lg'}>
        <div className="mb-2 flex items-baseline justify-between gap-3">
          <h2 className="text-lg font-semibold">{title}</h2>
          <IconButton label="Close" onClick={onClose} size={14}>
            <span aria-hidden>×</span>
          </IconButton>
        </div>
        {body}
      </Card>
    )
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-scrim" onClick={onClose} aria-hidden />
      <div
        ref={panel}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={`relative w-full rounded-lg border border-line bg-surface p-4 shadow-overlay outline-none ${
          width === 'sm' ? 'max-w-sm' : 'max-w-lg'
        }`}
      >
        <div className="mb-2 flex items-baseline justify-between gap-3">
          <h2 className="text-lg font-semibold">{title}</h2>
          <IconButton label="Close" onClick={onClose} size={14}>
            <span aria-hidden>×</span>
          </IconButton>
        </div>
        {body}
      </div>
    </div>
  )
}
