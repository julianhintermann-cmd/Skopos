import { useEffect, useRef, type RefObject } from 'react'

// The behaviour `role="dialog" aria-modal="true"` promises and neither of this
// app's two dialogs delivered.
//
// BottomSheet holds six of the ten navigation destinations plus Log out, and
// it could be Tab'd straight out of into the page behind, could not be closed
// from a keyboard at all, and returned focus to <body> when it did close. That
// is not a modal; it is a panel wearing a modal's ARIA. This makes the claim
// true.

const FOCUSABLE =
  'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])'

export function useDialogFocus(
  ref: RefObject<HTMLElement | null>,
  open: boolean,
  onClose: () => void,
) {
  // onClose is held in a ref rather than depended on. Every caller passes an
  // inline arrow, so depending on it would re-run this effect on each render —
  // and the effect focuses the panel, which would yank the caret out of any
  // input inside the sheet on every keystroke.
  const closeRef = useRef(onClose)
  useEffect(() => {
    closeRef.current = onClose
  }, [onClose])

  useEffect(() => {
    if (!open) return
    const panel = ref.current
    // The element to hand focus back to. Without this, closing the More sheet
    // dropped the keyboard user at the top of the document every time.
    const returnTo = document.activeElement as HTMLElement | null

    const focusable = () => Array.from(panel?.querySelectorAll<HTMLElement>(FOCUSABLE) ?? [])

    // Focus the panel itself rather than its first control: the first control
    // in the More sheet is a navigation link, and auto-activating screen
    // readers announce it as the whole dialog.
    panel?.focus()

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation()
        closeRef.current()
        return
      }
      if (e.key !== 'Tab') return
      const items = focusable()
      if (items.length === 0) {
        e.preventDefault()
        return
      }
      const first = items[0]
      const last = items[items.length - 1]
      const active = document.activeElement
      if (e.shiftKey && (active === first || active === panel)) {
        e.preventDefault()
        last.focus()
      } else if (!e.shiftKey && active === last) {
        e.preventDefault()
        first.focus()
      }
    }

    document.addEventListener('keydown', onKey, true)
    return () => {
      document.removeEventListener('keydown', onKey, true)
      // Only restore if focus is still inside the panel we are tearing down;
      // a click that both closed the dialog and moved focus elsewhere keeps
      // where it landed.
      if (!returnTo) return
      const active = document.activeElement
      if (active === document.body || (panel && panel.contains(active))) returnTo.focus()
    }
  }, [ref, open])
}
