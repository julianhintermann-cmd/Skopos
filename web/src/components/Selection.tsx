import { useCallback, useRef, useState, type ReactNode } from 'react'

// Selecting rows to act on several at once, without the classic bulk footgun.
//
// The footgun is acting on a selection whose rows are no longer what the
// operator was looking at. Three things guard against it here, and all three
// are cheaper than the incident they prevent:
//
//   - keys are stable identifiers (a prefix, a MAC), never a row index, so a
//     list that reorders under a poll cannot re-aim a selection;
//   - keys that are no longer in the payload drop out silently and the count
//     goes down with them — the operator can never act on a row that has since
//     expired or been removed elsewhere;
//   - changing the tab, filter or window clears the selection entirely,
//     because "the four I picked" means the four that were on screen.
export function useSelection<K extends string>(present: readonly K[], resetKey: string) {
  const [picked, setPicked] = useState<ReadonlySet<K>>(() => new Set<K>())
  const anchor = useRef<K | null>(null)

  // Reset during render rather than in an effect: an effect runs after the
  // browser has been handed a frame, so switching filters would commit one
  // paint of "4 selected" over rows that are not the four.
  const seen = useRef(resetKey)
  if (seen.current !== resetKey) {
    seen.current = resetKey
    if (picked.size > 0) setPicked(new Set<K>())
    anchor.current = null
  }

  // Derived, not stored: the selection is whatever survives in the newest
  // payload, in the order it is rendered in.
  const selected = present.filter((k) => picked.has(k))

  const toggle = useCallback(
    (key: K, extend: boolean) => {
      setPicked((prev) => {
        const next = new Set(prev)
        const from = anchor.current !== null ? present.indexOf(anchor.current) : -1
        const to = present.indexOf(key)
        // Shift extends over the order on screen, which is the only order the
        // operator can see.
        if (extend && from >= 0 && to >= 0) {
          const [lo, hi] = from < to ? [from, to] : [to, from]
          for (let i = lo; i <= hi; i++) next.add(present[i])
          return next
        }
        if (next.has(key)) next.delete(key)
        else next.add(key)
        anchor.current = key
        return next
      })
    },
    [present],
  )

  const clear = useCallback(() => {
    setPicked(new Set<K>())
    anchor.current = null
  }, [])

  const selectAllShown = useCallback(() => {
    setPicked(new Set(present))
  }, [present])

  return {
    selected,
    count: selected.length,
    has: (k: K) => picked.has(k),
    toggle,
    clear,
    selectAllShown,
    allShown: present.length > 0 && selected.length === present.length,
  }
}

// SelectBox is the per-row control. The label names the row, so a screen
// reader hears "Select 203.0.113.5/32" rather than thirty identical checkboxes.
export function SelectBox({
  checked,
  label,
  onToggle,
}: {
  checked: boolean
  label: string
  onToggle: (extend: boolean) => void
}) {
  return (
    <input
      type="checkbox"
      checked={checked}
      readOnly
      aria-label={label}
      onClick={(e) => onToggle(e.shiftKey)}
      className="h-4 w-4 shrink-0 cursor-pointer accent-[var(--accent)] pointer-coarse:h-5 pointer-coarse:w-5"
    />
  )
}

// BulkBar appears only when something is selected. "Select all" says how many
// and out of what — an implicit "all 200" over a filtered list of 34 is the
// other half of the same footgun.
export function BulkBar({
  count,
  shown,
  allShown,
  onSelectAll,
  onClear,
  children,
}: {
  count: number
  shown: number
  allShown: boolean
  onSelectAll: () => void
  onClear: () => void
  children: ReactNode
}) {
  if (count === 0) return null
  return (
    <div
      role="status"
      className="flex flex-wrap items-center gap-2 rounded-lg border border-line bg-raised px-3 py-2"
    >
      <span className="text-sm font-medium text-fg">
        {count} selected{count < shown ? ` of ${shown} shown` : ''}
      </span>
      <span className="mx-0.5 h-4 w-px bg-line" aria-hidden />
      {children}
      <div className="ml-auto flex items-center gap-2">
        {!allShown && (
          <button
            type="button"
            onClick={onSelectAll}
            className="rounded-md px-2 py-1 text-xs font-medium text-fg-muted transition-colors hover:bg-hover hover:text-fg pointer-coarse:min-h-11"
          >
            Select all {shown} shown
          </button>
        )}
        <button
          type="button"
          onClick={onClear}
          className="rounded-md px-2 py-1 text-xs font-medium text-fg-muted transition-colors hover:bg-hover hover:text-fg pointer-coarse:min-h-11"
        >
          Clear
        </button>
      </div>
    </div>
  )
}
