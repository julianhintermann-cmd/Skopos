import { useCallback, useEffect, useRef, useState } from 'react'
import { toneFill, toneQuiet, type Tone } from './ui/tone'

// The record of what an action actually did, kept next to the list it changed.
//
// Two rules from the 0.4.0 action contract shape this, and neither is
// satisfiable by the toast host as it stands:
//
//   - Undo carries a visible countdown. "Undo" on its own promises a
//     durability it does not have: this is a client-held inverse call, not a
//     server transaction log, and it dies with the page. A number ticking down
//     says exactly how long the offer is good for.
//   - A failure has to outlive the announcement. A toast that expires while
//     the operator is still reading it is not a record, and the failure of a
//     firewall change is the one thing on this page that must not evaporate.
//
// So successes fade, failures stay until they are dismissed, and a bulk action
// keeps its per-target list — twenty targets reported as one aggregate outcome
// is not an outcome.

export const UNDO_SECONDS = 8

export interface TargetResult {
  target: string
  ok: boolean
  // The sentence for this one target, not a status code.
  message: string
}

export interface OutcomeSpec {
  tone: Tone
  message: string
  // Per-target results for a bulk action, in the order they were attempted.
  results?: TargetResult[]
  // The inverse call. `run` returns the outcome of the undo itself — including
  // its own failure, because an Undo that silently fails is worse than no Undo.
  undo?: { label: string; run: () => Promise<OutcomeSpec> }
}

export interface Outcome extends OutcomeSpec {
  id: number
}

export function useOutcomes() {
  const [items, setItems] = useState<Outcome[]>([])
  const seq = useRef(0)

  const report = useCallback((o: OutcomeSpec) => {
    const id = ++seq.current
    // Newest first, and bounded: an operator working through a list should see
    // the last few outcomes, not a transcript that pushes the list off-screen.
    setItems((xs) => [{ ...o, id }, ...xs].slice(0, 5))
    return id
  }, [])

  const dismiss = useCallback((id: number) => {
    setItems((xs) => xs.filter((x) => x.id !== id))
  }, [])

  const replace = useCallback((id: number, next: OutcomeSpec) => {
    setItems((xs) => xs.map((x) => (x.id === id ? { ...next, id } : x)))
  }, [])

  return { items, report, dismiss, replace }
}

export function OutcomeStrip({
  items,
  dismiss,
  replace,
}: {
  items: Outcome[]
  dismiss: (id: number) => void
  replace: (id: number, next: OutcomeSpec) => void
}) {
  if (items.length === 0) return null
  return (
    <div className="flex flex-col gap-2">
      {items.map((item) => (
        <OutcomeRow key={item.id} item={item} dismiss={dismiss} replace={replace} />
      ))}
    </div>
  )
}

function OutcomeRow({
  item,
  dismiss,
  replace,
}: {
  item: Outcome
  dismiss: (id: number) => void
  replace: (id: number, next: OutcomeSpec) => void
}) {
  const [left, setLeft] = useState(UNDO_SECONDS)
  const [undoing, setUndoing] = useState(false)
  const [expanded, setExpanded] = useState(false)
  const undo = item.undo

  // The countdown is driven from a wall-clock deadline rather than by
  // decrementing on each tick: a background tab throttles timers to once a
  // minute, and a counter that only moves when the tab is focused would offer
  // an eight-second undo forty minutes after the fact.
  useEffect(() => {
    if (!undo) return
    const started = Date.now()
    setLeft(UNDO_SECONDS)
    const id = setInterval(() => {
      const remaining = UNDO_SECONDS - Math.floor((Date.now() - started) / 1000)
      setLeft(remaining > 0 ? remaining : 0)
    }, 250)
    return () => clearInterval(id)
  }, [undo])

  // Successes clear themselves; warnings and failures are the record and stay
  // until someone has read them.
  const settled = item.tone === 'ok' || item.tone === 'neutral' || item.tone === 'accent'
  const offering = !!undo && left > 0
  useEffect(() => {
    if (!settled || offering || undoing) return
    const id = setTimeout(() => dismiss(item.id), undo ? 600 : 8000)
    return () => clearTimeout(id)
  }, [settled, offering, undoing, undo, item.id, dismiss])

  const runUndo = async () => {
    if (!undo) return
    setUndoing(true)
    try {
      replace(item.id, await undo.run())
    } catch (e) {
      // undo.run is meant to catch its own failures and return them as an
      // outcome. This is the backstop, so a throw cannot end as silence.
      replace(item.id, {
        tone: 'crit',
        message: `The undo did not go through: ${(e as Error).message}. Nothing was reversed — check the list.`,
      })
    } finally {
      setUndoing(false)
    }
  }

  const failures = (item.results ?? []).filter((r) => !r.ok)
  const shown = expanded ? item.results ?? [] : failures

  return (
    <div
      role={item.tone === 'crit' ? 'alert' : 'status'}
      className={`flex flex-col gap-1.5 rounded-lg border border-line px-3 py-2.5 ${toneQuiet[item.tone]}`}
    >
      <div className="flex items-start gap-2.5">
        <span className={`mt-1.5 inline-block h-2 w-2 shrink-0 rounded-full ${toneFill[item.tone]}`} aria-hidden />
        <p className="min-w-0 flex-1 text-sm text-fg">{item.message}</p>
        {offering && (
          <button
            type="button"
            onClick={runUndo}
            disabled={undoing}
            className="shrink-0 rounded-md border border-line px-2 py-1 text-xs font-medium tabnums text-fg transition-colors hover:bg-hover disabled:opacity-50 pointer-coarse:min-h-11"
          >
            {undoing ? 'Undoing…' : `${undo?.label ?? 'Undo'} · ${left}`}
          </button>
        )}
        <button
          type="button"
          onClick={() => dismiss(item.id)}
          aria-label="Dismiss this message"
          className="shrink-0 rounded-md px-1 text-fg-muted transition-colors hover:bg-hover hover:text-fg pointer-coarse:min-h-11 pointer-coarse:px-2"
        >
          <span aria-hidden>×</span>
        </button>
      </div>

      {item.results && item.results.length > 0 && (
        <div className="pl-[1.125rem]">
          {failures.length > 0 && !expanded && (
            <p className="text-xs text-fg-muted">
              {failures.length} of {item.results.length} did not go through:
            </p>
          )}
          <ul className="mt-0.5 max-h-40 overflow-y-auto">
            {shown.map((r) => (
              <li key={r.target} className="flex flex-wrap items-baseline gap-x-2 py-0.5 text-xs">
                <span className={`inline-block h-1.5 w-1.5 shrink-0 self-center rounded-full ${r.ok ? toneFill.ok : toneFill.crit}`} aria-hidden />
                <span className="break-all font-mono text-fg">{r.target}</span>
                <span className="min-w-0 text-fg-muted">{r.message}</span>
              </li>
            ))}
          </ul>
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            className="mt-0.5 rounded-md text-xs font-medium text-fg-muted underline-offset-2 hover:underline pointer-coarse:min-h-11"
          >
            {expanded ? 'Show only what failed' : `Show all ${item.results.length}`}
          </button>
        </div>
      )}
    </div>
  )
}
