import { useEffect, useState } from 'react'
import { verdictNow, type EnforcementState, type Verdict } from '../lib/contracts'
import { toneFill, toneQuiet, toneText, type Tone } from './ui/tone'
import { formatRelative, formatTime } from '../lib/format'

// What the kernel was last found to hold, in words, with the time it was found.
//
// Until now no view read this. Every screen that claimed protection read
// `enforcing` — a configuration flag ANDed with "netlink opens" — so a page
// could say "12 enforced" over a kernel that held nothing, and did. The
// verdict fixes the claim; the timestamp fixes the other half, because a
// reading with no time on it is indistinguishable from a reading taken days
// ago. A page that cannot say when it last checked has to say that too.
//
// Six verdicts, and the one that costs the most care is `unverified`: it means
// nobody has looked in three verify intervals — six minutes — and it is drawn
// as neither good nor bad, because it is neither. Painting it green invents
// protection; painting it red invents a fault.

export interface KernelWords {
  tone: Tone
  // Two or three words, for a pill or a stat tile.
  label: string
  // What the kernel was found to hold.
  sentence: string
  // When it was last read, as a whole sentence. Never empty.
  when: string
  // The same fact in a few words, for a subtitle.
  whenShort: string
  // What to do about it, when there is something to do.
  detail?: string
  // The absolute timestamp, for a title attribute — relative times are
  // readable and imprecise, and precision matters in an incident.
  at?: string
}

// useNow re-renders on a slow tick so the age keeps moving.
//
// Without it the "checked 41s ago" beside a green verdict freezes at whatever
// the last successful poll said. The polling loop backs off on failure and
// gives up on a sleeping tab, which is exactly when an unmoving timestamp is
// most dangerous: the page would keep vouching for a reading it has no way of
// knowing is still recent.
function useNow(everyMs = 15000): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), everyMs)
    return () => clearInterval(id)
  }, [everyMs])
  return now
}

const verdictTone: Record<Verdict, Tone> = {
  observing: 'neutral',
  enforcing: 'ok',
  partial: 'warn',
  degraded: 'crit',
  // Grey, not amber and not green. Not knowing is its own state.
  unverified: 'unknown',
  unable: 'crit',
}

export function kernelWords(k: EnforcementState | undefined, nowMs: number): KernelWords {
  if (!k) {
    return {
      tone: 'unknown',
      label: 'Kernel unknown',
      sentence:
        'Skopos has not said what the kernel holds, so nothing on this page can tell you whether a block is being applied.',
      when: 'Nothing has been read back.',
      whenShort: 'no reading',
    }
  }

  const verdict = verdictNow(k, nowMs)
  const tone = verdictTone[verdict] ?? 'unknown'
  const at = k.checked_at ? formatTime(k.checked_at) : undefined
  const rel = k.checked_at ? formatRelative(k.checked_at) : null
  const checked = rel ? `checked ${rel}` : 'never checked'
  const staleMinutes = Math.round(k.stale_after_seconds / 60)
  // StaleAfter is three verify intervals, so the interval falls out of it. Two
  // constants that must agree eventually will not.
  const verifyMinutes = Math.max(1, Math.round(staleMinutes / 3))
  const failing = k.failing_since ? ` It has been failing since ${formatTime(k.failing_since)}.` : ''

  switch (verdict) {
    case 'observing':
      return {
        tone,
        label: 'Observe mode',
        sentence:
          'Nothing is being dropped. Blocks are recorded and counted, and by configuration the kernel holds no Skopos rules.',
        // Verify short-circuits in observe mode, so any timestamp on this
        // payload is the loop recording "nothing to check". Printing it as
        // evidence would be a reading that never happened.
        when: 'The kernel is not read back in observe mode — there is nothing to read back.',
        whenShort: 'nothing to verify',
        detail: 'Switch enforcement to enforce in Settings to make these blocks real.',
      }
    case 'enforcing':
      return {
        tone,
        label: 'Kernel holding',
        sentence: 'The kernel was read back and held every rule Skopos programmed.',
        when: `Read back ${rel}, at ${at}.`,
        whenShort: checked,
        at,
      }
    case 'partial':
      return {
        tone,
        label: 'Partly verified',
        sentence:
          'The table and chains were found, but the address sets were not among what was checked — whether the blocked addresses are in the kernel is unconfirmed.',
        when: `Last read back ${rel}, at ${at}.`,
        whenShort: checked,
        at,
      }
    case 'degraded':
      return {
        tone,
        label: 'Not holding',
        sentence:
          'Enforce is set and the kernel is not holding what Skopos programmed, so nothing is being dropped.',
        when: `Last read back ${rel ? `${rel}, at ${at}` : 'never'}.${failing}`,
        whenShort: checked,
        // k.error carries raw netlink wording ("file exists", "invalid
        // argument"), which reads as a crash rather than as a refusal. It
        // stays in the log.
        detail: 'The reason is in the Skopos log.',
        at,
      }
    case 'unable':
      return {
        tone,
        label: 'Cannot enforce',
        sentence: k.backend_up
          ? `Enforce is set and the ${k.backend} backend answers, but the skopos table, chains and sets are not in place — there is nothing for the rules to live in.`
          : `Enforce is set, but the ${k.backend} backend is unavailable, so no rule can reach the kernel at all.`,
        when: rel ? `Last read back ${rel}, at ${at}.` : 'The kernel has never been read back.',
        whenShort: checked,
        detail: k.backend_up
          ? 'Skopos rebuilds the base ruleset on its own; if this persists, the Skopos log says why.'
          : 'The container needs network_mode: host and the NET_ADMIN capability, and the kernel must have nf_tables.',
        at,
      }
    default:
      return {
        tone,
        label: 'Not verified',
        sentence: rel
          ? 'Nobody has read the kernel back recently, so what it holds right now is unknown. This is neither a fault nor an all-clear.'
          : 'The kernel has never been read back, so what it holds is unknown. This is neither a fault nor an all-clear.',
        when: rel
          ? `Last read back ${rel}, at ${at}. A reading stops counting as evidence after ${staleMinutes} minutes.`
          : 'The kernel has never been read back.',
        whenShort: checked,
        detail: rel
          ? `Skopos re-reads the kernel every ${verifyMinutes} minutes; three misses in a row look like this.`
          : `Skopos re-reads the kernel every ${verifyMinutes} minutes. If this does not change, the check is not running.`,
        at,
      }
  }
}

// dropsLabel is the heading over the per-block packet tally. "Dropped" is a
// claim about the kernel and may only be made when the kernel said so.
export function dropsLabel(k: EnforcementState | undefined, nowMs: number): string {
  if (!k) return 'Seen'
  switch (verdictNow(k, nowMs)) {
    case 'enforcing':
      return 'Dropped'
    case 'observing':
      return 'Would drop'
    default:
      return 'Seen'
  }
}

// dropsPhrase is the same fact in a sentence, for the phone cards.
export function dropsPhrase(k: EnforcementState | undefined, nowMs: number, packets: string): string {
  if (!k) return `${packets} seen`
  switch (verdictNow(k, nowMs)) {
    case 'enforcing':
      return `${packets} dropped`
    case 'observing':
      return `${packets} would have been dropped`
    default:
      return `${packets} seen — not confirmed dropped`
  }
}

// KernelVerdictPanel is the full statement: what the kernel holds, when that
// was established, and what to do about it. It replaces the two hand-rolled
// banners on Firewall, which inferred both from the configuration.
export function KernelVerdictPanel({ state }: { state: EnforcementState | undefined }) {
  const now = useNow()
  const w = kernelWords(state, now)
  return (
    <div
      // crit interrupts a screen reader; the quieter states wait for a gap.
      role={w.tone === 'crit' ? 'alert' : 'status'}
      className={`flex items-start gap-3 rounded-lg border border-line px-4 py-3 ${toneQuiet[w.tone]}`}
    >
      <span className={`mt-1.5 inline-block h-2 w-2 shrink-0 rounded-full ${toneFill[w.tone]}`} aria-hidden />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
          <span className="text-sm font-semibold">{w.label}</span>
          <span className="text-xs opacity-80" title={w.at}>
            {w.whenShort}
          </span>
        </div>
        <p className="mt-0.5 text-sm text-fg">{w.sentence}</p>
        <p className="mt-0.5 text-xs text-fg-muted">
          {w.when}
          {w.detail ? ` ${w.detail}` : ''}
        </p>
      </div>
    </div>
  )
}

// KernelStatusLine is the compact form: a dot, the verdict, and when it was
// established. The timestamp is not optional here either — it is half the
// answer, and the half a configuration-sourced pill could never give.
export function KernelStatusLine({ state, prefix }: { state: EnforcementState | undefined; prefix?: string }) {
  const now = useNow()
  const w = kernelWords(state, now)
  return (
    <span className="inline-flex flex-wrap items-baseline gap-x-1.5" title={w.sentence}>
      <span className={`inline-block h-1.5 w-1.5 shrink-0 self-center rounded-full ${toneFill[w.tone]}`} aria-hidden />
      {prefix && <span className="text-xs text-fg-muted">{prefix}</span>}
      <span className={`text-xs font-medium ${toneText[w.tone]}`}>{w.label}</span>
      <span className="text-xs text-fg-muted" title={w.at}>
        · {w.whenShort}
      </span>
    </span>
  )
}
