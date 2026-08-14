import { createContext, useContext, useEffect, useRef } from 'react'
import { useFetch } from './useFetch'
import type { BlocksResponse, Health } from './api'
import type { OverviewNow } from './contracts'
import { formatRelative } from './format'

// The three questions the strip answers, and the model behind them.
//
// Rule one of this file: unknown is a state, not a shade of bad. Four states
// per subsystem, and the absence of an answer is never rendered as good and
// never as bad. A grey "unknown" is a true statement about what Skopos knows;
// a green pill sourced from a failed request is not.

export type Tone = 'good' | 'warn' | 'crit' | 'neutral' | 'unknown' | 'loading'

export interface Chip {
  key: 'capture' | 'enforcement' | 'outstanding'
  tone: Tone
  // Short form for the chip itself.
  label: string
  // The full sentence, for the desktop tooltip and the phone sheet.
  detail: string
  href: string
  // Set when data is on screen but the last poll failed. This is what finally
  // consumes useFetch's `stale`, which had no readers at all across ~20 call
  // sites — a view could only hide the failure or blank the screen, and most
  // of them hid the failure.
  asOf?: string
}

export interface Status {
  chips: Chip[]
  // One sentence for the top of Now. Never a fabricated all-clear.
  verdict: { text: string; tone: Tone }
  mirror?: boolean
  // The overview payload the chips were built from, so Now can render its
  // talkers from the poll that is already running instead of opening a third
  // one against the same endpoint.
  overview: Fetched<OverviewNow>
}

export type Fetched<T> = { data: T | null; error: string | null; loading: boolean; stale: boolean }

// The strip lives in the shell and Now needs the same three answers for its
// verdict line. One provider, one set of polls: without it the two would race
// each other on /api/overview and disagree on screen.
export const StatusContext = createContext<Status | null>(null)

const pending: Fetched<OverviewNow> = { data: null, error: null, loading: true, stale: false }

// useStatus reads the shared status. Outside the provider it reports itself as
// still loading rather than inventing an answer.
export function useStatus(): Status {
  const ctx = useContext(StatusContext)
  if (ctx) return ctx
  return {
    chips: [],
    verdict: { text: 'Checking…', tone: 'loading' },
    overview: pending,
  }
}

// useAsOf remembers when data last arrived, so a stale chip can say how old
// the number it is still showing actually is.
function useAsOf(data: unknown): string | undefined {
  const at = useRef<Date | null>(null)
  useEffect(() => {
    if (data) at.current = new Date()
  }, [data])
  if (!at.current) return undefined
  return at.current.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hour12: false })
}

// useStatusValue does the polling. The shell calls it once and publishes the
// result through StatusContext.
export function useStatusValue(onUnauthorized?: () => void): Status {
  const overview = useFetch<OverviewNow>('/api/overview', { pollMs: 5000, onUnauthorized })
  const blocks = useFetch<BlocksResponse>('/api/blocks', { pollMs: 15000, onUnauthorized })
  const health = useFetch<Health>('/api/health', { pollMs: 30000 })
  const overviewAt = useAsOf(overview.data)
  const blocksAt = useAsOf(blocks.data)

  const chips: Chip[] = [
    captureChip(overview, health, overviewAt),
    enforcementChip(blocks, blocksAt),
    outstandingChip(overview, overviewAt),
  ]

  return { chips, verdict: verdictOf(chips), mirror: health.data?.mirror, overview }
}

function captureChip(
  overview: Fetched<OverviewNow>,
  health: Fetched<Health>,
  asOf: string | undefined,
): Chip {
  const base = { key: 'capture' as const, href: '/system' }

  if (health.data?.capture === 'demo') {
    return {
      ...base,
      tone: 'neutral',
      label: 'Demo data',
      detail: 'Skopos is running on generated traffic. Nothing here describes a real network.',
    }
  }
  if (overview.loading && !overview.data) {
    return { ...base, tone: 'loading', label: '', detail: 'Reading the capture state…' }
  }
  if (!overview.data) {
    return {
      ...base,
      tone: 'unknown',
      label: 'Capture unknown',
      detail: `Skopos could not read /api/overview${overview.error ? ` (${overview.error})` : ''}, so it cannot say whether it is capturing.`,
    }
  }

  const live = overview.data.live ?? {}
  // The server decides this. A rate that stops changing is not evidence of a
  // dead capture, and a client that guesses will eventually guess wrong in the
  // one direction that matters.
  const state = live.capture
  const packet = live.last_packet_at
    ? `last packet ${formatRelative(live.last_packet_at)}`
    : 'no packet has arrived since Skopos started'
  const sources =
    typeof live.sources_up === 'number' && typeof live.sources_total === 'number'
      ? ` ${live.sources_up} of ${live.sources_total} sources running.`
      : ''

  if (!state) {
    return {
      ...base,
      tone: 'unknown',
      label: 'Capture unknown',
      detail: 'This server does not report a capture state, so Skopos cannot vouch for the numbers on this page.',
      asOf: overview.stale ? asOf : undefined,
    }
  }
  const shape: Record<string, { tone: Tone; label: string; lead: string }> = {
    up: { tone: 'good', label: 'Capturing', lead: 'Capture is running.' },
    partial: { tone: 'warn', label: 'Capture partial', lead: 'Some capture sources are not running.' },
    down: { tone: 'crit', label: 'Capture down', lead: 'Capture is not running — nothing is being recorded.' },
    starting: { tone: 'neutral', label: 'Capture starting', lead: 'Capture is still starting up.' },
  }
  const s = shape[state] ?? { tone: 'unknown' as Tone, label: 'Capture unknown', lead: `The server reports capture as "${state}".` }
  return {
    ...base,
    tone: s.tone,
    label: s.label,
    detail: `${s.lead}${sources} ${packet}.`,
    asOf: overview.stale ? asOf : undefined,
  }
}

function enforcementChip(blocks: Fetched<BlocksResponse>, asOf: string | undefined): Chip {
  const base = { key: 'enforcement' as const, href: '/firewall' }
  if (blocks.loading && !blocks.data) {
    return { ...base, tone: 'loading', label: '', detail: 'Reading the firewall state…' }
  }
  if (!blocks.data) {
    return {
      ...base,
      tone: 'unknown',
      label: 'Firewall unknown',
      detail: `Skopos could not read /api/blocks${blocks.error ? ` (${blocks.error})` : ''}, so it cannot say whether anything is being dropped.`,
    }
  }

  const d = blocks.data
  const stale = blocks.stale ? asOf : undefined
  // "wanted but not ok" is the case a config-sourced pill can never express:
  // the setting says enforce and the kernel readback says otherwise.
  const kernelBroken = d.kernel ? d.kernel.wanted && !d.kernel.ok : d.enforcement === 'enforce' && !d.enforcing
  if (d.enforcement === 'enforce' && kernelBroken) {
    return {
      ...base,
      tone: 'crit',
      label: 'Firewall degraded',
      detail: `Enforce is set, but the kernel is not holding the rules${d.kernel?.error ? `: ${d.kernel.error}` : ''}. Blocks are recorded and nothing is dropped.`,
      asOf: stale,
    }
  }
  if (d.enforcement === 'enforce') {
    return { ...base, tone: 'good', label: 'Enforcing', detail: 'Blocks are applied in the kernel on this machine.', asOf: stale }
  }
  if (d.enforcement === 'observe') {
    return {
      ...base,
      tone: 'neutral',
      label: 'Observing',
      detail: 'Observe mode: blocks are recorded and counted, but no packet is dropped.',
      asOf: stale,
    }
  }
  return {
    ...base,
    tone: 'unknown',
    label: 'Firewall unknown',
    detail: 'The server did not say which enforcement mode it is in.',
    asOf: stale,
  }
}

function outstandingChip(overview: Fetched<OverviewNow>, asOf: string | undefined): Chip {
  const base = { key: 'outstanding' as const, href: '/alerts?unacked=1' }
  if (overview.loading && !overview.data) {
    return { ...base, tone: 'loading', label: '', detail: 'Counting outstanding alerts…' }
  }
  const n = overview.data?.unacked_alerts
  // The count is omitted, not zeroed, when its query failed. "0 unacked", in
  // green, is what an unreachable database used to look like.
  if (typeof n !== 'number') {
    return {
      ...base,
      tone: 'unknown',
      label: 'Alerts unknown',
      detail: `Skopos could not count outstanding alerts${overview.error ? ` (${overview.error})` : ''}.`,
      asOf: overview.stale ? asOf : undefined,
    }
  }
  if (n === 0) {
    return { ...base, tone: 'good', label: 'Nothing outstanding', detail: 'Every alert has been acknowledged.', asOf: overview.stale ? asOf : undefined }
  }
  return {
    ...base,
    tone: 'warn',
    label: `${n} outstanding`,
    detail: `${n} alert${n === 1 ? '' : 's'} ${n === 1 ? 'has' : 'have'} not been acknowledged.`,
    asOf: overview.stale ? asOf : undefined,
  }
}

// verdictOf composes the one sentence at the top of Now.
//
// The order is deliberate: what Skopos cannot see comes before what it can,
// because an all-clear assembled from two answers and one silence is a lie,
// and it is the exact lie a monitoring tool must never tell.
function verdictOf(chips: Chip[]): { text: string; tone: Tone } {
  if (chips.some((c) => c.tone === 'loading')) {
    return { text: 'Checking…', tone: 'loading' }
  }
  const unknown = chips.filter((c) => c.tone === 'unknown')
  const crit = chips.filter((c) => c.tone === 'crit')
  const warn = chips.filter((c) => c.tone === 'warn')

  const parts: string[] = []
  for (const c of [...crit, ...warn]) parts.push(c.detail)
  if (unknown.length > 0) {
    parts.push(
      `Skopos cannot answer for ${unknown.map((c) => c.key).join(' and ')} right now, so this page is not a clean bill of health.`,
    )
  }
  if (parts.length === 0) {
    const demo = chips.find((c) => c.key === 'capture' && c.label === 'Demo data')
    if (demo) return { text: demo.detail, tone: 'neutral' }
    return { text: 'Capturing, firewall as configured, nothing outstanding.', tone: 'good' }
  }
  const tone: Tone = crit.length > 0 ? 'crit' : unknown.length > 0 && warn.length === 0 ? 'unknown' : 'warn'
  return { text: parts.join(' '), tone }
}

// toneColor maps a chip tone to the design tokens. Colour is never the only
// carrier — every state also has distinct text — so the strip survives
// monochrome and colour-blind reading.
export function toneColor(tone: Tone): { fg: string; bg: string } {
  switch (tone) {
    case 'good':
      return { fg: 'var(--good)', bg: 'var(--good-tint)' }
    case 'warn':
      return { fg: 'var(--warn)', bg: 'var(--warn-tint)' }
    case 'crit':
      return { fg: 'var(--crit)', bg: 'var(--crit-tint)' }
    default:
      return { fg: 'var(--muted)', bg: 'var(--surface-2)' }
  }
}
