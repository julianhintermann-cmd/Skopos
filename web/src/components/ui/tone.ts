// The tone vocabulary, and the Tailwind class strings each tone resolves to.
//
// These are written out as whole literal class names on purpose. Tailwind v4
// discovers utilities by scanning source text, so a template like
// `text-${tone}` would compile to nothing at all.

export type Tone = 'neutral' | 'accent' | 'ok' | 'warn' | 'crit' | 'unknown'
export type Size = 'sm' | 'md'

// 'good' was the 0.3 spelling; the token is `--sk-ok` now. Sixteen view call
// sites still say 'good' and they migrate with their views, not with this
// change — the same reasoning as the legacy alias block in index.css, and the
// same expiry date.
export type ToneInput = Tone | 'good'

export function toneOf(t: ToneInput | undefined): Tone {
  return t === 'good' ? 'ok' : (t ?? 'neutral')
}

// Foreground only — for text that sits directly on a surface.
export const toneText: Record<Tone, string> = {
  neutral: 'text-fg',
  accent: 'text-accent',
  ok: 'text-ok',
  warn: 'text-warn',
  crit: 'text-crit',
  unknown: 'text-unknown',
}

// Tinted background + matching foreground, for pills and badges. Every pair
// here is validated at ≥4.5:1 in both themes.
export const toneQuiet: Record<Tone, string> = {
  neutral: 'bg-raised text-fg-muted',
  accent: 'bg-accent-quiet text-accent',
  ok: 'bg-ok-quiet text-ok',
  warn: 'bg-warn-quiet text-warn',
  crit: 'bg-crit-quiet text-crit',
  unknown: 'bg-unknown-quiet text-unknown',
}

// Solid fill, for status dots and rules. Never the only channel carrying the
// meaning — a dot always sits beside a word.
export const toneFill: Record<Tone, string> = {
  neutral: 'bg-line-strong',
  accent: 'bg-accent',
  ok: 'bg-ok',
  warn: 'bg-warn',
  crit: 'bg-crit',
  unknown: 'bg-unknown',
}
