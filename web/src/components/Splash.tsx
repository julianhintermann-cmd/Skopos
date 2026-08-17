import { useEffect, useRef, useState } from 'react'

// The startup animation: sonar boot → sweep → wordmark → the mark flies home.
//
// This is an OVERLAY, not a screen. The real application mounts underneath it
// from the first frame and is what gets revealed — there is no stand-in
// dashboard, no placeholder numbers, no invented device names. Skopos' whole
// claim is that what it shows you was measured, and a splash that paints a
// plausible-looking network for six seconds would be the one screen in the
// product that lies. It also means there is no second copy of the shell to
// keep in sync with the real one.
//
// The choreography ends exactly on Logo.tsx: same viewBox, same radii, the
// stroke weights glide to 1.5/1 and the blip settles into the same 3.2-second
// breath the real mark uses. At the end of the flight the animated mark is
// sitting on top of the real one, pixel for pixel, and cross-fades out. The
// handoff is invisible because there is nothing to see.

// Cues, in seconds from mount. Named after what happens, not when.
const CUE = { sweep: 1.4, word: 3.0, reveal: 4.0 }
const TOTAL = 6.6

// The reveal, broken out because four things overlap inside it and the order
// is the whole effect: the mark leaves before the curtain lifts, so the app
// appears behind a mark already in motion rather than under a static one.
const TRAVEL = { start: CUE.reveal + 0.15, end: CUE.reveal + 1.75 }
const CURTAIN = { start: CUE.reveal + 0.3, end: CUE.reveal + 1.95 }
const HANDOFF = { start: TRAVEL.end, end: TRAVEL.end + 0.4 }
// The overlay stops swallowing clicks well before it unmounts. Waiting for the
// last frame would mean a second of a visibly-ready app refusing the pointer.
const INERT_AT = CUE.reveal + 1.0

// Reduced motion gets the destination without the journey: the finished mark,
// held long enough to read, then gone. Not a shortened animation — none.
const STILL = { hold: 0.5, fade: 0.3 }

// Where the brand sits in the real shell. Both shells carry these, so the
// flight lands correctly on the sidebar (26px), the collapsed rail, or the
// mobile header (22px) without this file knowing which one is mounted.
const DEST_MARK = '[data-sk-brand-mark]'
const DEST_WORD = '[data-sk-brand-word]'

const LETTERS = ['S', 'K', 'O', 'P', 'O', 'S']

const clamp01 = (x: number) => (x < 0 ? 0 : x > 1 ? 1 : x)
const outCubic = (t: number) => 1 - Math.pow(1 - t, 3)
const inOutQuart = (t: number) => (t < 0.5 ? 8 * t * t * t * t : 1 - Math.pow(-2 * t + 2, 4) / 2)
const outBack = (t: number) => {
  const c1 = 1.70158
  return 1 + (c1 + 1) * Math.pow(t - 1, 3) + c1 * Math.pow(t - 1, 2)
}

const seg = (t: number, start: number, end: number) =>
  end <= start ? (t >= end ? 1 : 0) : clamp01((t - start) / (end - start))
const enter = (t: number, start: number, dur = 0.5) => outCubic(seg(t, start, start + dur))
const glide = (t: number, from: number, to: number, start: number, end: number) =>
  from + (to - from) * inOutQuart(seg(t, start, end))
const pop = (t: number, start: number, dur = 0.45) => outBack(seg(t, start, start + dur))

// A leg of the flight: how far to move and how much to shrink, measured rather
// than assumed. transform-origin is the element's own top-left, so a top-left
// delta plus a width ratio lands it exactly on the target at p = 1.
interface Leg {
  dx: number
  dy: number
  s: number
}

function legTo(from: HTMLElement | null, selector: string): Leg | null {
  const to = document.querySelector(selector)
  if (!from || !to) return null
  const a = from.getBoundingClientRect()
  const b = to.getBoundingClientRect()
  // A zero-width target is a shell that is mounted but not laid out, and a
  // ratio against it would fling the mark off-screen.
  if (a.width < 1 || b.width < 1) return null
  return { dx: b.left - a.left, dy: b.top - a.top, s: b.width / a.width }
}

// flightStyle turns a leg and a progress into a transform. With no leg — the
// shell has not mounted, or the rail hides the wordmark — the element stays
// put and dissolves instead. Failing to find the target must never strand a
// mark in the middle of the screen.
function flightStyle(leg: Leg | null, p: number, fade: number) {
  if (!leg) {
    return { transform: `scale(${1 - 0.08 * p})`, opacity: (1 - p) * fade }
  }
  return {
    transform: `translate(${leg.dx * p}px, ${leg.dy * p}px) scale(${1 + (leg.s - 1) * p})`,
    opacity: fade,
  }
}

export function Splash() {
  const [t, setT] = useState(0)
  const [done, setDone] = useState(false)
  const markRef = useRef<HTMLDivElement>(null)
  const wordRef = useRef<HTMLDivElement>(null)
  // Measured once, at the frame the flight starts — early enough that the
  // shell exists, late enough that the letter-spacing has stopped changing the
  // wordmark's width underneath the measurement.
  const flight = useRef<{ mark: Leg | null; word: Leg | null } | null>(null)
  const still = useRef(
    typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches,
  )
  const total = still.current ? STILL.hold + STILL.fade : TOTAL

  useEffect(() => {
    let raf = 0
    const t0 = performance.now()

    const frame = (now: number) => {
      const elapsed = (now - t0) / 1000
      if (elapsed >= total) {
        setDone(true)
        return
      }
      setT(elapsed)
      raf = requestAnimationFrame(frame)
    }
    raf = requestAnimationFrame(frame)

    // Any deliberate input ends it. This plays on every load by design, and a
    // six-second animation you cannot dismiss stops being a flourish the third
    // time you open the page in a hurry. It doubles as the accessibility
    // escape: a Tab press dismisses the overlay rather than moving focus into
    // an application hidden behind it.
    const skip = () => setDone(true)
    window.addEventListener('pointerdown', skip)
    window.addEventListener('keydown', skip)
    // A tab hidden mid-flight resumes on a wall clock it never watched. Jump to
    // the end instead of replaying a reveal nobody saw.
    const onHide = () => {
      if (document.hidden) setDone(true)
    }
    document.addEventListener('visibilitychange', onHide)

    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('pointerdown', skip)
      window.removeEventListener('keydown', skip)
      document.removeEventListener('visibilitychange', onHide)
    }
  }, [total])

  if (done) return null

  if (still.current) {
    const out = 1 - enter(t, STILL.hold, STILL.fade)
    return (
      <Stage opacity={out} inert>
        <Brand />
      </Stage>
    )
  }

  const R = CUE.reveal
  const WM = CUE.word
  const SW = CUE.sweep

  if (t >= TRAVEL.start && !flight.current) {
    flight.current = { mark: legTo(markRef.current, DEST_MARK), word: legTo(wordRef.current, DEST_WORD) }
  }
  const p = inOutQuart(seg(t, TRAVEL.start, TRAVEL.end))
  const handoff = 1 - enter(t, HANDOFF.start, HANDOFF.end - HANDOFF.start)
  const curtain = 1 - enter(t, CURTAIN.start, CURTAIN.end - CURTAIN.start)

  // Stroke geometry. Large and slim while the mark owns the screen, settling on
  // Logo.tsx's own numbers exactly as it reaches 26px — the transform scales
  // the stroke too, so these end values are what makes the handoff seamless.
  const sw = glide(t, 0.85, 1.5, TRAVEL.start, TRAVEL.end)
  const lw = glide(t, 0.62, 1, TRAVEL.start, TRAVEL.end)
  const blipR = glide(t, 1.9, 2.4, TRAVEL.start, TRAVEL.end)
  const dotR = glide(t, 1.3, 1.6, TRAVEL.start, TRAVEL.end)

  const dot = pop(t, 0.5, 0.5)
  const sweepOp = enter(t, SW - 0.15, 0.3)
  const rot = -430 * (1 - inOutQuart(seg(t, SW - 0.1, WM + 0.1)))
  const wedgeOp = sweepOp * (1 - enter(t, R + 0.3, 0.6))

  // The contact. After it lands the blip breathes on the same 3.2s cycle
  // Logo.tsx animates, so the value is already correct when the real mark
  // takes over.
  const ping = WM - 0.25
  const blipScale = pop(t, ping, 0.5)
  const pingP = enter(t, ping, 0.7)
  const pingOp = t > ping && pingP < 1 ? (1 - pingP) * 0.7 : 0
  const pulse = t > ping ? 0.575 + 0.325 * Math.cos(((t - ping) / 3.2) * 2 * Math.PI) : 0

  // Letter-spacing opens wide and closes to the 0.3em the real wordmark uses.
  // The negative margin cancels the trailing letter-space so the word stays
  // optically centred under the mark without padding the measured box — the
  // flight's scale is a width ratio, and padding on one side of it would land
  // the word a hair off.
  const tracking = glide(t, 0.72, 0.3, WM, WM + 0.7)
  const tagOp = enter(t, WM + 0.4, 0.5) * (1 - enter(t, R + 0.05, 0.35))
  const glow = enter(t, 0.3, 0.8) * (1 - enter(t, R + 0.1, 0.5))

  const ring = (at: number, r: number, op: number) => {
    const e = enter(t, at, 0.6)
    return (
      <g transform={`translate(22 22) scale(${0.55 + 0.45 * e}) translate(-22 -22)`}>
        <circle cx="22" cy="22" r={r} stroke="currentColor" strokeWidth={sw} opacity={op * e} />
      </g>
    )
  }

  return (
    <Stage opacity={1} curtain={curtain} inert={t >= INERT_AT}>
      {/* A breathing wash of the accent behind the mark. Built from the accent
          token rather than a literal so it reads in both themes. */}
      {/* The centring lives in the inline transform, not in Tailwind's
          -translate-x-1/2. In v4 those utilities emit the separate `translate`
          property, which composes with `transform` instead of being overridden
          by it — the pair shifted this by -50% twice and parked the glow in the
          top-left corner. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute left-1/2 top-1/2 rounded-full"
        style={{
          width: 'min(56vw, 34rem)',
          height: 'min(56vw, 34rem)',
          background:
            'radial-gradient(circle, color-mix(in srgb, var(--accent) 12%, transparent) 0%, transparent 62%)',
          opacity: glow,
          transform: `translate(-50%, -50%) scale(${1 + 0.04 * Math.sin(t * 1.2)})`,
        }}
      />

      <div
        ref={markRef}
        aria-hidden="true"
        style={{
          ...flightStyle(flight.current?.mark ?? null, p, handoff),
          transformOrigin: '0 0',
          width: 'var(--sk-mark)',
          height: 'var(--sk-mark)',
        }}
      >
        <svg
          width="100%"
          height="100%"
          viewBox="0 0 44 44"
          fill="none"
          style={{ color: 'var(--accent)', display: 'block', overflow: 'visible' }}
        >
          <defs>
            <linearGradient id="sk-splash-sweep" x1="0" y1="1" x2="1" y2="0">
              <stop offset="0%" stopColor="var(--accent)" stopOpacity="0" />
              <stop offset="70%" stopColor="var(--accent)" stopOpacity="0.16" />
              <stop offset="100%" stopColor="var(--accent-strong)" stopOpacity="0.42" />
            </linearGradient>
          </defs>
          {ring(0.1, 7, 0.9)}
          {ring(0.28, 13.5, 0.45)}
          {ring(0.46, 20, 0.2)}
          <g transform={`rotate(${rot} 22 22)`}>
            <path
              d="M22,22 L29.56,8.94 A15.13,15.13 0 0 1 36.87,19.34 Z"
              fill="url(#sk-splash-sweep)"
              opacity={wedgeOp}
            />
            <line
              x1="22"
              y1="22"
              x2="36"
              y2="8"
              stroke="currentColor"
              strokeWidth={lw}
              strokeLinecap="round"
              opacity={0.35 * sweepOp}
            />
          </g>
          <circle
            cx="31"
            cy="13"
            r={blipR + pingP * 6}
            fill="none"
            stroke="var(--accent-strong)"
            strokeWidth="0.5"
            opacity={pingOp}
          />
          <g transform={`translate(31 13) scale(${blipScale}) translate(-31 -13)`}>
            <circle cx="31" cy="13" r={blipR} fill="currentColor" opacity={pulse} />
          </g>
          <g transform={`translate(22 22) scale(${dot}) translate(-22 -22)`}>
            <circle cx="22" cy="22" r={dotR} fill="currentColor" />
          </g>
        </svg>
      </div>

      <div
        ref={wordRef}
        aria-hidden="true"
        className="font-mono font-semibold uppercase"
        style={{
          ...flightStyle(flight.current?.word ?? null, p, handoff),
          transformOrigin: '0 0',
          marginTop: 'calc(var(--sk-mark) * 0.1)',
          marginRight: `-${tracking}em`,
          fontSize: 'calc(var(--sk-mark) * 0.2456)',
          lineHeight: 1.1,
          letterSpacing: `${tracking}em`,
          whiteSpace: 'nowrap',
          color: 'var(--text)',
        }}
      >
        {LETTERS.map((ch, i) => {
          const e = enter(t, WM + 0.04 + i * 0.055, 0.4)
          return (
            <span
              key={i}
              style={{
                display: 'inline-block',
                opacity: e,
                filter: `blur(${(1 - e) * 5}px)`,
                transform: `translateY(${(1 - e) * 7}px)`,
              }}
            >
              {ch}
            </span>
          )
        })}
      </div>

      <div
        aria-hidden="true"
        className="font-mono"
        style={{
          marginTop: 'calc(var(--sk-mark) * 0.14)',
          fontSize: 'calc(var(--sk-mark) * 0.08)',
          letterSpacing: '0.02em',
          color: 'var(--muted)',
          opacity: tagOp,
        }}
      >
        σκοπός — the watcher
      </div>
    </Stage>
  )
}

// Stage is the curtain and the geometry. The mark's size is a single custom
// property everything else is a ratio of, so the composition holds from a
// phone to a desktop without a breakpoint anywhere in this file.
function Stage({
  children,
  opacity,
  curtain = 1,
  inert = false,
}: {
  children: React.ReactNode
  opacity: number
  curtain?: number
  inert?: boolean
}) {
  return (
    <div
      // A live region rather than silence: the application is behind this for
      // several seconds and a screen reader should say why.
      role="status"
      aria-label="Starting Skopos"
      className="fixed inset-0 z-[100] flex flex-col items-center justify-center overflow-hidden"
      style={{
        // The curtain is the background alone. The mark keeps its own opacity
        // so it can still be flying while the application shows through.
        background: `color-mix(in srgb, var(--bg) ${curtain * 100}%, transparent)`,
        opacity,
        pointerEvents: inert ? 'none' : 'auto',
        paddingBottom: '6vh',
        // Clamped so the mark never dominates a phone or gets lost on a
        // desktop; 180px is the size the choreography was drawn at.
        ['--sk-mark' as string]: 'clamp(6.5rem, 22vmin, 11.25rem)',
      }}
    >
      {children}
    </div>
  )
}

// The finished mark, for people who asked not to be animated at.
function Brand() {
  return (
    <>
      <svg
        aria-hidden="true"
        width="var(--sk-mark)"
        height="var(--sk-mark)"
        viewBox="0 0 44 44"
        fill="none"
        style={{ color: 'var(--accent)', width: 'var(--sk-mark)', height: 'var(--sk-mark)' }}
      >
        <circle cx="22" cy="22" r="20" stroke="currentColor" strokeWidth="0.85" opacity="0.2" />
        <circle cx="22" cy="22" r="13.5" stroke="currentColor" strokeWidth="0.85" opacity="0.45" />
        <circle cx="22" cy="22" r="7" stroke="currentColor" strokeWidth="0.85" opacity="0.9" />
        <line x1="22" y1="22" x2="36" y2="8" stroke="currentColor" strokeWidth="0.62" opacity="0.35" />
        <circle cx="31" cy="13" r="1.9" fill="currentColor" opacity="0.9" />
        <circle cx="22" cy="22" r="1.3" fill="currentColor" />
      </svg>
      <div
        aria-hidden="true"
        className="font-mono font-semibold uppercase"
        style={{
          marginTop: 'calc(var(--sk-mark) * 0.1)',
          marginRight: '-0.3em',
          fontSize: 'calc(var(--sk-mark) * 0.2456)',
          lineHeight: 1.1,
          letterSpacing: '0.3em',
          color: 'var(--text)',
        }}
      >
        Skopos
      </div>
    </>
  )
}
