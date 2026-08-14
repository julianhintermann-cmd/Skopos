import { useEffect, useState } from 'react'

// Where the app changes shape, and why each boundary sits where it does.
//
// PHONE also matches on height. An iPhone in landscape is 844×390: wider than
// any width-only phone test, so it was handed the desktop sidebar and the row
// actions that sit off the end of an 861px table. A viewport 480px tall has no
// room for a sidebar whatever its width.
const PHONE = '(max-width: 767px), (max-height: 480px)'

// RAIL is the tier that did not exist. Everything from 768 to 1023 got the
// full 224px sidebar — 29% of an iPad portrait — because every responsive
// utility in the app started at lg, so there was a phone design, a 1280px
// design and nothing in between. The min-height clause keeps it disjoint from
// PHONE rather than relying on evaluation order.
const RAIL = '(min-width: 768px) and (max-width: 1023px) and (min-height: 481px)'

export type Tier = 'phone' | 'rail' | 'wide'

function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => window.matchMedia(query).matches)
  useEffect(() => {
    const mq = window.matchMedia(query)
    const onChange = () => setMatches(mq.matches)
    // Re-read on subscribe: between the initial render and this effect the
    // viewport can already have changed, and a rotation that lands in that gap
    // used to leave the shell in the wrong shape until the next resize.
    onChange()
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [query])
  return matches
}

// useIsMobile reports whether the viewport is phone-sized, reactively. The
// app renders a dedicated mobile shell and per-view card layouts below this
// width — a separate experience, not a squeezed desktop.
export function useIsMobile(): boolean {
  return useMediaQuery(PHONE)
}

// useLayoutTier picks the shell. Only Layout calls it; views ask useIsMobile,
// because a card layout is a phone answer and the rail is a chrome answer.
export function useLayoutTier(): Tier {
  const phone = useMediaQuery(PHONE)
  const rail = useMediaQuery(RAIL)
  return phone ? 'phone' : rail ? 'rail' : 'wide'
}
