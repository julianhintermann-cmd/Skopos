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

// NARROW is a different question from either of the above, and it is asked by
// a view rather than by the shell: is there room for a wide table?
//
// Devices' table measures 994px with its controls at the 24px WCAG floor and
// 1107 once a touch screen grows them to 44. The rail gives it 678px at iPad
// portrait — 39% of every row past the right edge, and inside that 39% are
// wake, forget and details. ScrollArea makes that clipping honest; it does not
// make it reachable with a thumb. Below the width where the table genuinely
// fits, the card layout is the answer, so nothing is hidden at all.
const NARROW = '(max-width: 1279px)'

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

// useIsNarrow reports that a wide table will not fit, whatever shell is
// around it. A view with a table asks this; a view choosing a control asks
// useIsMobile. Keeping them separate is why the rail can stay a chrome answer.
export function useIsNarrow(): boolean {
  return useMediaQuery(NARROW)
}

// useLayoutTier picks the shell. Only Layout calls it; views ask useIsMobile,
// because a card layout is a phone answer and the rail is a chrome answer.
export function useLayoutTier(): Tier {
  const phone = useMediaQuery(PHONE)
  const rail = useMediaQuery(RAIL)
  return phone ? 'phone' : rail ? 'rail' : 'wide'
}
