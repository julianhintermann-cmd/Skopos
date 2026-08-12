import { useEffect, useState } from 'react'

const QUERY = '(max-width: 767px)'

// useIsMobile reports whether the viewport is phone-sized, reactively. The
// app renders a dedicated mobile shell and per-view card layouts below this
// width — a separate experience, not a squeezed desktop.
export function useIsMobile(): boolean {
  const [mobile, setMobile] = useState(() => window.matchMedia(QUERY).matches)
  useEffect(() => {
    const mq = window.matchMedia(QUERY)
    const onChange = () => setMobile(mq.matches)
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [])
  return mobile
}
