// One copy of the Cloudflare mark. Two identical inline SVGs existed, in
// Settings and in Cloudflare, each with the orange hardcoded. It is the only
// brand colour Skopos does not get to choose, which is why it is a token
// (--sk-brand-cf) rather than an exception to the no-hex rule.
export function CloudflareMark({ size = 26 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden>
      <path
        d="M16.5 16.5H7a3.5 3.5 0 0 1-.4-6.98A4.5 4.5 0 0 1 15 9.2a3 3 0 0 1 4.2 2.8 3 3 0 0 1-2.7 4.5z"
        fill="var(--sk-brand-cf)"
        opacity="0.9"
      />
    </svg>
  )
}
