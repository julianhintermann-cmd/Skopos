import type { ReactNode } from 'react'
import { useFetch } from '../lib/useFetch'
import type { Health } from '../lib/api'

// The page title, and under it the one qualifier that changes what its numbers
// mean.
export function PageTitle({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div>
      <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
      {children && (
        <p className="mt-0.5 text-xs" style={{ color: 'var(--muted)' }}>
          {children}
        </p>
      )}
    </div>
  )
}

// CaptureScopeNote says what "all traffic" means on this machine.
//
// It is not a persistent banner: a banner is scrolled past within a day and on
// a phone it permanently costs the top of every screen. It goes under the
// title of the two pages whose numbers are volume claims about a network — Now
// and Traffic — where it is read at the moment it matters, and on the capture
// chip everywhere else.
export function CaptureScopeNote() {
  const { data, loading } = useFetch<Health>('/api/health', { pollMs: 60000 })

  // No claim while the answer is still on its way.
  if (loading && !data) return null
  if (!data) return <>Capture scope unknown — Skopos cannot read its own health.</>
  return data.mirror ? (
    <>Watching the whole segment via a mirror port.</>
  ) : (
    <>Watching traffic that passes this machine — devices talking straight out through your router are not counted.</>
  )
}
