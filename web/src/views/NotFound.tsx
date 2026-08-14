import { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Card } from '../components/ui'
import { EntityPalette } from '../components/EntityPalette'
import { NAV } from '../components/nav'
import { entityHref, useDeviceIndex } from '../lib/links'

// The 404.
//
// `path="*"` used to render the dashboard, so a typo silently became the home
// page and a broken bookmark looked like success. There is no redirect here,
// automatic or delayed: a silent redirect is exactly what hid the mistake, and
// showing a working page for an address the user did not ask for is a lie
// about what happened.
export function NotFound({ onUnauthorized }: { onUnauthorized?: () => void }) {
  const { pathname } = useLocation()
  const index = useDeviceIndex(onUnauthorized)
  const [searching, setSearching] = useState(false)

  // The one conditional kindness: if a segment of the path is an address, a
  // CIDR or a MAC, offer the page it belongs to.
  const guess = pathname
    .split('/')
    .map((s) => safeDecode(s))
    .filter(Boolean)
    .map((s) => ({ value: s, href: entityHref(s, index) }))
    .find((g) => g.href)

  return (
    <div className="flex flex-col gap-4">
      <Card className="px-5 py-6">
        <h1 className="text-xl font-semibold tracking-tight">There is no page at this address.</h1>
        <p className="mt-2 text-sm" style={{ color: 'var(--muted)' }}>
          Skopos was asked for
        </p>
        <p className="mt-1 break-all font-mono text-sm" style={{ color: 'var(--text)' }}>
          {pathname}
        </p>

        {guess && (
          <p className="mt-3 text-sm">
            Did you mean{' '}
            <Link to={guess.href!} className="font-medium hover:underline" style={{ color: 'var(--accent-strong)' }}>
              {guess.value}
            </Link>
            ?
          </p>
        )}

        <div className="mt-4 flex flex-wrap items-center gap-2">
          <Link
            to="/"
            className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-on-accent transition-colors hover:bg-accent-hover"
          >
            Go to Now
          </Link>
          <button
            type="button"
            onClick={() => setSearching(true)}
            className="rounded-md border px-3 py-1.5 text-sm font-medium"
            style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text)' }}
          >
            Search for it
          </button>
        </div>
      </Card>

      <Card>
        <div className="px-4 py-3">
          <div className="font-mono text-[0.58rem] font-semibold uppercase tracking-[0.18em]" style={{ color: 'var(--muted)' }}>
            What does exist
          </div>
          <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-sm">
            {NAV.map((n) => (
              <li key={n.to}>
                <Link to={n.to} className="hover:underline" style={{ color: 'var(--accent-strong)' }}>
                  {n.label}
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </Card>

      <EntityPalette
        open={searching}
        onClose={() => setSearching(false)}
        initialQuery={lastSegment(pathname)}
        onUnauthorized={onUnauthorized}
      />
    </div>
  )
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s)
  } catch {
    return s
  }
}

function lastSegment(path: string): string {
  const parts = path.split('/').filter(Boolean)
  return parts.length > 0 ? safeDecode(parts[parts.length - 1]) : ''
}
