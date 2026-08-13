import { useMemo, useState } from 'react'
import { useFetch } from '../lib/useFetch'
import type { DomainStat } from '../lib/api'
import { Card, CardHeader, Spinner, EmptyState } from '../components/ui'
import { SheetSelect } from '../components/mobile'
import { useIsMobile } from '../lib/useIsMobile'
import { formatBytes, formatCount } from '../lib/format'

interface DomainsResponse {
  from: string
  to: string
  domains: DomainStat[] | null
}

const windows = [
  { label: '1h', hint: 'Last hour' },
  { label: '24h', hint: 'Last 24 hours' },
  { label: '7d', hint: 'Last 7 days' },
]

export function Domains({ onUnauthorized }: { onUnauthorized: () => void }) {
  const [win, setWin] = useState('24h')
  const isMobile = useIsMobile()
  const { data, loading, error } = useFetch<DomainsResponse>(`/api/domains?window=${win}&limit=100`, {
    pollMs: 30000,
    onUnauthorized,
  })

  const domains = useMemo(() => data?.domains ?? [], [data])
  const max = domains.length > 0 ? domains[0].bytes : 1

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-1.5">
        {isMobile ? (
          <SheetSelect
            value={win}
            label="Time range"
            options={windows.map((w) => ({ value: w.label, label: w.label, hint: w.hint }))}
            onChange={setWin}
          />
        ) : (
          windows.map((w) => (
            <button
              key={w.label}
              onClick={() => setWin(w.label)}
              className="rounded-md px-3 py-1 text-xs font-medium"
              style={
                w.label === win
                  ? { background: 'var(--accent-tint)', color: 'var(--accent-strong)' }
                  : { background: 'var(--surface-2)', color: 'var(--muted)' }
              }
            >
              {w.label}
            </button>
          ))
        )}
      </div>

      <Card>
        <CardHeader
          title="Domains"
          sub="names your devices actually asked for — learned from DNS answers and TLS handshakes on the wire"
        />
        <div className="px-4 pb-4">
          {loading && !data ? (
            <Spinner />
          ) : error ? (
            <EmptyState>Could not load domains: {error}</EmptyState>
          ) : domains.length === 0 ? (
            <EmptyState>
              No domains yet. Skopos learns them from DNS and mDNS answers and TLS server names as they pass
              the wire — give it a few minutes of traffic.
            </EmptyState>
          ) : (
            <ul className="flex flex-col gap-1.5">
              {domains.map((d) => (
                <li key={d.name} className="flex flex-col gap-1">
                  <div className="flex items-baseline justify-between gap-3 text-sm">
                    <span className="min-w-0 truncate font-medium">{d.name}</span>
                    <span className="shrink-0 font-mono text-xs tabnums" style={{ color: 'var(--muted)' }}>
                      {formatBytes(d.bytes)} · {formatCount(d.flows)} flows
                      {d.devices > 1 && ` · ${d.devices} devices`}
                    </span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full" style={{ background: 'var(--surface-2)' }}>
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: `${Math.max(1.5, (d.bytes / max) * 100)}%`,
                        background: 'var(--accent)',
                      }}
                    />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </Card>
    </div>
  )
}
