import { useCallback, useEffect, useMemo, useState } from 'react'
import { api, type CFAnalytics, type CFStatus, type CFZone } from '../lib/api'
import { Card, CardHeader, StatTile, Spinner, EmptyState, Button, Pill, Toggle, TextInput } from '../components/ui'
import { CFAnalyticsChart } from '../components/CFAnalyticsChart'
import { RangeControl } from '../components/RangeControl'
import { apiWindow, useUrlRange, useUrlState } from '../lib/useUrlState'
import { formatBytes, formatCount } from '../lib/format'

const TOKEN_URL = 'https://dash.cloudflare.com/profile/api-tokens'

export function Cloudflare({ onUnauthorized, canWrite }: { onUnauthorized: () => void; canWrite: boolean }) {
  const [status, setStatus] = useState<CFStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    try {
      const s = await api.get<CFStatus>('/api/integrations/cloudflare')
      setStatus(s)
      setError('')
    } catch (e) {
      if ((e as { status?: number }).status === 401) return onUnauthorized()
      setError((e as Error).message)
    } finally {
      setLoading(false)
    }
  }, [onUnauthorized])

  useEffect(() => {
    load()
  }, [load])

  if (loading && !status) return <Spinner />
  if (error && !status) return <EmptyState>Could not load Cloudflare status: {error}</EmptyState>
  if (!status) return null

  if (!status.connected) {
    return <ConnectCard canWrite={canWrite} onConnected={load} />
  }
  return <Connected status={status} canWrite={canWrite} onChange={load} />
}

function ConnectCard({ canWrite, onConnected }: { canWrite: boolean; onConnected: () => void }) {
  const [token, setToken] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  const connect = async () => {
    if (!token.trim()) return
    setBusy(true)
    setErr('')
    try {
      await api.post('/api/integrations/cloudflare', { token: token.trim() })
      setToken('')
      onConnected()
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-4">
      <Card className="overflow-hidden">
        <div className="flex items-center gap-3 px-5 pt-5">
          <CloudflareMark />
          <div>
            <h2 className="text-lg font-semibold tracking-tight">Connect Cloudflare</h2>
            <p className="text-sm" style={{ color: 'var(--muted)' }}>
              Monitor request traffic for your own domains alongside your LAN.
            </p>
          </div>
        </div>

        <div className="px-5 py-4">
          <ol className="flex flex-col gap-2.5 text-sm">
            <Step n={1}>
              Open your{' '}
              <a href={TOKEN_URL} target="_blank" rel="noreferrer" style={{ color: 'var(--accent-strong)' }} className="font-medium underline">
                Cloudflare API tokens
              </a>{' '}
              page and choose <em>Create Token → Custom token</em>.
            </Step>
            <Step n={2}>
              Grant two read-only permissions:{' '}
              <code className="rounded px-1 py-0.5 font-mono text-xs" style={{ background: 'var(--surface-2)' }}>Zone · Analytics · Read</code>{' '}
              and{' '}
              <code className="rounded px-1 py-0.5 font-mono text-xs" style={{ background: 'var(--surface-2)' }}>Zone · Zone · Read</code>.
            </Step>
            <Step n={3}>Include the zones you want to watch, create the token, and paste it here.</Step>
          </ol>

          <div className="mt-4 flex flex-col gap-2">
            <TextInput
              value={token}
              onChange={setToken}
              mono
              type="password"
              placeholder="Cloudflare API token"
              disabled={!canWrite || busy}
              onKeyDown={(e) => e.key === 'Enter' && connect()}
            />
            <div className="flex items-center gap-3">
              <Button variant="primary" onClick={connect} disabled={!canWrite || busy || !token.trim()}>
                {busy ? 'Verifying…' : 'Connect'}
              </Button>
              {err && <span className="text-sm" style={{ color: 'var(--crit)' }}>{err}</span>}
              {!canWrite && <span className="text-sm" style={{ color: 'var(--muted)' }}>Read-only session — connecting needs write access.</span>}
            </div>
          </div>
        </div>

        <div className="px-5 py-3 text-xs" style={{ background: 'var(--surface-2)', color: 'var(--muted)' }}>
          The token is encrypted at rest and never leaves your NAS. Revoke it any time from the same
          Cloudflare page; Skopos only ever reads analytics.
        </div>
      </Card>
    </div>
  )
}

function Connected({ status, canWrite, onChange }: { status: CFStatus; canWrite: boolean; onChange: () => void }) {
  const monitored = useMemo(() => status.zones.filter((z) => z.monitored), [status.zones])
  const fallback = monitored[0]?.id ?? status.zones[0]?.id ?? ''
  // The chosen zone is in the URL, so "look at this zone" is a link someone
  // can send. An id that no longer exists falls back without rewriting what
  // the sender typed.
  const [zone, setZone] = useUrlState('zone', fallback, {
    valid: status.zones.map((z) => z.id),
    history: 'push',
  })
  const selected = status.zones.some((z) => z.id === zone) ? zone : fallback

  const disconnect = async () => {
    await api.del('/api/integrations/cloudflare').catch(() => {})
    onChange()
  }

  return (
    <div className="flex flex-col gap-4">
      <Card className="px-4 py-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <CloudflareMark size={22} />
            <div>
              <div className="flex items-center gap-2">
                <span className="font-semibold">Cloudflare connected</span>
                <Pill tone="good">{status.zones.length} zone{status.zones.length === 1 ? '' : 's'}</Pill>
              </div>
              <div className="font-mono text-xs" style={{ color: 'var(--muted)' }}>
                {status.token_id ? `token ${status.token_id.slice(0, 10)}…` : 'token active'}
                {status.expires_on ? ` · expires ${new Date(status.expires_on).toLocaleDateString()}` : ' · no expiry'}
              </div>
            </div>
          </div>
          {canWrite && (
            <Button variant="danger" onClick={disconnect}>Disconnect</Button>
          )}
        </div>
      </Card>

      {monitored.length === 0 ? (
        <EmptyState>No zones are being monitored. Turn one on below to see its traffic.</EmptyState>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-1.5">
            {monitored.map((z) => (
              <button
                key={z.id}
                onClick={() => setZone(z.id)}
                className="rounded-md px-3 py-1 text-sm font-medium"
                style={
                  z.id === selected
                    ? { background: 'var(--accent-tint)', color: 'var(--accent-strong)' }
                    : { background: 'var(--surface-2)', color: 'var(--muted)' }
                }
              >
                {z.name}
              </button>
            ))}
          </div>
          {selected && <ZoneAnalytics zoneID={selected} onUnauthorized={onChange} />}
        </>
      )}

      <ZoneList zones={status.zones} canWrite={canWrite} onChange={onChange} />
    </div>
  )
}

// Cloudflare's analytics API takes a coarser window than Skopos's own history,
// so this control offers a subset of the shared vocabulary rather than a
// fourth vocabulary of its own.
const CF_RANGES = ['24h', '7d', '30d'] as const

function ZoneAnalytics({ zoneID, onUnauthorized }: { zoneID: string; onUnauthorized: () => void }) {
  const { range, setRange } = useUrlRange('24h', CF_RANGES)
  const win = apiWindow(range)
  const [data, setData] = useState<CFAnalytics | null>(null)
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState('')

  useEffect(() => {
    let stop = false
    setLoading(true)
    const load = async () => {
      try {
        const d = await api.get<CFAnalytics>(`/api/integrations/cloudflare/analytics?zone=${zoneID}&window=${win}`)
        if (stop) return
        setData(d)
        setErr('')
      } catch (e) {
        if ((e as { status?: number }).status === 401) return onUnauthorized()
        if (!stop) setErr((e as Error).message)
      } finally {
        if (!stop) setLoading(false)
      }
    }
    load()
    const id = setInterval(load, 60000)
    return () => {
      stop = true
      clearInterval(id)
    }
  }, [zoneID, win, onUnauthorized])

  const points = data?.points ?? []
  const totals = useMemo(() => {
    let requests = 0, bytes = 0, cachedReq = 0, threats = 0
    for (const p of points) {
      requests += p.requests
      bytes += p.bytes
      cachedReq += p.cached_requests
      threats += p.threats
    }
    const cachePct = requests > 0 ? Math.round((cachedReq / requests) * 100) : 0
    return { requests, bytes, cachePct, threats }
  }, [points])

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <RangeControl range={range} setRange={setRange} allowed={CF_RANGES} label="Time window" />
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile label="Requests" value={formatCount(totals.requests)} tone="accent" hint={`last ${range}`} />
        <StatTile label="Data served" value={formatBytes(totals.bytes).split(' ')[0]} unit={formatBytes(totals.bytes).split(' ')[1]} />
        <StatTile label="Cache hit" value={`${totals.cachePct}`} unit="%" tone={totals.cachePct >= 50 ? 'good' : 'neutral'} />
        <StatTile label="Threats" value={formatCount(totals.threats)} tone={totals.threats > 0 ? 'crit' : 'good'} hint="blocked at the edge" />
      </div>

      <Card>
        <CardHeader title="Requests over time" sub={`${range} · total vs cached`} />
        <div className="px-2 pb-2">
          {loading && !data ? (
            <Spinner />
          ) : err ? (
            <EmptyState>Could not load analytics: {err}</EmptyState>
          ) : points.length > 0 ? (
            <CFAnalyticsChart points={points} />
          ) : (
            <EmptyState>No traffic reported for this window yet.</EmptyState>
          )}
        </div>
      </Card>
    </div>
  )
}

function ZoneList({ zones, canWrite, onChange }: { zones: CFZone[]; canWrite: boolean; onChange: () => void }) {
  const toggle = async (z: CFZone) => {
    await api.post(`/api/integrations/cloudflare/zones/${z.id}`, { monitored: !z.monitored }).catch(() => {})
    onChange()
  }
  return (
    <Card>
      <CardHeader title="Zones" sub="choose which domains to monitor" />
      <div className="flex flex-col">
        {zones.map((z) => (
          <div key={z.id} className="flex items-center justify-between gap-3 px-4 py-2.5" style={{ borderTop: '1px solid var(--border)' }}>
            <div className="min-w-0">
              <div className="truncate font-medium">{z.name}</div>
              <div className="font-mono text-xs" style={{ color: 'var(--muted)' }}>{z.status}</div>
            </div>
            <Toggle checked={z.monitored} disabled={!canWrite} onChange={() => toggle(z)} label={`Monitor ${z.name}`} />
          </div>
        ))}
      </div>
    </Card>
  )
}

function Step({ n, children }: { n: number; children: React.ReactNode }) {
  return (
    <li className="flex gap-2.5">
      <span
        className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full font-mono text-xs font-semibold"
        style={{ background: 'var(--accent-tint)', color: 'var(--accent-strong)' }}
      >
        {n}
      </span>
      <span>{children}</span>
    </li>
  )
}

// The Cloudflare wordmark cloud, in the brand orange so the integration is
// recognisable at a glance.
function CloudflareMark({ size = 34 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden>
      <path
        d="M16.5 16.5H7a3.5 3.5 0 0 1-.4-6.98A4.5 4.5 0 0 1 15 9.2a3 3 0 0 1 4.2 2.8 3 3 0 0 1-2.7 4.5z"
        fill="#f6821f"
        opacity="0.9"
      />
    </svg>
  )
}
