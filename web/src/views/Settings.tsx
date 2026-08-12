import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useFetch } from '../lib/useFetch'
import { api, type CFStatus, type Health } from '../lib/api'
import { Card, CardHeader, Button, Pill, TextInput } from '../components/ui'
import { useTheme } from '../lib/theme'

export function Settings({ onUnauthorized, canWrite }: { onUnauthorized: () => void; canWrite: boolean }) {
  const health = useFetch<Health>('/api/health', { pollMs: 15000, onUnauthorized })
  const cf = useFetch<CFStatus>('/api/integrations/cloudflare', { onUnauthorized })

  return (
    <div className="flex flex-col gap-4">
      <Appearance />

      <Card>
        <CardHeader title="Integrations" sub="connect external services from here — no YAML editing" />
        <div className="flex items-center justify-between gap-3 px-4 py-3" style={{ borderTop: '1px solid var(--border)' }}>
          <div className="flex items-center gap-3">
            <CloudflareMark />
            <div>
              <div className="font-medium">Cloudflare</div>
              <div className="text-xs" style={{ color: 'var(--muted)' }}>
                Monitor request traffic for your own domains
              </div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {cf.data?.connected ? (
              <Pill tone="good">{cf.data.zones.length} zone{cf.data.zones.length === 1 ? '' : 's'}</Pill>
            ) : (
              <Pill tone="neutral">Not connected</Pill>
            )}
            <Link to="/cloudflare">
              <Button>{cf.data?.connected ? 'Manage' : 'Connect'}</Button>
            </Link>
          </div>
        </div>
        <AbuseIPDB onUnauthorized={onUnauthorized} canWrite={canWrite} />
      </Card>

      {canWrite && <Notifications />}

      <Card>
        <CardHeader title="About" sub="Skopos — the watcher" />
        <div className="grid grid-cols-2 gap-px px-4 pb-4 sm:grid-cols-3">
          <Meta label="Version" value={health.data?.version || 'dev'} />
          <Meta label="Capture" value={health.data?.capture || '—'} />
          <Meta label="Firewall" value={health.data?.firewall || '—'} />
        </div>
        <div className="flex flex-wrap gap-4 px-4 pb-4 text-sm">
          <a href="https://github.com/julianhintermann-cmd/skopos" target="_blank" rel="noreferrer" style={{ color: 'var(--accent-strong)' }} className="underline">
            Source & docs
          </a>
          <a href="/api/docs" target="_blank" rel="noreferrer" style={{ color: 'var(--accent-strong)' }} className="underline">
            API reference
          </a>
        </div>
      </Card>
    </div>
  )
}

function Appearance() {
  const { theme, setTheme } = useTheme()
  const options: { value: 'system' | 'light' | 'dark'; label: string }[] = [
    { value: 'system', label: 'System' },
    { value: 'light', label: 'Light' },
    { value: 'dark', label: 'Dark' },
  ]
  return (
    <Card className="px-4 py-3.5">
      <CardHeader title="Appearance" sub="dark is the default for a monitor on a second screen" />
      <div className="mt-2 inline-flex rounded-md border p-0.5" style={{ borderColor: 'var(--border)' }}>
        {options.map((o) => (
          <button
            key={o.value}
            onClick={() => setTheme(o.value)}
            className="rounded px-3 py-1 text-sm font-medium transition-colors"
            style={
              theme === o.value
                ? { background: 'var(--accent-tint)', color: 'var(--accent-strong)' }
                : { color: 'var(--muted)' }
            }
          >
            {o.label}
          </button>
        ))}
      </div>
    </Card>
  )
}

// AbuseIPDB connects an API key for abuse scores in alert lookups. The key is
// verified against the service, then sealed at rest — same handling as the
// Cloudflare token.
function AbuseIPDB({ onUnauthorized, canWrite }: { onUnauthorized: () => void; canWrite: boolean }) {
  const { data, refresh } = useFetch<{ configured: boolean }>('/api/integrations/abuseipdb', { onUnauthorized })
  const [key, setKey] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  const connect = async () => {
    setBusy(true)
    setErr('')
    try {
      await api.post('/api/integrations/abuseipdb', { key: key.trim() })
      setKey('')
      refresh()
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  const disconnect = async () => {
    await api.del('/api/integrations/abuseipdb').catch(() => {})
    refresh()
  }

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3" style={{ borderTop: '1px solid var(--border)' }}>
      <div className="flex items-center gap-3">
        <span className="flex h-6 w-6 items-center justify-center rounded font-mono text-xs font-bold" style={{ background: 'var(--crit-tint)', color: 'var(--crit)' }}>
          !
        </span>
        <div>
          <div className="font-medium">AbuseIPDB</div>
          <div className="text-xs" style={{ color: 'var(--muted)' }}>
            Abuse scores for alert sources ("who is this?")
          </div>
        </div>
      </div>
      <div className="flex items-center gap-2">
        {data?.configured ? (
          <>
            <Pill tone="good">Connected</Pill>
            {canWrite && <Button variant="danger" onClick={disconnect}>Remove</Button>}
          </>
        ) : canWrite ? (
          <>
            <div className="w-52">
              <TextInput value={key} onChange={setKey} mono type="password" placeholder="AbuseIPDB API key" disabled={busy} />
            </div>
            <Button onClick={connect} disabled={busy || !key.trim()}>
              {busy ? 'Verifying…' : 'Connect'}
            </Button>
          </>
        ) : (
          <Pill tone="neutral">Not connected</Pill>
        )}
        {err && <span className="text-xs" style={{ color: 'var(--crit)' }}>{err}</span>}
      </div>
    </div>
  )
}

function Notifications() {
  const [result, setResult] = useState('')
  const send = async () => {
    setResult('sending…')
    try {
      const r = await api.post<{ ok: boolean; error?: string }>('/api/notify/test')
      setResult(r.ok ? 'sent ✓' : `failed: ${r.error}`)
    } catch (e) {
      setResult((e as Error).message)
    }
  }
  return (
    <Card className="px-4 py-3.5">
      <CardHeader title="Notifications" sub="verify your ntfy / webhook setup" />
      <div className="mt-2 flex items-center gap-3">
        <Button onClick={send}>Send test notification</Button>
        {result && <span className="text-sm" style={{ color: 'var(--muted)' }}>{result}</span>}
      </div>
    </Card>
  )
}

function Meta({ label, value }: { label: string; value: string }) {
  return (
    <div className="py-2">
      <div className="font-mono text-[0.62rem] font-semibold uppercase tracking-[0.1em]" style={{ color: 'var(--muted)' }}>
        {label}
      </div>
      <div className="mt-0.5 text-sm font-medium">{value}</div>
    </div>
  )
}

function CloudflareMark() {
  return (
    <svg width="26" height="26" viewBox="0 0 24 24" fill="none" aria-hidden>
      <path d="M16.5 16.5H7a3.5 3.5 0 0 1-.4-6.98A4.5 4.5 0 0 1 15 9.2a3 3 0 0 1 4.2 2.8 3 3 0 0 1-2.7 4.5z" fill="#f6821f" opacity="0.9" />
    </svg>
  )
}
