import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import QRCode from 'qrcode'
import { useFetch } from '../lib/useFetch'
import { api, type CFStatus, type Health } from '../lib/api'
import { Card, CardHeader, Button, Pill, TextInput, KeyValue, useToast } from '../components/ui'
import { useTheme } from '../lib/theme'
import { AISettings } from '../components/AISettings'
import { RuntimeSettings } from '../components/RuntimeSettings'
import { ConfigCard } from '../components/ConfigCard'
import { Glossary } from '../components/settingsHelp'
import { PageTitle } from '../components/PageTitle'

export function Settings({ onUnauthorized, canWrite }: { onUnauthorized: () => void; canWrite: boolean }) {
  const health = useFetch<Health>('/api/health', { pollMs: 15000, onUnauthorized })
  const cf = useFetch<CFStatus>('/api/integrations/cloudflare', { onUnauthorized })

  return (
    <div className="flex flex-col gap-4">
      {/* This view had no h1 at all, so a screen reader arriving from the nav
          landed in a list of h2 cards with nothing naming the page. */}
      <PageTitle title="Settings">
        what this Skopos is configured with, and the parts of it you can change without a restart
      </PageTitle>

      {/* Above Protection on purpose: whether the file was read at all decides
          what every value under it means. */}
      <ConfigCard
        onUnauthorized={onUnauthorized}
        cloudflare={cf.data ? { connected: cf.data.connected, zones: cf.data.zones.length } : null}
        cloudflareError={cf.error}
      />

      <RuntimeSettings onUnauthorized={onUnauthorized} canWrite={canWrite} />

      <Glossary />

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
        <ReputationSources />
      </Card>

      <AISettings canWrite={canWrite} />

      <TwoFactor onUnauthorized={onUnauthorized} canWrite={canWrite} />

      {canWrite && <Notifications />}

      <Card>
        <CardHeader title="About" sub="Skopos — the watcher" />
        {/* KeyValue renders a null as words. These three used to fall back to
            'dev' and two em-dashes, so a health request that never landed was
            drawn as a running build with an unnamed capture mode. */}
        <div className="px-4 pb-4">
          <KeyValue
            columns={3}
            items={[
              { label: 'Version', value: health.data?.version || null },
              { label: 'Capture', value: health.data?.capture || null },
              { label: 'Firewall', value: health.data?.firewall || null },
            ]}
          />
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

// TwoFactor manages TOTP enrollment: scan the QR (or copy the secret) into an
// authenticator app, confirm with a live code. Only meaningful when the login
// itself is enabled.
function TwoFactor({ onUnauthorized, canWrite }: { onUnauthorized: () => void; canWrite: boolean }) {
  const { data, refresh } = useFetch<{ supported: boolean; enabled: boolean }>('/api/auth/totp', { onUnauthorized })
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null)
  const [qr, setQr] = useState('')
  const [code, setCode] = useState('')
  const [err, setErr] = useState('')

  useEffect(() => {
    if (setup?.uri) {
      QRCode.toDataURL(setup.uri, { margin: 1, width: 192 }).then(setQr).catch(() => setQr(''))
    } else {
      setQr('')
    }
  }, [setup])

  const start = async () => {
    setErr('')
    try {
      setSetup(await api.post<{ secret: string; uri: string }>('/api/auth/totp/setup'))
    } catch (e) {
      setErr((e as Error).message)
    }
  }
  const enable = async () => {
    setErr('')
    try {
      await api.post('/api/auth/totp/enable', { code })
      setSetup(null)
      setCode('')
      refresh()
    } catch (e) {
      setErr((e as Error).message)
    }
  }
  const disable = async () => {
    setErr('')
    try {
      await api.post('/api/auth/totp/disable', { code })
      setCode('')
      refresh()
    } catch (e) {
      setErr((e as Error).message)
    }
  }

  return (
    <Card>
      <CardHeader
        title="Two-factor authentication"
        sub="a one-time code from your authenticator app, on top of the password"
        right={data?.enabled ? <Pill tone="good">Enabled</Pill> : <Pill tone="neutral">Off</Pill>}
      />
      <div className="px-4 pb-4">
        {!data?.supported ? (
          <p className="text-sm" style={{ color: 'var(--muted)' }}>
            The login itself is disabled (<code className="font-mono text-xs">auth.mode: none</code>). Enable
            <code className="font-mono text-xs"> single_admin</code> in config.yaml first — 2FA guards the login.
          </p>
        ) : data.enabled ? (
          canWrite && (
            <div className="flex flex-wrap items-center gap-2">
              <div className="w-36">
                <TextInput value={code} onChange={(v) => setCode(v.replace(/\D/g, '').slice(0, 6))} mono placeholder="123456" />
              </div>
              <Button variant="danger" onClick={disable} disabled={code.length !== 6}>
                Disable 2FA
              </Button>
              <span className="text-xs" style={{ color: 'var(--muted)' }}>Enter a current code to confirm.</span>
            </div>
          )
        ) : setup ? (
          <div className="flex flex-wrap items-start gap-5">
            {qr && (
              <img
                src={qr}
                alt="TOTP enrollment QR code"
                width={160}
                height={160}
                className="rounded-md"
                style={{ background: '#fff', padding: 6 }}
              />
            )}
            <div className="flex min-w-0 flex-1 flex-col gap-2 text-sm">
              <p>Scan the code with Google Authenticator, Aegis or any TOTP app — or add the secret manually:</p>
              <code className="w-fit rounded px-2 py-1 font-mono text-xs" style={{ background: 'var(--surface-2)' }}>
                {setup.secret}
              </code>
              <p className="text-xs" style={{ color: 'var(--muted)' }}>
                Then confirm with the 6-digit code the app shows. If you ever lose the authenticator, reset by
                deleting the <code className="font-mono">totp_*</code> rows from the meta table in skopos.db.
              </p>
              <div className="flex items-center gap-2">
                <div className="w-36">
                  <TextInput value={code} onChange={(v) => setCode(v.replace(/\D/g, '').slice(0, 6))} mono placeholder="123456" />
                </div>
                <Button variant="primary" onClick={enable} disabled={code.length !== 6}>
                  Confirm & enable
                </Button>
                <Button onClick={() => setSetup(null)}>Cancel</Button>
              </div>
            </div>
          </div>
        ) : (
          canWrite && <Button onClick={start}>Set up 2FA</Button>
        )}
        {err && <p className="mt-2 text-xs" style={{ color: 'var(--crit)' }}>{err}</p>}
      </div>
    </Card>
  )
}

// ReputationSources documents where "who is this?" answers come from. Both
// sources are open and keyless, so there is nothing to connect — the card
// exists so the operator knows what is being queried on their behalf.
function ReputationSources() {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3" style={{ borderTop: '1px solid var(--border)' }}>
      <div className="flex items-center gap-3">
        <span className="flex h-6 w-6 items-center justify-center rounded font-mono text-xs font-bold" style={{ background: 'var(--accent-tint)', color: 'var(--accent-strong)' }}>
          ?
        </span>
        <div>
          <div className="font-medium">IP reputation</div>
          <div className="text-xs" style={{ color: 'var(--muted)' }}>
            RDAP for ownership, DShield (SANS Internet Storm Center) for attack history
          </div>
        </div>
      </div>
      <Pill tone="good">Always on</Pill>
    </div>
  )
}

// Whether a channel is configured is answered at rest by the Configuration
// card, from the server. This is the other half — whether a configured channel
// can actually be reached — and it can only be answered by sending something.
function Notifications() {
  const toast = useToast()
  const [sending, setSending] = useState(false)

  // The outcome used to be written into a bare <span> beside the button: no
  // live region, so a screen reader was told nothing about whether the
  // notification went out. Same fix as the identical card on System.
  const send = async () => {
    setSending(true)
    try {
      const r = await api.post<{ ok: boolean; error?: string }>('/api/notify/test')
      toast.show(
        r.ok
          ? { message: 'Test notification sent.', tone: 'ok' }
          : { message: `Test notification failed: ${r.error}`, tone: 'crit', ttlMs: 9000 },
      )
    } catch (e) {
      toast.show({ message: `Test notification failed: ${(e as Error).message}`, tone: 'crit', ttlMs: 9000 })
    } finally {
      setSending(false)
    }
  }

  return (
    <Card className="px-4 py-3.5">
      <CardHeader title="Notifications" sub="whether a configured channel can actually be reached" />
      <div className="mt-2">
        <Button onClick={() => void send()} loading={sending}>
          Send test notification
        </Button>
      </div>
    </Card>
  )
}

function CloudflareMark() {
  return (
    <svg width="26" height="26" viewBox="0 0 24 24" fill="none" aria-hidden>
      <path d="M16.5 16.5H7a3.5 3.5 0 0 1-.4-6.98A4.5 4.5 0 0 1 15 9.2a3 3 0 0 1 4.2 2.8 3 3 0 0 1-2.7 4.5z" fill="#f6821f" opacity="0.9" />
    </svg>
  )
}
