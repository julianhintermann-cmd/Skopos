import { useState } from 'react'
import { useFetch } from '../lib/useFetch'
import { api, type BlocksResponse, type SettingsResponse, type RuntimeSettings as RS } from '../lib/api'
import { Card, CardHeader, Button, Pill, TextInput, Spinner } from './ui'

// ns converts a Go duration (nanoseconds on the wire) to a human string, and
// back. The API accepts either, so the UI sends the readable form.
function toDurationString(ns: number): string {
  if (ns <= 0) return '0s'
  const secs = Math.round(ns / 1e9)
  if (secs % 3600 === 0) return `${secs / 3600}h`
  if (secs % 60 === 0) return `${secs / 60}m`
  return `${secs}s`
}

// RuntimeSettings edits the configuration subset that applies without a
// restart. The YAML stays the baseline; every change here is an override the
// operator can drop again with "Reset to config.yaml".
export function RuntimeSettings({ onUnauthorized, canWrite }: { onUnauthorized: () => void; canWrite: boolean }) {
  const { data, loading, refresh } = useFetch<SettingsResponse>('/api/settings', { onUnauthorized })
  // Enforcement state has to come from the firewall, not from the string in
  // the settings payload. Reading the config back to itself meant this card
  // could show a green "enforce" pill while the Firewall view showed the
  // degraded banner — the app contradicting itself about the same fact.
  const blocks = useFetch<BlocksResponse>('/api/blocks', { pollMs: 15000, onUnauthorized })
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  const eff = data?.effective
  const overridden = new Set(data?.overridden ?? [])

  const send = async (patch: Record<string, unknown>) => {
    setBusy(true)
    setErr('')
    try {
      await api.post('/api/settings', patch)
      refresh()
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const reset = async () => {
    setBusy(true)
    setErr('')
    try {
      await api.del('/api/settings')
      refresh()
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  if (loading && !data) {
    return (
      <Card>
        <CardHeader title="Protection" sub="applies immediately — no restart" />
        <Spinner />
      </Card>
    )
  }
  if (!eff) return null

  const enforcing = blocks.data?.enforcing ?? false
  const kernel = blocks.data?.kernel

  return (
    <Card>
      <CardHeader
        title="Protection"
        sub="changes apply immediately — no restart, no YAML editing"
        right={
          overridden.size > 0 && canWrite ? (
            <Button onClick={reset} disabled={busy}>
              Reset to config.yaml
            </Button>
          ) : undefined
        }
      />

      <Row
        label="Enforcement"
        hint={
          enforcing
            ? 'Blocks are applied in the kernel — traffic from blocked addresses and countries is dropped.'
            : 'Blocks are recorded and counted, but nothing is dropped. Arm this when the numbers look right.'
        }
        overridden={overridden.has('enforcement')}
      >
        {canWrite ? (
          <div className="flex items-center gap-1.5">
            {(['observe', 'enforce'] as const).map((mode) => (
              <button
                key={mode}
                onClick={() => send({ enforcement: mode })}
                disabled={busy}
                className="rounded-md px-3 py-1.5 text-xs font-medium"
                style={
                  eff.enforcement === mode
                    ? {
                        background: mode === 'enforce' ? 'var(--good-tint)' : 'var(--warn-tint)',
                        color: mode === 'enforce' ? 'var(--good)' : 'var(--warn)',
                      }
                    : { background: 'var(--surface-2)', color: 'var(--muted)' }
                }
              >
                {mode === 'enforce' ? 'Enforce' : 'Observe'}
              </button>
            ))}
          </div>
        ) : (
          <Pill tone={enforcing ? 'good' : 'warn'}>{eff.enforcement}</Pill>
        )}
      </Row>

      {eff.enforcement === 'enforce' && kernel && !kernel.ok && (
        <div className="px-4 pb-3 text-sm" style={{ color: 'var(--warn)' }}>
          Set to enforce, but the kernel does not currently hold the rules
          {kernel.failing_since ? ` (since ${new Date(kernel.failing_since).toLocaleString()})` : ''}
          {kernel.error ? `: ${kernel.error}` : '.'} Skopos keeps retrying.
        </div>
      )}

      <DurationRow
        label="Automatic block lifetime"
        hint="How long a detector-created block stays before it expires in the kernel."
        value={eff.block_ttl}
        overridden={overridden.has('block_ttl')}
        canWrite={canWrite}
        busy={busy}
        onSave={(v) => send({ block_ttl: v })}
      />

      <DurationRow
        label="Alert cooldown"
        hint="At most one notification per detector and source within this window; extras are counted."
        value={eff.cooldown}
        overridden={overridden.has('cooldown')}
        canWrite={canWrite}
        busy={busy}
        onSave={(v) => send({ cooldown: v })}
      />

      <AllowlistRow
        value={eff.allowlist ?? []}
        overridden={overridden.has('allowlist')}
        canWrite={canWrite}
        busy={busy}
        onSave={(list) => send({ allowlist: list })}
      />

      <DetectorRow
        label="Port-scan detection"
        hint={`${eff.portscan.external.ports} ports or ${eff.portscan.external.targets} targets from outside within ${toDurationString(eff.portscan.window)}`}
        enabled={eff.portscan.enabled}
        overridden={overridden.has('portscan.enabled')}
        canWrite={canWrite}
        busy={busy}
        onToggle={(on) => send({ 'portscan.enabled': on })}
      />

      <DetectorRow
        label="Connection-rate detection"
        hint={`${eff.rate.max_new_connections} new connections or ${eff.rate.max_packets_per_second} pkt/s per source within ${toDurationString(eff.rate.window)}`}
        enabled={eff.rate.enabled}
        overridden={overridden.has('rate.enabled')}
        canWrite={canWrite}
        busy={busy}
        onToggle={(on) => send({ 'rate.enabled': on })}
      />

      {err && (
        <p className="px-4 pb-3 text-xs" style={{ color: 'var(--crit)' }}>
          {err}
        </p>
      )}
    </Card>
  )
}

function Row({
  label,
  hint,
  overridden,
  children,
}: {
  label: string
  hint: string
  overridden: boolean
  children: React.ReactNode
}) {
  return (
    <div
      className="flex flex-wrap items-center justify-between gap-3 px-4 py-3"
      style={{ borderTop: '1px solid var(--border)' }}
    >
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 font-medium">
          {label}
          {overridden && <Pill tone="accent">changed here</Pill>}
        </div>
        <div className="mt-0.5 text-xs" style={{ color: 'var(--muted)' }}>
          {hint}
        </div>
      </div>
      {children}
    </div>
  )
}

function DurationRow({
  label,
  hint,
  value,
  overridden,
  canWrite,
  busy,
  onSave,
}: {
  label: string
  hint: string
  value: number
  overridden: boolean
  canWrite: boolean
  busy: boolean
  onSave: (v: string) => void
}) {
  const [draft, setDraft] = useState('')
  const current = toDurationString(value)
  return (
    <Row label={label} hint={hint} overridden={overridden}>
      {canWrite ? (
        <div className="flex items-center gap-2">
          <div className="w-28">
            <TextInput value={draft || current} onChange={setDraft} mono placeholder={current} />
          </div>
          <Button onClick={() => onSave(draft || current)} disabled={busy || !draft || draft === current}>
            Save
          </Button>
        </div>
      ) : (
        <span className="font-mono text-sm">{current}</span>
      )}
    </Row>
  )
}

function AllowlistRow({
  value,
  overridden,
  canWrite,
  busy,
  onSave,
}: {
  value: string[]
  overridden: boolean
  canWrite: boolean
  busy: boolean
  onSave: (list: string[]) => void
}) {
  const [entry, setEntry] = useState('')
  return (
    <div className="px-4 py-3" style={{ borderTop: '1px solid var(--border)' }}>
      <div className="flex items-center gap-2 font-medium">
        Never-block allowlist
        {overridden && <Pill tone="accent">changed here</Pill>}
      </div>
      <div className="mt-0.5 text-xs" style={{ color: 'var(--muted)' }}>
        These addresses are never blocked, whatever a detector says. Your gateway is protected in addition,
        always.
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        {value.length === 0 && (
          <span className="text-sm" style={{ color: 'var(--muted)' }}>
            Nothing beyond the gateway.
          </span>
        )}
        {value.map((v) => (
          <span
            key={v}
            className="inline-flex items-center gap-1.5 rounded-full py-0.5 pl-2.5 pr-1 font-mono text-xs"
            style={{ background: 'var(--surface-2)', color: 'var(--text)' }}
          >
            {v}
            {canWrite && (
              <button
                onClick={() => onSave(value.filter((x) => x !== v))}
                aria-label={`Remove ${v}`}
                className="rounded-full px-1"
                disabled={busy}
              >
                ×
              </button>
            )}
          </span>
        ))}
      </div>
      {canWrite && (
        <div className="mt-2 flex items-center gap-2">
          <div className="w-56">
            <TextInput
              value={entry}
              onChange={setEntry}
              mono
              placeholder="192.168.1.10 or 10.0.0.0/8"
              onKeyDown={(e) => {
                if (e.key === 'Enter' && entry.trim()) {
                  onSave([...value, entry.trim()])
                  setEntry('')
                }
              }}
            />
          </div>
          <Button
            onClick={() => {
              onSave([...value, entry.trim()])
              setEntry('')
            }}
            disabled={busy || !entry.trim()}
          >
            Add
          </Button>
        </div>
      )}
    </div>
  )
}

function DetectorRow({
  label,
  hint,
  enabled,
  overridden,
  canWrite,
  busy,
  onToggle,
}: {
  label: string
  hint: string
  enabled: boolean
  overridden: boolean
  canWrite: boolean
  busy: boolean
  onToggle: (on: boolean) => void
}) {
  return (
    <Row label={label} hint={hint} overridden={overridden}>
      {canWrite ? (
        <Button onClick={() => onToggle(!enabled)} disabled={busy} variant={enabled ? 'danger' : 'primary'}>
          {enabled ? 'Disable' : 'Enable'}
        </Button>
      ) : (
        <Pill tone={enabled ? 'good' : 'neutral'}>{enabled ? 'On' : 'Off'}</Pill>
      )}
    </Row>
  )
}

export type { RS }
