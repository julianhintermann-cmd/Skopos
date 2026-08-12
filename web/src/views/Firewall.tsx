import { useState } from 'react'
import { useFetch } from '../lib/useFetch'
import { api, countryFlag, countryName, type Block, type GeoIPSummary } from '../lib/api'
import { Card, CardHeader, Spinner, EmptyState, Button, Pill, TextInput } from '../components/ui'
import { Th, Td } from './Devices'
import { useDeviceNames } from '../lib/deviceNames'
import { formatRelative, formatTime } from '../lib/format'

// blockName resolves a blocked prefix to a device name when it is a single
// host that the inventory knows (strip the /32 or /128 the API normalises to).
function blockName(names: Map<string, string>, prefix: string): string {
  const host = prefix.replace(/\/(32|128)$/, '')
  return names.get(host) ?? ''
}

export function Firewall({ onUnauthorized, canWrite }: { onUnauthorized: () => void; canWrite: boolean }) {
  const { data, loading, error, refresh } = useFetch<{ blocks: Block[] | null }>('/api/blocks', {
    pollMs: 5000,
    onUnauthorized,
  })
  const [prefix, setPrefix] = useState('')
  const [reason, setReason] = useState('')
  const [ttl, setTtl] = useState('')
  const [busy, setBusy] = useState(false)
  const [formError, setFormError] = useState('')
  const names = useDeviceNames(onUnauthorized)

  const blocks = data?.blocks ?? []

  const addBlock = async () => {
    setBusy(true)
    setFormError('')
    try {
      await api.post('/api/blocks', { prefix, reason, ttl })
      setPrefix('')
      setReason('')
      setTtl('')
      refresh()
    } catch (e) {
      setFormError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const unblock = async (p: string) => {
    await api.del(`/api/blocks?prefix=${encodeURIComponent(p)}`)
    refresh()
  }

  return (
    <div className="flex flex-col gap-4">
      {canWrite && (
        <Card className="px-4 py-3.5">
          <CardHeader title="Block an address" sub="IP or CIDR — never blocks the gateway or allowlist" />
          <div className="mt-2 flex flex-wrap items-end gap-2 px-0">
            <Field label="Prefix" value={prefix} onChange={setPrefix} placeholder="203.0.113.5 or 203.0.113.0/24" width="w-56" />
            <Field label="Reason" value={reason} onChange={setReason} placeholder="optional note" width="w-48" />
            <Field label="TTL" value={ttl} onChange={setTtl} placeholder="24h · blank = permanent" width="w-40" />
            <Button variant="primary" onClick={addBlock} disabled={busy || !prefix}>
              Block
            </Button>
          </div>
          {formError && <p className="mt-2 text-xs" style={{ color: 'var(--crit)' }}>{formError}</p>}
        </Card>
      )}

      <CountryBlocking canWrite={canWrite} onUnauthorized={onUnauthorized} />

      <Card>
        <CardHeader title="Active blocks" sub={`${blocks.length} in effect`} />
        {loading && !data ? (
          <Spinner />
        ) : error ? (
          <EmptyState>Could not load blocks: {error}</EmptyState>
        ) : blocks.length === 0 ? (
          <EmptyState>Nothing is blocked.</EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ color: 'var(--muted)' }}>
                  <Th>Prefix</Th>
                  <Th>Origin</Th>
                  <Th>Reason</Th>
                  <Th>Created</Th>
                  <Th>Expires</Th>
                  {canWrite && <Th> </Th>}
                </tr>
              </thead>
              <tbody>
                {blocks.map((b) => (
                  <tr key={b.ID} style={{ borderTop: '1px solid var(--border)' }}>
                    <Td mono>
                      {b.Prefix}
                      {blockName(names, b.Prefix) && (
                        <div className="font-sans text-xs" style={{ color: 'var(--muted)' }}>
                          {blockName(names, b.Prefix)}
                        </div>
                      )}
                    </Td>
                    <Td>
                      <Pill tone={b.Origin === 'manual' ? 'accent' : 'neutral'}>{b.Origin}</Pill>
                    </Td>
                    <Td muted>{b.Reason || '—'}</Td>
                    <Td muted>{formatTime(b.Created)}</Td>
                    <Td muted>{b.Expires ? formatRelative(b.Expires) : 'permanent'}</Td>
                    {canWrite && (
                      <Td>
                        <button
                          onClick={() => unblock(b.Prefix)}
                          className="text-xs font-medium"
                          style={{ color: 'var(--crit)' }}
                        >
                          Unblock
                        </button>
                      </Td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}

// CountryBlocking manages the blocked-country list. Blocking is reactive:
// inbound sources from listed countries are blocked the moment they appear
// (once enforcement is on), instead of loading half the internet's prefixes
// into the kernel.
function CountryBlocking({ canWrite, onUnauthorized }: { canWrite: boolean; onUnauthorized: () => void }) {
  const { data, refresh } = useFetch<GeoIPSummary>('/api/geoip/summary?window=1h', { onUnauthorized })
  const [input, setInput] = useState('')
  const [err, setErr] = useState('')
  const blocked = data?.blocked ?? []

  const save = async (countries: string[]) => {
    setErr('')
    try {
      await api.post('/api/geoip/blocked', { countries })
      setInput('')
      refresh()
    } catch (e) {
      if ((e as { status?: number }).status === 401) return onUnauthorized()
      setErr((e as Error).message)
    }
  }

  const add = () => {
    const code = input.trim().toUpperCase()
    if (!code) return
    save([...blocked, code])
  }

  return (
    <Card>
      <CardHeader
        title="Country blocking"
        sub="inbound sources from these countries are blocked on sight (when enforcement is on)"
      />
      <div className="flex flex-col gap-2.5 px-4 pb-4">
        <div className="flex flex-wrap items-center gap-1.5">
          {blocked.length === 0 && (
            <span className="text-sm" style={{ color: 'var(--muted)' }}>No countries blocked.</span>
          )}
          {blocked.map((c) => (
            <span
              key={c}
              className="inline-flex items-center gap-1.5 rounded-full py-0.5 pl-2 pr-1 text-xs font-medium"
              style={{ background: 'var(--crit-tint)', color: 'var(--crit)' }}
            >
              {countryFlag(c)} {countryName(c)}
              {canWrite && (
                <button
                  onClick={() => save(blocked.filter((x) => x !== c))}
                  aria-label={`Unblock ${countryName(c)}`}
                  className="rounded-full px-1 font-mono"
                >
                  ×
                </button>
              )}
            </span>
          ))}
        </div>
        {canWrite && (
          <div className="flex items-center gap-2">
            <div className="w-40">
              <TextInput
                value={input}
                onChange={setInput}
                mono
                placeholder="ISO code, e.g. RU"
                onKeyDown={(e) => e.key === 'Enter' && add()}
              />
            </div>
            <Button onClick={add} disabled={!input.trim()}>Block country</Button>
            {err && <span className="text-xs" style={{ color: 'var(--crit)' }}>{err}</span>}
          </div>
        )}
      </div>
    </Card>
  )
}

function Field({
  label,
  value,
  onChange,
  placeholder,
  width,
}: {
  label: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
  width: string
}) {
  return (
    <label className={`flex flex-col gap-1 ${width}`}>
      <span className="font-mono text-[0.62rem] font-semibold uppercase tracking-[0.1em]" style={{ color: 'var(--muted)' }}>
        {label}
      </span>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="rounded-md border px-2.5 py-1.5 text-sm font-mono"
        style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text)' }}
      />
    </label>
  )
}
