import { useState } from 'react'
import { useFetch } from '../lib/useFetch'
import { api, type Block } from '../lib/api'
import { Card, CardHeader, Spinner, EmptyState, Button, Pill } from '../components/ui'
import { Th, Td } from './Devices'
import { formatRelative, formatTime } from '../lib/format'

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
                    <Td mono>{b.Prefix}</Td>
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
