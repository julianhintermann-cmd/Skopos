import { useState } from 'react'
import { useFetch } from '../lib/useFetch'
import { api, type Health, type AuditEntry } from '../lib/api'
import { Card, CardHeader, Spinner, EmptyState, Button, Pill } from '../components/ui'
import { Th, Td } from './Devices'
import { formatTime } from '../lib/format'

export function System({ onUnauthorized, canWrite }: { onUnauthorized: () => void; canWrite: boolean }) {
  const health = useFetch<Health>('/api/health', { pollMs: 5000, onUnauthorized })
  const audit = useFetch<{ audit: AuditEntry[] | null }>('/api/audit?limit=50', { pollMs: 10000, onUnauthorized })
  const [testResult, setTestResult] = useState<string>('')

  const sendTest = async () => {
    setTestResult('sending…')
    try {
      const r = await api.post<{ ok: boolean; error?: string }>('/api/notify/test')
      setTestResult(r.ok ? 'sent ✓' : `failed: ${r.error}`)
    } catch (e) {
      setTestResult((e as Error).message)
    }
  }

  const h = health.data
  const entries = audit.data?.audit ?? []

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader title="Health" sub="subsystem status" />
        {health.loading && !h ? (
          <Spinner />
        ) : !h ? (
          <EmptyState>Could not load health.</EmptyState>
        ) : (
          <div className="grid grid-cols-2 gap-px px-4 pb-4 sm:grid-cols-3" style={{ color: 'var(--text)' }}>
            <HealthItem label="Overall" ok={h.ok} value={h.ok ? 'Healthy' : 'Degraded'} />
            <HealthItem label="Capture" value={h.capture} neutral />
            <HealthItem label="Firewall" value={h.firewall} neutral />
            <HealthItem label="Enforcement" value={h.enforcing ? 'Enforcing' : 'Observe'} ok={h.enforcing} neutral={!h.enforcing} />
            <HealthItem label="Cold storage" ok={h.cold_storage_ok} value={h.cold_storage_ok ? 'Writable' : 'Unreachable'} />
            <HealthItem label="Version" value={h.version || 'dev'} neutral />
          </div>
        )}
      </Card>

      {canWrite && (
        <Card className="px-4 py-3.5">
          <CardHeader title="Notifications" sub="verify your ntfy / webhook setup" />
          <div className="mt-2 flex items-center gap-3">
            <Button onClick={sendTest}>Send test notification</Button>
            {testResult && <span className="text-sm" style={{ color: 'var(--muted)' }}>{testResult}</span>}
          </div>
        </Card>
      )}

      <Card>
        <CardHeader title="Audit log" sub="recent security-relevant actions" />
        {audit.loading && !audit.data ? (
          <Spinner />
        ) : entries.length === 0 ? (
          <EmptyState>No audit entries yet.</EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ color: 'var(--muted)' }}>
                  <Th>Time</Th>
                  <Th>Actor</Th>
                  <Th>Action</Th>
                  <Th>Target</Th>
                  <Th>Detail</Th>
                </tr>
              </thead>
              <tbody>
                {entries.map((e) => (
                  <tr key={e.ID} style={{ borderTop: '1px solid var(--border)' }}>
                    <Td muted>{formatTime(e.Time)}</Td>
                    <Td mono>{e.Actor}</Td>
                    <Td>
                      <Pill tone={e.Action === 'block' ? 'warn' : e.Action === 'login_failed' ? 'warn' : 'neutral'}>
                        {e.Action}
                      </Pill>
                    </Td>
                    <Td mono>{e.Target}</Td>
                    <Td muted>{e.Detail}</Td>
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

function HealthItem({ label, value, ok, neutral }: { label: string; value: string; ok?: boolean; neutral?: boolean }) {
  const color = neutral ? 'var(--text)' : ok ? 'var(--good)' : 'var(--crit)'
  return (
    <div className="py-2">
      <div className="font-mono text-[0.62rem] font-semibold uppercase tracking-[0.1em]" style={{ color: 'var(--muted)' }}>
        {label}
      </div>
      <div className="mt-0.5 flex items-center gap-1.5 text-sm font-medium" style={{ color }}>
        {!neutral && (
          <span className="inline-block h-1.5 w-1.5 rounded-full" style={{ background: color }} />
        )}
        {value}
      </div>
    </div>
  )
}
