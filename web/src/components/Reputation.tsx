import { useEffect, useState } from 'react'
import { api, countryFlag, countryName, type ReputationInfo } from '../lib/api'

// Who an external address belongs to. Lifted out of the alerts list because
// three pages now ask the same question — the list, the incident page and the
// address dossier — and the answer must read identically in all of them.

// Reputation loads and renders the ownership panel for one address.
export function Reputation({ ip }: { ip: string }) {
  const [info, setInfo] = useState<ReputationInfo | null>(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    let stop = false
    setInfo(null)
    setErr('')
    api
      .get<ReputationInfo>(`/api/reputation?ip=${encodeURIComponent(ip)}`)
      .then((i) => !stop && setInfo(i))
      .catch((e) => !stop && setErr((e as Error).message))
    return () => {
      stop = true
    }
  }, [ip])

  // A failed lookup is not a clean address. It is a failed lookup, and it says
  // so — this panel sits next to an alert that fired for a reason.
  if (err) return <div className="text-xs" style={{ color: 'var(--crit)' }}>Lookup failed: {err}</div>
  if (!info) return <div className="text-xs" style={{ color: 'var(--muted)' }}>Looking up {ip}…</div>

  const score = info.abuse_score
  const signals = info.signals ?? []
  const reports = info.abuse_reports ?? 0
  return (
    <div className="rounded-md px-3 py-2 text-xs" style={{ background: 'var(--surface-2)' }}>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        {info.org && <span><span style={{ color: 'var(--muted)' }}>Owner</span> {info.org}{info.handle ? ` (${info.handle})` : ''}</span>}
        {info.country && (
          <span>
            <span style={{ color: 'var(--muted)' }}>
              {info.country_source === 'registry' ? 'Registered in' : 'Country'}
            </span>{' '}
            {countryFlag(info.country)} {countryName(info.country)}
          </span>
        )}
        {info.isp && <span><span style={{ color: 'var(--muted)' }}>ISP</span> {info.isp}</span>}
        {info.usage_type && <span><span style={{ color: 'var(--muted)' }}>Type</span> {info.usage_type}</span>}
        {score !== undefined ? (
          <span
            className="rounded-full px-2 py-0.5 font-medium"
            style={
              score >= 50
                ? { background: 'var(--crit-tint)', color: 'var(--crit)' }
                : { background: 'var(--warn-tint)', color: 'var(--warn)' }
            }
          >
            Abuse {score}%{reports > 0 ? ` · ${reports} reports` : ''}
          </span>
        ) : (
          // Never green. No free source having data on an address does not
          // make it safe — it makes it unknown.
          <span className="rounded-full px-2 py-0.5 font-medium" style={{ background: 'var(--surface)', color: 'var(--muted)' }}>
            No reports — unknown, not cleared
          </span>
        )}
      </div>

      {signals.length > 0 && (
        <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5" style={{ color: 'var(--muted)' }}>
          {signals.map((s) => (
            <span key={s.source}>
              {s.source}: {s.detail}
            </span>
          ))}
        </div>
      )}

      <div className="mt-1 flex flex-wrap gap-x-3" style={{ color: 'var(--muted)' }}>
        <span>Look up elsewhere:</span>
        <Lookup href={`https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`}>AbuseIPDB</Lookup>
        <Lookup href={`https://www.shodan.io/host/${encodeURIComponent(ip)}`}>Shodan</Lookup>
        <Lookup href={`https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}`}>VirusTotal</Lookup>
      </div>
    </div>
  )
}

// Lookup opens a third-party report on the address. Nothing is sent anywhere
// until the operator clicks: these are plain links, not background requests.
function Lookup({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noreferrer" className="underline" style={{ color: 'var(--accent-strong)' }}>
      {children}
    </a>
  )
}
