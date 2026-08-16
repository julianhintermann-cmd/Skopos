import { useEffect, useState } from 'react'
import {
  api,
  countryFlag,
  countryName,
  type ReputationInfo,
  type ReputationSignal,
  type ReputationState,
  type ReputationVerdict,
} from '../lib/api'

// Who an external address belongs to, and what anyone has on it. Lifted out of
// the alerts list because three pages ask the same question — the list, the
// incident page and the address dossier — and the answer must read identically
// in all of them.
//
// This card used to lead with "Abuse 70%". No source it consults publishes a
// percentage; the number was assembled here, and a blocklist match contributed
// a flat 70 regardless of which list or how many. Because the built-in lists
// cover a lot of address space, almost everything an operator opened showed 70,
// and the figure that looked the most precise was the only one nobody had
// measured. What each source actually said is shown instead.

// verdictStyle maps the one-word summary onto a label and a tone.
//
// None of them is green, and that is not an oversight. "No reports" means two
// sensor networks have not happened to hear about this address, which is a
// weak statement about a very large internet — it is a reason to keep reading,
// never a clearance.
const verdictStyle: Record<
  ReputationVerdict,
  { label: string; note: string; fg: string; bg: string }
> = {
  listed: {
    label: 'On a blocklist',
    note: '',
    fg: 'var(--crit)',
    bg: 'var(--crit-tint)',
  },
  reported: {
    label: 'Reported',
    note: 'by sensors that saw it',
    fg: 'var(--warn)',
    bg: 'var(--warn-tint)',
  },
  no_reports: {
    label: 'No reports',
    note: 'checked, not cleared',
    fg: 'var(--muted)',
    bg: 'var(--surface)',
  },
  unknown: {
    label: 'Unknown',
    note: 'nothing could be looked up',
    fg: 'var(--muted)',
    bg: 'var(--surface)',
  },
}

// stateMark is the short word in front of each source's line. "no answer" and
// "nothing" sit next to each other on purpose: the difference between them is
// the whole reason this panel lists sources individually.
const stateMark: Record<ReputationState, { text: string; fg: string }> = {
  listed: { text: 'listed', fg: 'var(--crit)' },
  reported: { text: 'reported', fg: 'var(--warn)' },
  clean: { text: 'nothing', fg: 'var(--muted)' },
  unknown: { text: 'not checked', fg: 'var(--muted)' },
  error: { text: 'no answer', fg: 'var(--muted)' },
}

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

  const v = verdictStyle[info.verdict] ?? verdictStyle.unknown
  const signals = info.signals ?? []

  return (
    <div className="rounded-md px-3 py-2 text-xs" style={{ background: 'var(--surface-2)' }}>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        <span className="rounded-full px-2 py-0.5 font-medium" style={{ background: v.bg, color: v.fg }}>
          {v.label}
          {v.note && <span className="font-normal"> — {v.note}</span>}
        </span>
        {info.org && (
          <span>
            <span style={{ color: 'var(--muted)' }}>Owner</span> {info.org}
            {info.handle ? ` (${info.handle})` : ''}
          </span>
        )}
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
      </div>

      {signals.length > 0 && (
        <ul className="mt-1.5 space-y-0.5">
          {signals.map((s) => (
            <SignalRow key={s.source} signal={s} />
          ))}
        </ul>
      )}

      <div className="mt-1.5 flex flex-wrap items-center gap-x-3" style={{ color: 'var(--muted)' }}>
        <span>Look up elsewhere:</span>
        <Lookup href={`https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`}>AbuseIPDB</Lookup>
        <Lookup href={`https://www.shodan.io/host/${encodeURIComponent(ip)}`}>Shodan</Lookup>
        <Lookup href={`https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}`}>VirusTotal</Lookup>
      </div>
    </div>
  )
}

// SignalRow prints one source's answer: who was asked, what came back, and the
// counts they published. Counts are rendered only when the source gave them —
// an absent count is left absent rather than shown as zero.
function SignalRow({ signal }: { signal: ReputationSignal }) {
  const mark = stateMark[signal.state] ?? stateMark.unknown
  return (
    <li className="flex flex-wrap items-baseline gap-x-2">
      <span className="w-24 shrink-0" style={{ color: 'var(--muted)' }}>
        {signal.source}
      </span>
      <span className="font-medium" style={{ color: mark.fg }}>
        {mark.text}
      </span>
      <span style={{ color: 'var(--muted)' }}>{signal.detail}</span>
    </li>
  )
}

// Lookup opens a third-party report on the address. Nothing is sent anywhere
// until the operator clicks: these are plain links, not background requests.
function Lookup({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    // 17px on a phone, on its own row: this one can take the full target
    // without colliding with anything, because the row holds nothing else.
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      className="inline-flex items-center underline pointer-coarse:min-h-11"
      style={{ color: 'var(--accent-strong)' }}
    >
      {children}
    </a>
  )
}
