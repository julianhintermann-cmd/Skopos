import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useFetch } from '../lib/useFetch'
import { coveredByProtected, type Alert, type BlocksResponse } from '../lib/api'
import type { SearchResponse } from '../lib/contracts'
import { Card, CardHeader, Spinner, EmptyState, StatTile, Pill, Button, SeverityBadge } from '../components/ui'
import { FlowTable } from '../components/FlowTable'
import { RangeControl } from '../components/RangeControl'
import { BlockDialog } from '../components/BlockDialog'
import { Reputation } from '../components/Reputation'
import { PageTitle } from '../components/PageTitle'
import { useDeviceIndex, isPrivateAddress } from '../lib/links'
import { apiWindow, useUrlRange, WINDOWS } from '../lib/useUrlState'
import { formatBytes, formatCount, formatTime, formatRelative } from '../lib/format'

// Everything Skopos knows about one address, in one place.
//
// This is where every address link in the app lands when the address is not
// one of your own devices, and it is composition rather than new machinery:
// every panel comes from an endpoint that already exists. What it adds is that
// the answers are in the same place at the same time, which is the only way
// "should I block this?" gets answered in one sitting.
const ALERT_LOOKBACK = 200

export function IPDossier({ onUnauthorized, canWrite }: { onUnauthorized: () => void; canWrite: boolean }) {
  const { addr = '' } = useParams()
  const { range, setRange } = useUrlRange('24h', WINDOWS)
  const index = useDeviceIndex(onUnauthorized)
  const [blocking, setBlocking] = useState(false)
  const [copied, setCopied] = useState(false)

  const search = useFetch<SearchResponse>(
    `/api/search?address=${encodeURIComponent(addr)}&window=${apiWindow(range)}&limit=300`,
    { pollMs: 30000, onUnauthorized },
  )
  const blocks = useFetch<BlocksResponse>('/api/blocks', { pollMs: 15000, onUnauthorized })
  const alerts = useFetch<{ alerts: Alert[] | null }>(`/api/alerts?limit=${ALERT_LOOKBACK}`, { pollMs: 30000, onUnauthorized })

  const name = index.names.get(addr)
  const private_ = isPrivateAddress(addr)
  const flows = search.data?.flows ?? []
  const bytes = flows.reduce((sum, f) => sum + f.bytes, 0)
  const truncated = search.data?.truncated ?? false

  const blocked = (blocks.data?.blocks ?? []).find(
    (b) => b.Prefix === addr || b.Prefix === `${addr}/32` || b.Prefix === `${addr}/128`,
  )
  const protectedBy = coveredByProtected(addr, 'address', blocks.data?.protected ?? [])
  const mine = (alerts.data?.alerts ?? []).filter((a) => a.Source === addr)

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--muted)' }}>
        <Link to="/traffic" className="hover:underline">
          Traffic
        </Link>
        <span>/</span>
        <span className="min-w-0 truncate font-mono" style={{ color: 'var(--text)' }}>
          {addr}
        </span>
      </div>

      {blocking && (
        <BlockDialog
          source={addr}
          detector=""
          onClose={() => setBlocking(false)}
          onDone={() => {
            setBlocking(false)
            blocks.refresh()
          }}
          onUnauthorized={onUnauthorized}
        />
      )}

      <Card className="px-4 py-3.5">
        <PageTitle title={name || addr}>
          {name ? `${addr} · known to Skopos as a device` : private_ ? 'a private address on your own network' : 'an address outside your network'}
        </PageTitle>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          {canWrite && !protectedBy && <Button onClick={() => setBlocking(true)}>Block</Button>}
          {canWrite && protectedBy && (
            <Button disabled>Block — {protectedBy} is on the never-block list</Button>
          )}
          <Button
            onClick={() => {
              navigator.clipboard?.writeText(addr).then(
                () => {
                  setCopied(true)
                  setTimeout(() => setCopied(false), 2000)
                },
                () => setCopied(false),
              )
            }}
          >
            {copied ? 'Copied' : 'Copy address'}
          </Button>
          <Link
            to={`/traffic?lens=flows&range=${range}&address=${encodeURIComponent(addr)}`}
            className="rounded-md border px-3 py-1.5 text-sm font-medium"
            style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text)' }}
          >
            Open in Traffic
          </Link>
        </div>
      </Card>

      <Card>
        <CardHeader title="Block status" sub="what the firewall has been told about this address" />
        <div className="px-4 pb-4 text-sm">
          {blocks.loading && !blocks.data ? (
            <span style={{ color: 'var(--muted)' }}>Checking…</span>
          ) : !blocks.data ? (
            <span style={{ color: 'var(--warn)' }}>
              Could not read the block list{blocks.error ? `: ${blocks.error}` : ''} — this is not a confirmed "not blocked".
            </span>
          ) : blocked ? (
            <div className="flex flex-wrap items-center gap-2">
              <Pill tone="crit">blocked</Pill>
              <span>{blocked.Prefix}</span>
              {blocked.Reason && <span style={{ color: 'var(--muted)' }}>{blocked.Reason}</span>}
              <span style={{ color: 'var(--muted)' }}>
                {blocked.Expires ? `expires ${formatRelative(blocked.Expires)}` : 'permanent'}
              </span>
              {blocked.attempts > 0 && (
                <span style={{ color: 'var(--muted)' }}>
                  {formatCount(blocked.attempts)} packets seen since start
                  {blocked.last_attempt ? `, last ${formatRelative(blocked.last_attempt)}` : ''}
                </span>
              )}
            </div>
          ) : protectedBy ? (
            <div className="flex flex-wrap items-center gap-2">
              <Pill tone="accent">never blocked</Pill>
              <span style={{ color: 'var(--muted)' }}>covered by {protectedBy} on the allowlist</span>
            </div>
          ) : (
            // The endpoint is authoritative here, so "not blocked" is a real
            // answer rather than an absence of one.
            <span style={{ color: 'var(--muted)' }}>Not blocked.</span>
          )}
        </div>
      </Card>

      {!private_ && (
        <Card>
          <CardHeader title="Who is this" sub="ownership and reputation, from the public registries" />
          <div className="px-4 pb-4">
            <Reputation ip={addr} />
          </div>
        </Card>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <RangeControl range={range} setRange={setRange} allowed={WINDOWS} />
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
        <StatTile
          label="Volume"
          value={formatBytes(bytes).split(' ')[0]}
          unit={formatBytes(bytes).split(' ')[1]}
          tone="accent"
          hint={truncated ? `across the ${flows.length} flows shown — a floor` : `across ${flows.length} flows`}
        />
        <StatTile
          label="Flows"
          value={truncated ? `${formatCount(search.data?.count ?? 0)}+` : formatCount(search.data?.count ?? 0)}
          hint={`last ${range}`}
        />
        <StatTile label="Alerts" value={formatCount(mine.length)} hint={`within the last ${ALERT_LOOKBACK} alerts`} />
      </div>

      <Card>
        <CardHeader
          title="Traffic"
          sub={`${range} · every flow to or from this address`}
          right={
            truncated ? <Pill tone="warn">page limit reached — this is not the whole window</Pill> : undefined
          }
        />
        {search.loading && !search.data ? (
          <Spinner />
        ) : !search.data ? (
          <EmptyState>Could not search flows{search.error ? `: ${search.error}` : ''}.</EmptyState>
        ) : (
          <FlowTable rows={flows} index={index} empty={`No flows to or from ${addr} in the last ${range}.`} />
        )}
      </Card>

      <Card>
        <CardHeader
          title="Alerts from this source"
          sub={`within the last ${ALERT_LOOKBACK} alerts — there is no per-source alert query yet`}
        />
        {alerts.loading && !alerts.data ? (
          <Spinner />
        ) : !alerts.data ? (
          <EmptyState>Could not read the alerts list{alerts.error ? `: ${alerts.error}` : ''}.</EmptyState>
        ) : mine.length === 0 ? (
          <EmptyState>None in the last {ALERT_LOOKBACK} alerts.</EmptyState>
        ) : (
          <ul>
            {mine.map((a) => (
              <li key={a.ID} style={{ borderTop: '1px solid var(--border)' }}>
                <Link to={`/alerts/${a.ID}`} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-4 py-2.5 text-sm">
                  <SeverityBadge severity={a.Severity} />
                  <span className="font-medium">{a.Title}</span>
                  <span style={{ color: 'var(--muted)' }}>{a.Detail}</span>
                  <span className="ml-auto font-mono text-xs" style={{ color: 'var(--muted)' }}>
                    {formatTime(a.Time)}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  )
}
