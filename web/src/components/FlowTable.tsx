import type { ReactNode } from 'react'
import type { LiveFlow } from '../lib/api'
import { Pill } from './ui'
import { EntityLink } from './entity'
import { displayName, type DeviceIndex } from '../lib/links'
import { useIsMobile } from '../lib/useIsMobile'
import { formatBytes, formatCount } from '../lib/format'

// One table, two data sources.
//
// The streaming feed and the history search were two components rendering the
// same rows with different columns, so switching between "right now" and "last
// 24 hours" lost the operator's place and made them re-read the layout. They
// are one component now; the caller decides where the rows came from.

export interface FeedFlow extends LiveFlow {
  // Stable key for streamed rows (a flow has no id) and the just-arrived
  // highlight. Absent for search results, which are keyed by index.
  _id?: number
  _fresh?: boolean
}

export function FlowTable({ rows, index, empty }: { rows: FeedFlow[]; index: DeviceIndex; empty: ReactNode }) {
  const isMobile = useIsMobile()

  if (rows.length === 0) {
    return (
      <div className="px-4 py-10 text-center text-sm" style={{ color: 'var(--muted)' }}>
        {empty}
      </div>
    )
  }

  if (isMobile) {
    return (
      <div>
        {rows.map((r, i) => (
          <FlowCard key={r._id ?? i} row={r} index={index} />
        ))}
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="sk-rows w-full text-sm">
        <thead>
          <tr style={{ color: 'var(--muted)' }}>
            <Hd>Time</Hd>
            <Hd>Source</Hd>
            <Hd>Destination</Hd>
            <Hd>Proto</Hd>
            <Hd right>Volume</Hd>
            <Hd right>Packets</Hd>
            <Hd>Direction</Hd>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <FlowRow key={r._id ?? i} row={r} index={index} />
          ))}
        </tbody>
      </table>
    </div>
  )
}

function FlowRow({ row, index }: { row: FeedFlow; index: DeviceIndex }) {
  return (
    <tr
      className={row._fresh ? 'motion-safe:animate-flash' : undefined}
      style={{ borderTop: '1px solid var(--border)' }}
    >
      <Cell muted>{clock(row.end)}</Cell>
      <Cell>
        <Endpoint addr={row.src} port={row.src_port} index={index} />
      </Cell>
      <Cell>
        <Endpoint addr={row.dst} port={row.dst_port} name={row.dst_name} index={index} />
      </Cell>
      <Cell mono>{row.proto}</Cell>
      <Cell right>{formatBytes(row.bytes)}</Cell>
      <Cell right muted>
        {formatCount(row.packets)}
      </Cell>
      <Cell>
        <span className="inline-flex items-center gap-1">
          <DirectionBadge dir={row.dir} />
          {row.blocked && (
            <Pill tone="crit">
              <span title="This peer is actively blocked — the packets arrived at the wire and were dropped by the firewall.">
                blocked
              </span>
            </Pill>
          )}
        </span>
      </Cell>
    </tr>
  )
}

// FlowCard is the phone rendering of one conversation: endpoints on the first
// line, the numbers underneath — no horizontal scrolling, thumb-sized rows.
function FlowCard({ row, index }: { row: FeedFlow; index: DeviceIndex }) {
  const src = displayName(index, row.src) || row.src
  const dst = row.dst_name || index.names.get(row.dst) || row.dst
  return (
    <div
      className={'px-4 py-2.5' + (row._fresh ? ' motion-safe:animate-flash' : '')}
      style={{ borderTop: '1px solid var(--border)' }}
    >
      <div className="flex items-center gap-1.5 text-[13px] font-medium">
        <span className="min-w-0 flex-1 truncate">
          <EntityLink value={row.src} index={index} label={src} mono={false} />
        </span>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--muted)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
          <path d="M5 12h14M13 6l6 6-6 6" />
        </svg>
        <span className="min-w-0 flex-1 truncate text-right">
          <EntityLink value={row.dst_name || row.dst} index={index} label={dst} mono={false} />
          <span className="font-mono text-[0.7rem]" style={{ color: 'var(--muted)' }}>
            :{row.dst_port}
          </span>
        </span>
      </div>
      <div className="mt-1 flex items-center gap-2 font-mono text-[0.68rem]" style={{ color: 'var(--muted)' }}>
        <span>{clock(row.end)}</span>
        <span>{row.proto}</span>
        <span className="tabnums">{formatBytes(row.bytes)}</span>
        <span className="ml-auto inline-flex items-center gap-1">
          {row.blocked && <Pill tone="crit">blocked</Pill>}
          <DirectionBadge dir={row.dir} />
        </span>
      </div>
    </div>
  )
}

// Endpoint links the address itself, and the destination name separately: the
// two go to different pages, and collapsing them into one link made the domain
// page unreachable from the only table that lists domains per flow.
function Endpoint({ addr, port, name, index }: { addr: string; port: number; name?: string; index: DeviceIndex }) {
  const label = displayName(index, addr, name)
  return (
    <div className="min-w-0">
      <div className="truncate">
        {label ? (
          <EntityLink value={name || addr} index={index} label={label} mono={false} />
        ) : (
          <EntityLink value={addr} index={index} className="text-xs" />
        )}
        {port > 0 && (
          <span className="font-mono text-xs" style={{ color: 'var(--muted)' }}>
            :{port}
          </span>
        )}
      </div>
      {label && (
        <div className="font-mono text-[0.7rem]">
          <EntityLink value={addr} index={index} className="opacity-70" />
        </div>
      )}
    </div>
  )
}

const dirMeta: Record<string, { label: string; tone: 'neutral' | 'accent' | 'good' | 'warn' }> = {
  lan_wan: { label: 'Outbound', tone: 'accent' },
  wan_lan: { label: 'Inbound', tone: 'warn' },
  lan_lan: { label: 'Internal', tone: 'neutral' },
  wan_wan: { label: 'Transit', tone: 'neutral' },
}

export function DirectionBadge({ dir }: { dir: string }) {
  const m = dirMeta[dir] ?? { label: dir, tone: 'neutral' as const }
  return <Pill tone={m.tone}>{m.label}</Pill>
}

export function dirLabel(dir: string): string {
  return dirMeta[dir]?.label ?? dir
}

function Hd({ children, right }: { children: ReactNode; right?: boolean }) {
  return (
    <th className={`px-4 py-2 font-mono text-[0.62rem] font-semibold uppercase tracking-[0.1em] ${right ? 'text-right' : 'text-left'}`}>
      {children}
    </th>
  )
}

function Cell({ children, mono, muted, right }: { children: ReactNode; mono?: boolean; muted?: boolean; right?: boolean }) {
  return (
    <td
      className={`px-4 py-1.5 align-top ${mono ? 'font-mono text-xs' : ''} ${right ? 'text-right tabnums' : ''}`}
      style={muted ? { color: 'var(--muted)' } : undefined}
    >
      {children}
    </td>
  )
}

function clock(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
}
