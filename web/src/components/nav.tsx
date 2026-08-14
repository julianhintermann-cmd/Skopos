import type { ReactNode } from 'react'

// The navigation model, in one place, because three surfaces render it: the
// desktop sidebar, the phone tab bar and More sheet, and the entity palette.
// When they each held their own copy they disagreed — the sidebar had ten
// items, the phone had four plus six, and neither matched the routes.
//
// Ten items became eight: Overview is Now, Live is a position on Traffic's
// time control, and Domains is a lens on Traffic. Nothing was deleted; two
// pages stopped pretending to be destinations.
//
// The labels are literal strings rather than i18n keys because lib/i18n.ts is
// held by another engineer this cycle. The keys this needs are listed in the
// handover: nav.now, section.watch, section.skopos.

export type Section = 'watch' | 'protect' | 'skopos'

export interface NavItem {
  to: string
  label: string
  section: Section
  icon: (props: { size?: number }) => ReactNode
  end?: boolean
  // Extra words the palette should match on, so "overview" and "live" still
  // find the pages they turned into.
  aliases?: string[]
}

export const SECTIONS: { id: Section; title: string }[] = [
  // Watch is your network; Skopos is the tool itself. That is the split that
  // matters at the moment something is wrong — "Monitor / Protect / Manage"
  // were three verbs the app performs and the user does not think in.
  { id: 'watch', title: 'Watch' },
  { id: 'protect', title: 'Protect' },
  { id: 'skopos', title: 'Skopos' },
]

export const NAV: NavItem[] = [
  { to: '/', label: 'Now', section: 'watch', icon: PulseIcon, end: true, aliases: ['overview', 'home', 'dashboard', 'status'] },
  {
    to: '/traffic',
    label: 'Traffic',
    section: 'watch',
    icon: WaveIcon,
    aliases: ['live', 'domains', 'flows', 'throughput', 'search', 'history'],
  },
  { to: '/devices', label: 'Devices', section: 'watch', icon: GridIcon, aliases: ['clients', 'inventory', 'hosts'] },
  { to: '/cloudflare', label: 'Cloudflare', section: 'watch', icon: CloudIcon, aliases: ['zones', 'edge', 'cdn'] },
  { to: '/alerts', label: 'Alerts', section: 'protect', icon: BellIcon, aliases: ['incidents', 'notifications'] },
  { to: '/firewall', label: 'Firewall', section: 'protect', icon: ShieldIcon, aliases: ['blocks', 'countries', 'nftables'] },
  { to: '/system', label: 'System', section: 'skopos', icon: StackIcon, aliases: ['health', 'audit', 'version', 'speedtest'] },
  { to: '/settings', label: 'Settings', section: 'skopos', icon: GearIcon, aliases: ['config', 'preferences', 'enforcement'] },
]

// Four tabs plus More. Alerts keeps a tab because it is the ntfy landing
// target; the firewall is acted on rarely and always deliberately, so it moves
// into More.
export const TAB_PATHS = ['/', '/traffic', '/devices', '/alerts']
export const MORE_PATHS = ['/cloudflare', '/firewall', '/system', '/settings']

export const TABS = TAB_PATHS.map((p) => NAV.find((n) => n.to === p)!)
export const MORE = MORE_PATHS.map((p) => NAV.find((n) => n.to === p)!)

// --- icons (stroke = currentColor) ----------------------------------------
//
// Each takes an optional size: 16 in the sidebar, 20 in the phone tab bar,
// where the target has to fit a thumb.

function icon(path: ReactNode, size = 16) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      {path}
    </svg>
  )
}

type IconProps = { size?: number }

export function PulseIcon({ size }: IconProps) {
  return icon(<polyline points="3 12 8 12 11 4 14 20 17 12 21 12" />, size)
}
export function WaveIcon({ size }: IconProps) {
  return icon(<path d="M3 12c2-4 4-4 6 0s4 4 6 0 4-4 6 0" />, size)
}
export function GridIcon({ size }: IconProps) {
  return icon(
    <>
      <rect x="3" y="3" width="7" height="7" rx="1" />
      <rect x="14" y="3" width="7" height="7" rx="1" />
      <rect x="3" y="14" width="7" height="7" rx="1" />
      <rect x="14" y="14" width="7" height="7" rx="1" />
    </>,
    size,
  )
}
export function CloudIcon({ size }: IconProps) {
  return icon(<path d="M17.5 18H7a4 4 0 0 1-.5-7.97A5 5 0 0 1 16 9.5a3.5 3.5 0 0 1 1.5 8.5z" />, size)
}
export function BellIcon({ size }: IconProps) {
  return icon(
    <>
      <path d="M18 8a6 6 0 1 0-12 0c0 7-3 9-3 9h18s-3-2-3-9" />
      <path d="M13.7 21a2 2 0 0 1-3.4 0" />
    </>,
    size,
  )
}
export function ShieldIcon({ size }: IconProps) {
  return icon(<path d="M12 3l7 3v5c0 4-3 7-7 8-4-1-7-4-7-8V6z" />, size)
}
// StackIcon is "the machine": stacked units. The gear it replaces now points
// at Settings, where every user alive expects to find it.
export function StackIcon({ size }: IconProps) {
  return icon(
    <>
      <rect x="3" y="4" width="18" height="5" rx="1.5" />
      <rect x="3" y="14" width="18" height="5" rx="1.5" />
      <path d="M7 6.5h.01M7 16.5h.01" />
    </>,
    size,
  )
}
export function GearIcon({ size }: IconProps) {
  return icon(
    <>
      <circle cx="12" cy="12" r="3.2" />
      <path d="M12 2.5v2.2M12 19.3v2.2M4.2 4.2l1.6 1.6M18.2 18.2l1.6 1.6M2.5 12h2.2M19.3 12h2.2M4.2 19.8l1.6-1.6M18.2 5.8l1.6-1.6" />
    </>,
    size,
  )
}
export function SearchIcon({ size }: IconProps) {
  return icon(
    <>
      <circle cx="11" cy="11" r="7" />
      <path d="M20 20l-3.5-3.5" />
    </>,
    size,
  )
}
export function DotsIcon({ size }: IconProps) {
  return icon(
    <>
      <circle cx="5" cy="12" r="1.6" />
      <circle cx="12" cy="12" r="1.6" />
      <circle cx="19" cy="12" r="1.6" />
    </>,
    size,
  )
}
