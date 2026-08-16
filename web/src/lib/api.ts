// Typed client for the Skopos API. Thin wrappers over fetch with JSON handling
// and a shared error shape; every view calls through here.

import type { Point, CoverageCounts, EnforcementState } from './contracts'

export class APIError extends Error {
  status: number
  // otpRequired is the login endpoint saying the password was right and it
  // wants the second factor. It travels as a field rather than as text in the
  // message, so the login form branches on a fact instead of on wording.
  otpRequired: boolean
  constructor(status: number, message: string, otpRequired = false) {
    super(message)
    this.status = status
    this.otpRequired = otpRequired
  }
}

// requestTimeoutMs bounds every call. Without it a hung request never settles:
// fetch has no default timeout, so a NAS that accepts the connection and then
// stops answering — a saturated single SQLite connection, a container being
// rebuilt, a Wi-Fi handover — leaves the promise pending forever. Nothing
// rejects, so nothing marks the data stale, and the dashboard sits there
// showing numbers from before the trouble started as though they were current.
// That is the failure this whole release is about, arriving through the one
// path that reports no error at all.
//
// 20s is well past a slow query on a busy NAS and well short of a person
// deciding the page is broken.
const requestTimeoutMs = 20_000

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const init: RequestInit = { method, headers: {}, signal: AbortSignal.timeout(requestTimeoutMs) }
  if (body !== undefined) {
    ;(init.headers as Record<string, string>)['Content-Type'] = 'application/json'
    init.body = JSON.stringify(body)
  }
  let resp: Response
  try {
    resp = await fetch(path, init)
  } catch (e) {
    // A timeout arrives as a DOMException whose message is "signal timed out",
    // which tells a reader nothing about what they were waiting for. Status 0
    // marks it as "never reached the server", which is the fact the caller has
    // to branch on: an unanswered request may still have been applied.
    if (e instanceof DOMException && e.name === 'TimeoutError') {
      throw new APIError(0, `${path} did not answer within ${requestTimeoutMs / 1000}s`)
    }
    throw new APIError(0, e instanceof Error ? e.message : String(e))
  }
  // 401 carries two different meanings here: "your session is gone, go to the
  // login screen", and login's own "right password, now the one-time code".
  // Reading the body tells them apart. Throwing away the body unread — which
  // is what this used to do — made enabling 2FA a permanent lockout: the form
  // never learned to ask for the code and reported invalid credentials for a
  // password that was correct.
  const text = await resp.text()
  let data: { error?: string; otp_required?: boolean } = {}
  try {
    data = text ? JSON.parse(text) : {}
  } catch {
    data = {}
  }
  if (resp.status === 401) {
    throw new APIError(401, data.error || 'unauthorized', data.otp_required === true)
  }
  if (!resp.ok) throw new APIError(resp.status, data.error || resp.statusText)
  // 202 is inside resp.ok and means the opposite of what a success branch
  // assumes: the server stored the change and the kernel did not take it.
  // Letting it through as success is how a refused quarantine came back as a
  // green toast — the caller has to be made to notice, so it is thrown and
  // carries the server's own account of what failed.
  if (resp.status === 202) {
    const applied = (data as { applied?: { error?: string; errors?: { field?: string; message?: string }[] } }).applied
    const detail =
      applied?.error ||
      applied?.errors?.map((e) => (e.field ? `${e.field}: ${e.message}` : e.message)).join('; ') ||
      'the change was saved but the firewall did not take it'
    throw new APIError(202, detail)
  }
  return data as T
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body),
  del: <T>(path: string) => request<T>('DELETE', path),
  postText: async (path: string, text: string) => {
    const resp = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: text })
    return resp.json()
  },
}

// ---- shared types (mirror the Go JSON shapes) ----

export type Severity = 'info' | 'warning' | 'critical'

export interface LiveStats {
  bits_per_second: number
  packets_per_second: number
  sampling: boolean
  observed_pps: number
}

export interface TimePoint {
  time: string
  bytes: number
  packets: number
  flows: number
}

// Seconds covered by one rollup bucket. The server chooses the resolution per
// request (store.ChooseResolution widens it as the range grows) and reports it
// next to the series, so anything turning bucket totals into a rate has to read
// it rather than assume minutes. Returns null for a resolution this build does
// not know, so callers can decline to draw instead of scaling by a guess.
export function bucketSeconds(resolution: string): number | null {
  switch (resolution) {
    case '1m':
      return 60
    case '1h':
      return 3600
    case '1d':
      return 86400
    default:
      return null
  }
}

// LiveFlow mirrors api.LiveFlow: a completed conversation shown in the live
// view. Streamed over SSE (`flows` events) and returned by /api/live/flows.
export interface LiveFlow {
  start: string
  end: string
  src: string
  dst: string
  src_port: number
  dst_port: number
  proto: string
  dir: string
  bytes: number
  packets: number
  dst_name?: string
  // Touches an actively blocked prefix: capture sees the packets arrive, the
  // kernel drops them right after.
  blocked?: boolean
}

export interface Talker {
  address: string
  name?: string
  bytes: number
  packets: number
  flows: number
}

export interface Overview {
  live: LiveStats
  resolution: string
  throughput_1h: TimePoint[] | null
  top_talkers: Talker[] | null
  active_blocks: number
  unacked_alerts: number
  enforcing: boolean
}

export interface Alert {
  ID: number
  Time: string
  Detector: string
  Severity: Severity
  Source: string
  Title: string
  Detail: string
  Count: number
  Ack: boolean
  AckTime: string | null
}

export interface Block {
  ID: number
  Prefix: string
  Origin: string
  Reason: string
  Created: string
  Expires: string | null
  Active: boolean
  // Packets seen from/to this prefix since start: proof of drops when
  // enforcing, a preview of them in observe mode.
  attempts: number
  last_attempt?: string
}

export interface BlocksResponse {
  blocks: Block[] | null
  // "observe" or "enforce" from the config — with "observe", blocks are
  // recorded but nothing is dropped.
  enforcement: string
  // True only when enforce is set AND the nftables backend is usable.
  enforcing: boolean
  // Prefixes that can never be blocked: the operator's allowlist plus the
  // default gateway. A block form should say so before the operator commits.
  protected?: string[] | null
  // What the kernel was last actually found to hold, as opposed to what the
  // configuration intends. Absent from older servers.
  kernel?: EnforcementState
}

// networkPrefix widens an address to the network an operator would think of
// as "the rest of them": /24 for IPv4, /64 for IPv6. The backend masks the
// result, so the host bits here do not matter.
export function networkPrefix(ip: string): string {
  return ip.includes(':') ? `${ip}/64` : `${ip}/24`
}

// coveredByProtected reports whether a prefix the operator is about to block
// overlaps the never-block set. Only exact and containing matches are checked
// on the client — the backend does the authoritative overlap test and refuses
// regardless; this is here to warn before the click, not to decide.
export function coveredByProtected(ip: string, scope: 'address' | 'network', protectedList: string[]): string | null {
  const wide = scope === 'network' ? networkPrefix(ip).split('/')[1] : null
  for (const p of protectedList) {
    const [base, bitsText] = p.split('/')
    if (base === ip) return p
    const bits = Number(bitsText)
    if (!Number.isFinite(bits)) continue
    // A /24 block covers an allowlisted address in the same /24.
    if (wide && !base.includes(':') && !ip.includes(':')) {
      const a = base.split('.').slice(0, 3).join('.')
      const b = ip.split('.').slice(0, 3).join('.')
      if (a === b) return p
    }
    // An allowlisted range that contains the address (IPv4 /8, /16, /24 only
    // — the common shapes; anything else is left to the backend).
    if (!base.includes(':') && !ip.includes(':') && [8, 16, 24].includes(bits)) {
      const n = bits / 8
      if (base.split('.').slice(0, n).join('.') === ip.split('.').slice(0, n).join('.')) return p
    }
  }
  return null
}

export interface Device {
  ID: number
  MAC: string
  // One address per family — a dual-stack machine is one device with two
  // addresses. Either may be empty.
  IP: string
  IP6: string
  Label: string
  Hostname: string
  Vendor: string
  WatchPresence: boolean
  Present: boolean
  // "" (unrestricted), "lan_only" or "quarantine".
  Policy?: string
  FirstSeen: string
  LastSeen: string
}

// deviceName is the best display name for a device: the operator label wins,
// then the discovered hostname. Mirrors model.Device.Name on the backend.
export function deviceName(d: Device): string {
  return d.Label || d.Hostname || ''
}

// deviceAddr is the address that stands for the device where only one fits.
// Mirrors model.Device.PrimaryAddr.
export function deviceAddr(d: Device): string {
  return d.IP || d.IP6 || ''
}

// randomizedMAC reports whether a hardware address was made up by its owner
// rather than assigned to a manufacturer: the second-lowest bit of the first
// octet is the "locally administered" flag. Phones and laptops set it to
// avoid being tracked across networks, which is why the same device can show
// up under several entries — worth saying out loud in the list.
export function randomizedMAC(mac: string): boolean {
  const first = parseInt(mac.slice(0, 2), 16)
  return Number.isFinite(first) && (first & 0x02) !== 0
}

export interface PortUsage {
  port: number
  proto: string
  bytes: number
  flows: number
}

// DeviceDetail is /api/devices/{mac}/detail: the inventory record plus the
// device's traffic over the requested window.
export interface DeviceDetail {
  device: Device
  from: string
  to: string
  resolution: string
  // Every field below is optional because the server omits what it could not
  // answer and names it in `unavailable`, rather than sending an empty array
  // that reads as a finding of nothing. Absent and empty are different facts.
  series?: Point[]
  bucket_seconds?: number
  coverage?: CoverageCounts
  destinations?: Talker[]
  ports?: PortUsage[]
  domains?: DomainStat[]
  fingerprints?: Fingerprint[]
  unavailable?: string[]
}

export interface CountryStat {
  country: string
  bytes: number
  flows: number
}

export interface DomainStat {
  name: string
  flows: number
  bytes: number
  devices: number
}

export interface Fingerprint {
  ja4: string
  hits: number
  first_seen: string
  last_seen: string
}

export interface Incident {
  id: number
  source: string
  first_seen: string
  last_seen: string
  severity: string
  detectors: string[] | null
  alert_count: number
  title: string
  ack: boolean
  alerts?: Alert[] | null
}

export interface MuteRule {
  id: number
  detector?: string
  prefix?: string
  port?: number
  reason?: string
  created: string
  expires?: string
}

export interface RuntimeSettings {
  enforcement: string
  block_ttl: number
  allowlist: string[] | null
  cooldown: number
  quiet_hours: {
    enabled: boolean
    from_hour: number
    from_minute: number
    to_hour: number
    to_minute: number
    min_severity: string
  }
  portscan: {
    enabled: boolean
    window: number
    external: { ports: number; targets: number }
    internal: { ports: number; targets: number }
    block: boolean
  }
  rate: {
    enabled: boolean
    window: number
    max_new_connections: number
    max_packets_per_second: number
    block: boolean
  }
}

export interface SettingsResponse {
  effective: RuntimeSettings
  base: RuntimeSettings
  overridden: string[] | null
}

export interface UpdateStatus {
  checked: boolean
  current: string
  latest?: string
  update_available: boolean
  url?: string
  last_check?: string
  error?: string
}

export interface GeoIPSummary {
  available: boolean
  out: CountryStat[]
  in: CountryStat[]
  blocked: string[]
  // Prefixes loaded into the kernel per blocked country (empty until the
  // GeoIP database is downloaded).
  blocked_prefixes?: Record<string, number>
}

// countryFlag renders an ISO 3166-1 alpha-2 code as its emoji flag.
export function countryFlag(code: string): string {
  if (!/^[A-Z]{2}$/.test(code)) return '🌐'
  return String.fromCodePoint(...[...code].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65))
}

const regionNames = typeof Intl !== 'undefined' ? new Intl.DisplayNames(['en'], { type: 'region' }) : null

// countryName resolves an ISO code to a readable name via the browser's own
// locale data — no shipped country table.
export function countryName(code: string): string {
  try {
    return regionNames?.of(code) ?? code
  } catch {
    return code
  }
}

// ReputationState is what one source managed to say. The last three are
// deliberately distinct: a source holding nothing, a source that could not be
// asked, and a source that was asked and failed are three different facts.
export type ReputationState = 'listed' | 'reported' | 'clean' | 'unknown' | 'error'

// ReputationSignal is one source's answer, carrying only figures that source
// published. It used to carry a 0-100 `score` that no source publishes and
// Skopos invented; see the note on ReputationVerdict.
export interface ReputationSignal {
  source: string
  state: ReputationState
  detail: string
  reports?: number
  targets?: number
  lists?: string[]
}

// ReputationVerdict is a word, not a percentage, and that is the point. The
// free sources publish report counts and list memberships, never a risk
// rating. Skopos used to manufacture one — a blocklist match was hardcoded to
// 70 — so nearly every address came back "Abuse 70%", the one figure on the
// card that looked measured being the only one nobody had measured.
export type ReputationVerdict = 'listed' | 'reported' | 'no_reports' | 'unknown'

export interface ReputationInfo {
  ip: string
  org?: string
  handle?: string
  country?: string
  // "geoip" (where the address is), "registry" (where its holder is
  // incorporated) or "asn".
  country_source?: string
  verdict: ReputationVerdict
  abuse_reports?: number
  isp?: string
  usage_type?: string
  signals?: ReputationSignal[] | null
  checked_at: string
}

export interface SpeedtestResult {
  ID: number
  Time: string
  DownMbps: number
  UpMbps: number
  LatencyMs: number
}

export interface AuditEntry {
  ID: number
  Time: string
  Actor: string
  Action: string
  Target: string
  Detail: string
}

export interface Me {
  username: string
  scope: string
  auth: boolean
  enforcing: boolean
}

// ---- Cloudflare integration ----

export interface CFZone {
  id: string
  name: string
  status: string
  monitored: boolean
}

export interface CFStatus {
  connected: boolean
  token_id?: string
  expires_on?: string
  zones: CFZone[]
}

export interface CFPoint {
  time: string
  requests: number
  bytes: number
  cached_requests: number
  cached_bytes: number
  threats: number
}

export interface CFAnalytics {
  zone_id: string
  since: string
  until: string
  points: CFPoint[] | null
}

export interface Health {
  ok: boolean
  version: string
  capture: string
  firewall: string
  enforcing: boolean
  cold_storage_ok: boolean
  // True when a capture interface is a mirror/SPAN port: Skopos sees the
  // whole segment, while blocking still acts only on traffic passing this
  // machine.
  mirror?: boolean
  detail?: string
}
