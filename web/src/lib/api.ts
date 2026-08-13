// Typed client for the Skopos API. Thin wrappers over fetch with JSON handling
// and a shared error shape; every view calls through here.

export class APIError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const init: RequestInit = { method, headers: {} }
  if (body !== undefined) {
    ;(init.headers as Record<string, string>)['Content-Type'] = 'application/json'
    init.body = JSON.stringify(body)
  }
  const resp = await fetch(path, init)
  if (resp.status === 401) throw new APIError(401, 'unauthorized')
  const text = await resp.text()
  const data = text ? JSON.parse(text) : {}
  if (!resp.ok) throw new APIError(resp.status, data.error || resp.statusText)
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
}

export interface Device {
  ID: number
  MAC: string
  IP: string
  Label: string
  Hostname: string
  Vendor: string
  WatchPresence: boolean
  Present: boolean
  FirstSeen: string
  LastSeen: string
}

// deviceName is the best display name for a device: the operator label wins,
// then the discovered hostname. Mirrors model.Device.Name on the backend.
export function deviceName(d: Device): string {
  return d.Label || d.Hostname || ''
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
  series: TimePoint[] | null
  destinations: Talker[] | null
  ports: PortUsage[] | null
  domains: DomainStat[] | null
  fingerprints: Fingerprint[] | null
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

export interface ReputationInfo {
  ip: string
  org?: string
  handle?: string
  country?: string
  abuse_score?: number
  abuse_reports?: number
  isp?: string
  usage_type?: string
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
  detail?: string
}
