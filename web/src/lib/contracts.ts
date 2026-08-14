// The 0.4.0 response shapes, declared here because lib/api.ts is held by
// another engineer this cycle. Everything in this file belongs in api.ts and
// should be folded into it when that lands — it is a staging area, not a
// second client.
//
// What changed on the wire: a measurement that was not taken is now absent
// rather than zero, and a bucket that was not captured carries null rather
// than zero. Reading the new payloads through the old types is exactly what
// turns a dead capture into a calm network on screen.

import type { LiveFlow, Talker } from './api'

// PointState says what a bucket's numbers mean (store.PointState). Only down
// and nodata carry nulls; a genuine zero is a measurement and plots at zero.
export type PointState = 'measured' | 'sampled' | 'down' | 'nodata' | 'unverified'

export interface Point {
  time: string
  state: PointState
  // null exactly when state is down or nodata.
  bytes: number | null
  packets: number | null
  flows: number | null
  // Present only when state is sampled: the fraction of packets that survived,
  // and the bucket's true packet total (exact even under sampling).
  keep_rate?: number
  observed_packets?: number
  // Present only when some but not all capture sources covered the bucket.
  sources_up?: number
  sources_total?: number
}

// CoverageCounts summarises a series so a view can say "27 of 877 minutes not
// captured" without walking it. A dense array of nodata has a length, so
// series.length > 0 is no longer a usable proxy for "there is data".
export interface CoverageCounts {
  measured: number
  sampled: number
  down: number
  nodata: number
  unverified: number
}

// CaptureState is the server's own verdict on the capture sources. It is read,
// never inferred: a rate that stops changing is not evidence of anything, and
// the client is not in a position to decide otherwise.
export type CaptureState = 'up' | 'partial' | 'down' | 'starting'

// LiveNow is /api/overview.live and the SSE `live` event. Every measured field
// is optional because the server omits what it did not measure.
export interface LiveNow {
  bits_per_second?: number
  packets_per_second?: number
  sampling?: boolean
  observed_pps?: number
  keep_rate?: number
  capture?: CaptureState
  sources_up?: number
  sources_total?: number
  // Absent means no packet has arrived since start — not "just now".
  last_packet_at?: string
  measured_at?: string
}

// SeriesResponse covers /api/flows and anything else returning a dense series.
export interface SeriesResponse {
  from: string
  to: string
  resolution: string
  bucket_seconds?: number
  series: Point[] | null
  coverage?: CoverageCounts
  top_talkers?: Talker[] | null
  // Keys the server could not answer at all. A key listed here is absent from
  // the payload rather than zero-filled.
  unavailable?: string[] | null
}

// OverviewNow is /api/overview. active_blocks, unacked_alerts, top_talkers and
// throughput_1h are optional: each is dropped and named in `unavailable` when
// its query failed, so a view must distinguish "none" from "we do not know".
export interface OverviewNow {
  live: LiveNow
  resolution: string
  bucket_seconds?: number
  throughput_1h?: Point[] | null
  coverage?: CoverageCounts
  top_talkers?: Talker[] | null
  active_blocks?: number
  unacked_alerts?: number
  enforcing: boolean
  unavailable?: string[] | null
}

export interface SearchResponse {
  from: string
  to: string
  count: number
  // True when the limit cut the result off. Rendering "300 flows" while this
  // is set presents a page cap as a total.
  truncated?: boolean
  flows: LiveFlow[] | null
}

// ChartPoint is what the chart layer accepts today: bytes that exist. Kept
// structural rather than importing TimePoint so this file does not break when
// api.ts is rewritten around Point.
export interface ChartPoint {
  time: string
  bytes: number
  packets: number
  flows: number
}

// measuredPoints drops the buckets that have no measurement. The chart cannot
// draw a gap yet — that is the chart layer's fix, landing separately — and of
// the two available lies, plotting a null as zero ("the network was silent")
// is the worse one. Pair every call with coverageNote so the dropped buckets
// are stated in words next to the picture.
export function measuredPoints(points: Point[] | null | undefined): ChartPoint[] {
  const out: ChartPoint[] = []
  for (const p of points ?? []) {
    if (p.bytes === null || p.packets === null || p.flows === null) continue
    out.push({ time: p.time, bytes: p.bytes, packets: p.packets, flows: p.flows })
  }
  return out
}

// coverageNote is the sentence that goes with a chart or a total: what share of
// the window was actually captured, in the units the server counted in.
export function coverageNote(c: CoverageCounts | undefined, bucketLabel: string): string | null {
  if (!c) return null
  const total = c.measured + c.sampled + c.down + c.nodata + c.unverified
  if (total === 0) return null
  const parts: string[] = []
  if (c.down > 0) parts.push(`${c.down} not captured`)
  if (c.nodata > 0) parts.push(`${c.nodata} outside recorded history`)
  if (c.sampled > 0) parts.push(`${c.sampled} sampled — the volume is a floor`)
  if (c.unverified > 0) parts.push(`${c.unverified} recorded before coverage was tracked`)
  if (parts.length === 0) return null
  return `${parts.join(' · ')} of ${total} ${bucketLabel}`
}

// hasMeasurement reports whether a series contains anything that was measured.
// The dense contract means an all-nodata array still has a length.
export function hasMeasurement(c: CoverageCounts | undefined, points: Point[] | null | undefined): boolean {
  if (c) return c.measured + c.sampled + c.unverified > 0
  return (points ?? []).some((p) => p.bytes !== null)
}

// bucketSecondsOf reads the server's own bucket size, falling back to the
// resolution string for a server from before it was reported. Returns null
// when neither is understood, so a caller can decline to draw rather than
// scale by a guess.
export function bucketSecondsOf(r: { bucket_seconds?: number; resolution?: string }): number | null {
  if (typeof r.bucket_seconds === 'number' && r.bucket_seconds > 0) return r.bucket_seconds
  switch (r.resolution) {
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
