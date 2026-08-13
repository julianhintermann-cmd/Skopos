// Human-readable formatting helpers. Throughput uses bits (network
// convention); data volumes use binary bytes.

export function formatBits(bps: number): string {
  const units = ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s', 'Tbit/s']
  let v = bps
  let i = 0
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000
    i++
  }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`
}

export function formatBytes(bytes: number): string {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let v = bytes
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`
}

export function formatCount(n: number): string {
  return n.toLocaleString()
}

export function formatPPS(pps: number): string {
  if (pps >= 1000) return `${(pps / 1000).toFixed(1)}k pkt/s`
  return `${Math.round(pps)} pkt/s`
}

export function formatTime(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  })
}

export function formatRelative(iso: string): string {
  const then = new Date(iso).getTime()
  const diff = (Date.now() - then) / 1000
  const secs = Math.abs(diff)
  const unit =
    secs < 60
      ? `${Math.floor(secs)}s`
      : secs < 3600
        ? `${Math.floor(secs / 60)}m`
        : secs < 86400
          ? `${Math.floor(secs / 3600)}h`
          : `${Math.floor(secs / 86400)}d`
  // A block's expiry sits in the future; everything else is in the past.
  return diff >= 0 ? `${unit} ago` : `in ${unit}`
}
