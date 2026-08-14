// One resolver for every address, MAC and name the app renders.
//
// Before this, five render sites decided independently where an address should
// go and three of them picked the same wrong answer. The rule is now single:
// ask entityHref, link when it answers, render plain text when it does not.
// A dead link is worse than no link — it teaches the operator that clicking
// things in Skopos does nothing.

import { useEffect, useState } from 'react'
import { api, deviceName, type Device } from './api'

// DeviceIndex is the inventory in the three shapes the resolver needs.
export interface DeviceIndex {
  // address → display name (operator label, else discovered hostname).
  names: Map<string, string>
  // address → MAC, for both families. The device page is richer than the
  // address dossier, so a known address routes to it instead.
  macByAddress: Map<string, string>
  // upper-cased MAC → device.
  byMAC: Map<string, Device>
  // False until the first successful load: an address is not "unknown to the
  // inventory" while the inventory is still unread.
  loaded: boolean
}

export const emptyIndex: DeviceIndex = {
  names: new Map(),
  macByAddress: new Map(),
  byMAC: new Map(),
  loaded: false,
}

function buildIndex(devices: Device[]): DeviceIndex {
  const index: DeviceIndex = { names: new Map(), macByAddress: new Map(), byMAC: new Map(), loaded: true }
  for (const d of devices) {
    index.byMAC.set(d.MAC.toUpperCase(), d)
    const n = deviceName(d)
    for (const addr of [d.IP, d.IP6]) {
      if (!addr) continue
      index.macByAddress.set(addr, d.MAC)
      if (n) index.names.set(addr, n)
    }
  }
  return index
}

// useDeviceIndex polls the inventory. It is the superset of useDeviceNames —
// same endpoint, same interval — and exposes `names` so components that only
// want the name map can pass it straight through.
export function useDeviceIndex(onUnauthorized?: () => void): DeviceIndex {
  const [index, setIndex] = useState<DeviceIndex>(emptyIndex)

  useEffect(() => {
    let stop = false
    const load = async () => {
      try {
        const { devices } = await api.get<{ devices: Device[] | null }>('/api/devices')
        if (!stop) setIndex(buildIndex(devices ?? []))
      } catch (e) {
        if ((e as { status?: number }).status === 401) onUnauthorized?.()
      }
    }
    load()
    const id = setInterval(load, 30000)
    return () => {
      stop = true
      clearInterval(id)
    }
  }, [onUnauthorized])

  return index
}

const MAC_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
// A hostname worth a dossier has at least two labels and an alphabetic TLD.
// A single label ("nas") is excluded: no page can answer for it, so linking
// would promise one.
const HOST_RE = /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}\.?$/i

export function isMAC(v: string): boolean {
  return MAC_RE.test(v)
}

export function isIPv4(v: string): boolean {
  const m = IPV4_RE.exec(v)
  return !!m && m.slice(1).every((o) => Number(o) <= 255)
}

export function isIPv6(v: string): boolean {
  return v.includes(':') && /^[0-9a-f:.]+$/i.test(v) && !MAC_RE.test(v)
}

export function isIP(v: string): boolean {
  return isIPv4(v) || isIPv6(v)
}

// isCIDR accepts what /api/search?address= accepts, which is what the dossier
// is reachable for.
export function isCIDR(v: string): boolean {
  const slash = v.lastIndexOf('/')
  if (slash < 0) return false
  const base = v.slice(0, slash)
  const bits = Number(v.slice(slash + 1))
  if (!Number.isInteger(bits) || bits < 0) return false
  if (isIPv4(base)) return bits <= 32
  if (isIPv6(base)) return bits <= 128
  return false
}

export function isHostname(v: string): boolean {
  return HOST_RE.test(v) && !isIPv4(v)
}

// isPrivateAddress marks the addresses a public reputation lookup cannot say
// anything about. Rendering a "who is this" panel for 192.168.1.20 is noise at
// best and an invitation to read an empty answer as a clean one.
export function isPrivateAddress(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|127\.|::1|fe80:|fc|fd)/i.test(ip)
}

// entityHref is the whole routing table for entities, in one place.
//
// Returns null for anything Skopos has no page for, and the caller renders
// plain text. That null is load-bearing: it is what stops a country code, a
// port number or a detector name from becoming a link to nowhere.
export function entityHref(value: string, index: DeviceIndex): string | null {
  const v = value.trim()
  if (!v) return null

  if (isMAC(v)) {
    return index.byMAC.has(v.toUpperCase()) ? `/devices/${encodeURIComponent(v)}` : null
  }
  if (isIP(v)) {
    const mac = index.macByAddress.get(v)
    if (mac) return `/devices/${encodeURIComponent(mac)}`
    return `/ip/${encodeURIComponent(v)}`
  }
  if (isCIDR(v)) {
    // A host prefix is the address: /32 and /128 are how the block API
    // normalises what the operator typed as a bare address.
    const host = v.replace(/\/(32|128)$/, '')
    if (host !== v && isIP(host)) return entityHref(host, index)
    return `/ip/${encodeURIComponent(v)}`
  }
  if (isHostname(v)) {
    return `/domain/${encodeURIComponent(v.replace(/\.$/, ''))}`
  }
  return null
}

// displayName is the shared naming rule: an explicit name (DNS, SNI) wins,
// then the inventory, then nothing.
export function displayName(index: DeviceIndex, address: string, explicit?: string): string {
  return explicit || index.names.get(address) || ''
}
