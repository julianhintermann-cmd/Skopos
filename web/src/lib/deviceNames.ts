import { useEffect, useState } from 'react'
import { api, deviceName, type Device } from './api'

// useDeviceNames polls the device inventory and returns a map of IP → best
// display name (operator label, else discovered hostname). Shared by every
// view that shows addresses, so an internal IP renders as its device name
// everywhere — top talkers, alerts, blocks, the live feed.
export function useDeviceNames(onUnauthorized?: () => void): Map<string, string> {
  const [names, setNames] = useState<Map<string, string>>(new Map())

  useEffect(() => {
    let stop = false
    const load = async () => {
      try {
        const { devices } = await api.get<{ devices: Device[] | null }>('/api/devices')
        if (stop) return
        const m = new Map<string, string>()
        for (const d of devices ?? []) {
          const n = deviceName(d)
          if (d.IP && n) m.set(d.IP, n)
        }
        setNames(m)
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

  return names
}

// resolveName is the display rule shared by tables: an explicit name (e.g.
// DNS/SNI) wins, then the device inventory, then nothing.
export function resolveName(names: Map<string, string>, address: string, explicit?: string): string {
  return explicit || names.get(address) || ''
}
