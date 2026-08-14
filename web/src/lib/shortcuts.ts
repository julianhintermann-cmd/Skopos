import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'

// g-prefixed navigation, the convention every tool with a keyboard has settled
// on. Desktop only in practice, and suppressed whenever a text field has
// focus — a shortcut that fires while someone is typing a block reason is a
// bug, not a feature.

export const CHORDS: { keys: string; target: string; label: string }[] = [
  { keys: 'g n', target: '/', label: 'Now' },
  { keys: 'g t', target: '/traffic', label: 'Traffic' },
  { keys: 'g d', target: '/devices', label: 'Devices' },
  { keys: 'g c', target: '/cloudflare', label: 'Cloudflare' },
  { keys: 'g a', target: '/alerts', label: 'Alerts' },
  { keys: 'g f', target: '/firewall', label: 'Firewall' },
  { keys: 'g s', target: '/system', label: 'System' },
  // Comma is the conventional settings key and avoids the s collision.
  { keys: 'g ,', target: '/settings', label: 'Settings' },
]

const BY_KEY = new Map(CHORDS.map((c) => [c.keys.slice(2), c.target]))

// How long a half-typed chord waits for its second key before giving up.
const CHORD_MS = 1500

function typing(): boolean {
  const el = document.activeElement as HTMLElement | null
  if (!el) return false
  return el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable
}

export function useShortcuts({ onPalette, onHelp }: { onPalette: () => void; onHelp: () => void }) {
  const navigate = useNavigate()

  useEffect(() => {
    let pending = false
    let timer: ReturnType<typeof setTimeout> | undefined

    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        // The palette is reachable from inside a field too: it is how you
        // leave the field.
        e.preventDefault()
        onPalette()
        return
      }
      if (typing() || e.metaKey || e.ctrlKey || e.altKey) return

      if (pending) {
        pending = false
        clearTimeout(timer)
        const target = BY_KEY.get(e.key.toLowerCase())
        if (target) {
          e.preventDefault()
          navigate(target)
        }
        return
      }
      if (e.key === '?') {
        e.preventDefault()
        onHelp()
        return
      }
      if (e.key.toLowerCase() === 'g') {
        pending = true
        timer = setTimeout(() => {
          pending = false
        }, CHORD_MS)
      }
    }

    window.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('keydown', onKey)
      clearTimeout(timer)
    }
  }, [navigate, onPalette, onHelp])
}
