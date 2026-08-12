import type { Talker } from '../lib/api'
import { resolveName } from '../lib/deviceNames'

// A horizontal magnitude list: single-hue teal bars (magnitude, not identity),
// each labelled with its name (device label / hostname / DNS name) or address
// and its value. Bars share one scale so lengths are comparable at a glance.
export function TalkerBars({
  talkers,
  format,
  names,
}: {
  talkers: Talker[]
  format: (t: Talker) => string
  names?: Map<string, string>
}) {
  const max = Math.max(...talkers.map((t) => t.bytes), 1)
  return (
    <div className="flex flex-col gap-1.5">
      {talkers.map((t) => {
        const name = resolveName(names ?? new Map(), t.address, t.name)
        return (
          <div key={t.address} className="flex items-center gap-3">
            <div className="w-44 shrink-0 leading-tight" title={name ? `${name} · ${t.address}` : t.address}>
              {name ? (
                <>
                  <div className="truncate text-xs font-medium">{name}</div>
                  <div className="truncate font-mono text-[0.65rem]" style={{ color: 'var(--muted)' }}>
                    {t.address}
                  </div>
                </>
              ) : (
                <div className="truncate font-mono text-xs">{t.address}</div>
              )}
            </div>
            <div className="relative h-5 flex-1 overflow-hidden rounded" style={{ background: 'var(--surface-2)' }}>
              <div
                className="absolute inset-y-0 left-0 rounded"
                style={{ width: `${(t.bytes / max) * 100}%`, background: 'var(--accent)', opacity: 0.85 }}
              />
            </div>
            <div className="tabnums w-24 shrink-0 text-right font-mono text-xs" style={{ color: 'var(--muted)' }}>
              {format(t)}
            </div>
          </div>
        )
      })}
    </div>
  )
}
