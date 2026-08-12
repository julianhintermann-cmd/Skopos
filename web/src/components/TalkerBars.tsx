import type { Talker } from '../lib/api'

// A horizontal magnitude list: single-hue teal bars (magnitude, not identity),
// each labelled with its address and value. Bars share one scale so lengths
// are comparable at a glance.
export function TalkerBars({ talkers, format }: { talkers: Talker[]; format: (t: Talker) => string }) {
  const max = Math.max(...talkers.map((t) => t.bytes), 1)
  return (
    <div className="flex flex-col gap-1.5">
      {talkers.map((t) => (
        <div key={t.address} className="flex items-center gap-3">
          <div className="w-40 shrink-0 truncate font-mono text-xs" title={t.name || t.address}>
            {t.name || t.address}
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
      ))}
    </div>
  )
}
