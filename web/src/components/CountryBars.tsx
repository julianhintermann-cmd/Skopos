import { countryFlag, countryName, type CountryStat } from '../lib/api'
import { formatBytes } from '../lib/format'

// CountryBars ranks countries by traffic share: flag, name, a single-hue bar
// and the volume. The browser's Intl data supplies the names, the flags are
// plain emoji — no shipped country table, no map asset.
export function CountryBars({ stats }: { stats: CountryStat[] }) {
  const max = Math.max(...stats.map((s) => s.bytes), 1)
  return (
    <div className="flex flex-col gap-1.5">
      {stats.map((s) => (
        <div key={s.country} className="flex items-center gap-3">
          <div className="w-40 shrink-0 truncate text-xs" title={`${countryName(s.country)} (${s.country})`}>
            <span className="mr-1.5">{countryFlag(s.country)}</span>
            {countryName(s.country)}
          </div>
          <div className="relative h-5 flex-1 overflow-hidden rounded" style={{ background: 'var(--surface-2)' }}>
            <div
              className="absolute inset-y-0 left-0 rounded"
              style={{ width: `${(s.bytes / max) * 100}%`, background: 'var(--accent)', opacity: 0.85 }}
            />
          </div>
          <div className="tabnums w-20 shrink-0 text-right font-mono text-xs" style={{ color: 'var(--muted)' }}>
            {formatBytes(s.bytes)}
          </div>
        </div>
      ))}
    </div>
  )
}
