import { Link } from 'react-router-dom'
import { countryFlag, countryName, type CountryStat, type Talker } from '../lib/api'
import { entityHref, displayName, type DeviceIndex } from '../lib/links'
import { formatBytes } from '../lib/format'

// The render sites for entities. Each one asks entityHref where a value goes
// and falls back to plain text, so no view has to hold that rule itself.
//
// These supersede TalkerBars and CountryBars, which draw the same magnitude
// lists without links.

// EntityLink renders an address, MAC or name as a link when Skopos has a page
// for it, and as text when it does not.
export function EntityLink({
  value,
  index,
  label,
  mono = true,
  className = '',
}: {
  value: string
  index: DeviceIndex
  label?: string
  mono?: boolean
  className?: string
}) {
  const text = label || value
  const cls = `${mono ? 'font-mono' : ''} ${className}`
  const href = entityHref(value, index)
  if (!href) return <span className={cls}>{text}</span>
  return (
    <Link
      to={href}
      // A 15px-tall tap target, and it is the link that opens the dossier for
      // an address. The padding grows the hit box without moving anything:
      // vertical padding on an inline box does not change the line height, and
      // the negative horizontal margin gives the text back its own width.
      //
      // Deliberately not the full 44px. These sit in card lists with 4-8px
      // between lines, so a 44px box would overlap the line above and below and
      // a thumb aimed at one address would open another. Trading a small target
      // for a wrong target is not an improvement. Where a link is alone on its
      // own row, the row should pass a `pointer-coarse:min-h-11` className.
      className={`${cls} hover:underline pointer-coarse:-mx-1 pointer-coarse:px-1 pointer-coarse:py-1.5`}
      style={{ color: 'var(--accent-strong)' }}
      title={value}
    >
      {text}
    </Link>
  )
}

// TalkerRows is the magnitude list with every row linked: one shared scale,
// single-hue bars for magnitude rather than identity.
export function TalkerRows({
  talkers,
  index,
  format = (t: Talker) => formatBytes(t.bytes),
}: {
  talkers: Talker[]
  index: DeviceIndex
  format?: (t: Talker) => string
}) {
  const max = Math.max(...talkers.map((t) => t.bytes), 1)
  return (
    <div className="flex flex-col gap-1.5">
      {talkers.map((t) => {
        const name = displayName(index, t.address, t.name)
        return (
          <div key={t.address} className="flex items-center gap-3">
            <div className="w-44 shrink-0 leading-tight" title={name ? `${name} · ${t.address}` : t.address}>
              {name ? (
                <>
                  <EntityLink value={t.address} index={index} label={name} mono={false} className="block truncate text-xs font-medium" />
                  <div className="truncate font-mono text-[0.65rem]" style={{ color: 'var(--muted)' }}>
                    {t.address}
                  </div>
                </>
              ) : (
                <EntityLink value={t.address} index={index} className="block truncate text-xs" />
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

// CountryRows links each country to the blocking control with its code
// prefilled and not submitted.
//
// It deliberately does not link to filtered traffic: /api/geoip/summary
// aggregates and discards the addresses, so no endpoint can answer "show me
// the flows to Russia". Offering that link would open a page that cannot be
// built.
export function CountryRows({ stats }: { stats: CountryStat[] }) {
  const max = Math.max(...stats.map((s) => s.bytes), 1)
  return (
    <div className="flex flex-col gap-1.5">
      {stats.map((s) => (
        <div key={s.country} className="flex items-center gap-3">
          <Link
            to={`/firewall?tab=countries&add=${encodeURIComponent(s.country)}`}
            className="w-40 shrink-0 truncate text-xs hover:underline"
            title={`${countryName(s.country)} (${s.country}) — block this country`}
          >
            <span className="mr-1.5">{countryFlag(s.country)}</span>
            {countryName(s.country)}
          </Link>
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
