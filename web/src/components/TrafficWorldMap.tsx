import WorldMap, { type DataItem } from 'react-svg-worldmap'
import { useTheme } from '../lib/theme'
import { formatBytes } from '../lib/format'
import { countryName, type CountryStat } from '../lib/api'

// TrafficWorldMap renders the country statistics as a choropleth: one accent
// hue whose opacity scales with volume, on a recessive landmass — magnitude,
// not identity, exactly like the bar charts it accompanies.
export function TrafficWorldMap({ stats }: { stats: CountryStat[] }) {
  const { resolved } = useTheme()
  const cssVar = (name: string) =>
    getComputedStyle(document.documentElement).getPropertyValue(name).trim()
  const accent = cssVar('--accent')
  const grid = cssVar('--chart-grid')
  const land = cssVar('--surface-3')

  const max = Math.max(...stats.map((s) => s.bytes), 1)
  const byCode = new Map(stats.map((s) => [s.country.toLowerCase(), s.bytes]))
  // The lib types `country` as a literal union of ISO codes; our codes come
  // from the API as plain strings, so cast — unknown codes just don't render.
  const data = stats.map((s) => ({ country: s.country.toLowerCase(), value: s.bytes })) as DataItem<number>[]

  return (
    // Re-key on theme so the CSS-variable colors are re-read.
    <div key={resolved} className="mx-auto w-full max-w-2xl [&_svg]:h-auto [&_svg]:w-full">
      <WorldMap
        color={accent}
        backgroundColor="transparent"
        size="responsive"
        frame={false}
        richInteraction
        data={data}
        styleFunction={(ctx: { countryCode: string }) => {
          const value = byCode.get(ctx.countryCode.toLowerCase()) ?? 0
          // Log scale keeps small countries visible next to a dominant one.
          const share = value > 0 ? Math.log1p(value) / Math.log1p(max) : 0
          return {
            fill: value > 0 ? accent : land,
            fillOpacity: value > 0 ? 0.25 + 0.75 * share : 0.55,
            stroke: grid,
            strokeWidth: 0.6,
            strokeOpacity: 0.8,
            cursor: value > 0 ? 'pointer' : 'default',
          }
        }}
        tooltipTextFunction={(ctx: { countryCode: string }) => {
          const code = ctx.countryCode.toUpperCase()
          const value = byCode.get(ctx.countryCode.toLowerCase()) ?? 0
          return value > 0 ? `${countryName(code)}: ${formatBytes(value)}` : countryName(code)
        }}
      />
    </div>
  )
}
