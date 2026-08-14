import { Card, CardHeader, StatTile } from './ui'
import { Sparkline } from './Sparkline'
import type { LiveNow } from '../lib/contracts'
import { formatBits, formatPPS } from '../lib/format'

// The zero-width time position: what is moving right now.
//
// Every tile here has a "no reading" state, and it is not zero. The server now
// omits a measurement it did not take, so an absent field means the capture
// said nothing — and an accent-toned 0 bps in that case is a dead capture
// drawn as a calm network, which for a traffic monitor is the worst thing this
// row can say.
export function LivePulse({
  live,
  spark,
  connected,
  variant = 'full',
}: {
  live: LiveNow | null
  spark: number[]
  connected: boolean
  variant?: 'full' | 'compact'
}) {
  const bits = typeof live?.bits_per_second === 'number' ? formatBits(live.bits_per_second) : ''
  const pps = typeof live?.packets_per_second === 'number' ? formatPPS(live.packets_per_second) : ''
  const sources =
    typeof live?.sources_up === 'number' && typeof live?.sources_total === 'number'
      ? { up: live.sources_up, total: live.sources_total }
      : null

  return (
    <div className="flex flex-col gap-4">
      <div className={`grid gap-3 ${variant === 'full' ? 'grid-cols-2 lg:grid-cols-4' : 'grid-cols-2'}`}>
        <StatTile
          label="Throughput"
          value={bits ? bits.split(' ')[0] : '—'}
          unit={bits ? bits.split(' ')[1] : undefined}
          tone={bits ? 'accent' : 'neutral'}
          hint={bits ? undefined : 'no reading'}
        />
        <StatTile
          label="Packets"
          value={pps ? pps.split(' ')[0] : '—'}
          unit={pps ? 'pkt/s' : undefined}
          hint={pps ? undefined : 'no reading'}
        />
        {variant === 'full' && (
          <>
            <StatTile
              label="Sampling"
              value={live?.sampling ? 'On' : live ? 'Off' : '—'}
              tone={live?.sampling ? 'warn' : 'neutral'}
              hint={
                live?.sampling
                  ? typeof live.keep_rate === 'number'
                    ? `${Math.round(live.keep_rate * 100)}% of packets kept — volumes are a floor`
                    : 'volumes are a floor'
                  : live
                    ? 'every packet counted'
                    : 'no reading'
              }
            />
            <StatTile
              label="Sources"
              value={sources ? `${sources.up}/${sources.total}` : '—'}
              tone={sources && sources.up < sources.total ? 'warn' : 'neutral'}
              hint={sources ? 'capture interfaces running' : 'not reported'}
            />
          </>
        )}
      </div>

      <Card>
        <CardHeader
          title="Live throughput"
          sub="bits per second · updated every second"
          right={<LiveDot connected={connected} />}
        />
        <div className="px-3 pb-3">
          {spark.length > 1 ? (
            <Sparkline values={spark} height={variant === 'full' ? 96 : 72} />
          ) : (
            <div
              className="flex items-center justify-center text-sm"
              style={{ color: 'var(--muted)', height: variant === 'full' ? 96 : 72 }}
            >
              {connected ? 'Waiting for the first reading…' : 'Connecting to the live stream…'}
            </div>
          )}
        </div>
      </Card>
    </div>
  )
}

// LiveDot reports the state of the browser's own connection to the stream —
// not the state of the capture. Those are two different failures and the
// status strip owns the second one.
export function LiveDot({ connected }: { connected: boolean }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium" style={{ color: connected ? 'var(--good)' : 'var(--muted)' }}>
      <span
        className="inline-block h-2 w-2 rounded-full"
        style={{
          background: connected ? 'var(--good)' : 'var(--muted)',
          animation: connected ? 'skopos-pulse 2s ease-in-out infinite' : undefined,
        }}
      />
      {connected ? 'Live' : 'Reconnecting'}
    </span>
  )
}
