import { useState, type ReactNode } from 'react'
import { Card, CardHeader, Code } from './ui'

// In-context help, because the alternative was reading Go source.
//
// Every control on the Protection card is a bare label today, and the words an
// operator has to understand before touching them — protected, observe,
// cooldown, quiet hours — are defined nowhere in the app. The numbers are
// worse than the words: a field that takes seconds and a field that takes
// packets per second look identical, and neither says what the server will
// refuse.
//
// So each entry carries four things, and the fourth is the one that is
// normally missing: what the running process does with the value, the unit,
// the range the server actually enforces, and what goes wrong when it is set
// badly. The ranges are read off internal/settings.Validate and the
// consequences off internal/policy and internal/detect, so a bound printed
// here is a bound the process holds rather than a plausible-sounding one.

export interface Help {
  // What the running process does with this value. One sentence.
  what: string
  // The unit, spelled out. Omitted for switches, which have no unit.
  unit?: string
  // What the server will accept. From settings.Validate.
  range?: string
  // What happens when it is wrong — in both directions where both exist.
  wrong: string
}

export const SETTING_HELP: Record<string, Help> = {
  enforcement: {
    what:
      'Whether Skopos writes its blocks into the kernel at all. Observe records and counts every block decision and drops nothing; enforce loads the same decisions into nftables.',
    range: 'observe or enforce',
    wrong:
      'In observe, nothing on this machine is protected however many blocks the Firewall page lists. Arming it does not fail the save when the backend is unavailable — the line under this row reports what the kernel was actually found to hold, which is the only answer that counts.',
  },
  block_ttl: {
    what:
      'How long a block created by a detector stays before nftables expires it on its own. Blocks you add by hand default to permanent and are not affected.',
    unit: 'a duration — 30m, 24h, 168h',
    range: 'zero or more; 0 makes automatic blocks permanent too',
    wrong:
      'Too short and a scanner is back before you have read the alert. Too long — or 0 — and a dynamic address blocked today belongs to someone else next week, with nothing scheduled to lift it.',
  },
  cooldown: {
    what:
      'The smallest gap between notifications for the same detector and the same source address. Alerts inside the gap are still recorded and counted; only the push is held back.',
    unit: 'a duration — 5m, 30m, 2h',
    range: 'zero or more; 0 sends every alert',
    wrong:
      'Too short and one persistent scanner empties your phone overnight. Too long and a second, unrelated event from the same address never reaches you at all.',
  },
  allowlist: {
    what:
      'Addresses and ranges no detector may ever block. Skopos adds your default gateway to this list itself and will not remove it — that is what "protected" means everywhere else in the app.',
    unit: 'one address or CIDR per entry — 192.168.1.10, 10.0.0.0/8',
    range: 'anything Go’s netip parses; a bare address is treated as a single host',
    wrong:
      'An entry that does not parse is refused and nothing is changed. An entry that is too wide is accepted and silently disables blocking for everything inside it.',
  },

  'portscan.enabled': {
    what:
      'Watches for one source touching many distinct ports, or many distinct hosts, inside a short window, and raises an alert when either count crosses its threshold.',
    wrong:
      'Off, port scans still happen and nothing records them. Turning it off does not lift blocks already in the kernel.',
  },
  'portscan.window': {
    what: 'The sliding window the port and target counts are measured over.',
    unit: 'a duration — 30s, 60s, 5m',
    range: 'must be greater than zero',
    wrong:
      'A short window misses a scan spread thinly over minutes, which is how a careful one is done. A long window turns ordinary service discovery — a phone waking up and finding the printer — into a scan.',
  },
  'portscan.external': {
    what:
      'How many distinct ports, or distinct hosts, a source outside your private ranges may touch inside the window before it is reported.',
    unit: 'two counts: distinct ports, and distinct target hosts',
    range: 'both must be greater than zero',
    wrong:
      'Set low, the internet alone produces alerts all day — background scanning of any public address is constant. Set high, a real sweep of your NAS passes unremarked.',
  },
  'portscan.internal': {
    what: 'The same two counts, for sources inside your own private ranges.',
    unit: 'two counts: distinct ports, and distinct target hosts',
    range: 'both must be greater than zero',
    wrong:
      'Your own devices are chatty: mDNS discovery, a backup client walking shares, a console probing for a companion app. Internal thresholds set as low as the external ones alert on all of it.',
  },
  'portscan.block': {
    what:
      'Whether a confirmed port scan also blocks its source, with nobody approving it. The block is only created while enforcement is set to enforce; in observe it is recorded and nothing is dropped. Addresses on the never-block list are skipped.',
    wrong:
      'This is the app acting on its own. A false positive takes a real device off the network for the whole automatic block lifetime, and the source that trips it most often is one of yours — a scanner you ran yourself, seen from the LAN.',
  },

  'rate.enabled': {
    what:
      'Watches for one source opening many new connections, or pushing many packets per second, inside a short window.',
    wrong:
      'Off, a flood is still captured and charted, but nothing raises an alert about it and nothing can act on it.',
  },
  'rate.window': {
    what: 'The sliding window the connection and packet counts are measured over.',
    unit: 'a duration — 5s, 10s, 60s',
    range: 'must be greater than zero',
    wrong:
      'Below a few seconds, one page load fetching forty assets looks like a flood. Far above it, a genuine flood is averaged down under the limits and never trips.',
  },
  'rate.max_new_connections': {
    what: 'How many new connections one source may open inside the window before it is reported.',
    unit: 'connections per window, per source address',
    range: 'must be greater than zero',
    wrong:
      'Too low and any busy browser, torrent client or update run trips it. Too high and a SYN flood is indistinguishable from a quiet evening.',
  },
  'rate.max_packets_per_second': {
    what: 'How many packets per second one source may send before it is reported.',
    unit: 'packets per second, per source address',
    range: 'must be greater than zero',
    wrong:
      'Too low and one large file transfer or a backup run reads as an attack. Too high and nothing short of a link-saturating flood ever crosses it.',
  },
  'rate.block': {
    what:
      'Whether a confirmed rate event also blocks its source unattended. As with the port scanner the block only reaches the kernel while enforcement is enforce — and this detector never auto-blocks a source inside your private ranges, whatever this is set to.',
    wrong:
      'The rate detector is the one most likely to fire on legitimate traffic, so this is the switch most likely to block something you needed. Watch the alerts it raises for a few days before arming it.',
  },

  quiet_hours: {
    what:
      'A nightly window in which notifications below a minimum severity are held back. Alerts are still recorded, counted and acknowledgeable; only the push is suppressed.',
    unit: 'a local start and end time, and the lowest severity still delivered',
    range: 'times are 00:00–23:59 and may cross midnight; severity is info, warning or critical',
    wrong:
      'Left unset, the minimum behaves as critical, so a warning at 3am is silent. Set it to info and quiet hours deliver everything, which is the same as being off.',
  },
}

// HelpDot is the control, not the content: a 16px "?" that expands the panel
// its row renders underneath. It is a disclosure rather than a hover tooltip
// on purpose — a tooltip is unreachable on a phone, invisible to a keyboard
// and gone the moment you move to the field it describes.
export function HelpDot({
  label,
  open,
  panelId,
  onToggle,
}: {
  label: string
  open: boolean
  panelId: string
  onToggle: () => void
}) {
  return (
    <button
      type="button"
      onClick={onToggle}
      aria-expanded={open}
      aria-controls={panelId}
      aria-label={`What ${label} does`}
      title={`What ${label} does`}
      className={`inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-full border font-mono text-[0.6rem] font-semibold transition-colors ${
        open
          ? 'border-accent bg-accent-quiet text-accent'
          : 'border-line-strong text-fg-muted hover:bg-hover hover:text-fg active:bg-active'
      }`}
    >
      <span aria-hidden>?</span>
    </button>
  )
}

// HelpPanel renders the four facts as four facts. They are labelled rather
// than run together into a paragraph so "what will the server accept" can be
// answered without reading the rest.
export function HelpPanel({ id, help }: { id: string; help: Help }) {
  return (
    <div id={id} className="mt-2 rounded-md border border-line bg-raised px-3 py-2 text-xs">
      <p className="text-fg">{help.what}</p>
      {help.unit && (
        <p className="mt-1.5 text-fg-muted">
          <HelpTag>Unit</HelpTag>
          {help.unit}
        </p>
      )}
      {help.range && (
        <p className="mt-1 text-fg-muted">
          <HelpTag>Accepted</HelpTag>
          {help.range}
        </p>
      )}
      <p className="mt-1 text-fg-muted">
        <HelpTag>If it is wrong</HelpTag>
        {help.wrong}
      </p>
    </div>
  )
}

function HelpTag({ children }: { children: ReactNode }) {
  return <span className="mr-1.5 font-mono text-label uppercase text-fg-muted">{children}</span>
}

// useHelpToggle bundles the open flag with the id that ties the button to the
// panel, so a row cannot ship one without the other.
export function useHelpToggle(key: string) {
  const [open, setOpen] = useState(false)
  return { open, panelId: `help-${key.replace(/[^a-z0-9]+/gi, '-')}`, toggle: () => setOpen((v) => !v) }
}

// --- glossary ---------------------------------------------------------------

// The words the app uses about itself and never defines. Each of these is
// rendered somewhere as a bare label — on the header pill, in a table column,
// on an alert — with no way to resolve it short of reading the Go source.
const GLOSSARY: { term: string; definition: ReactNode }[] = [
  {
    term: 'Observe / Enforce',
    definition: (
      <>
        The global switch. In <strong>observe</strong> Skopos decides everything it would normally
        decide, records the blocks and counts the packets they would have caught, and touches the
        kernel with none of it. In <strong>enforce</strong> the same decisions are loaded into
        nftables and traffic is actually dropped. A block listed on the Firewall page exists in the
        database either way; only enforce makes it real.
      </>
    ),
  },
  {
    term: 'Protected',
    definition: (
      <>
        The set of addresses that can never be blocked, by a detector or by you: your never-block
        allowlist plus the default gateway, which Skopos adds itself. Blocking the gateway would cut
        this machine off the network, including the page you are reading, so the request is refused
        at the server rather than obeyed.
      </>
    ),
  },
  {
    term: 'Detector',
    definition: (
      <>
        One rule that watches captured traffic and raises alerts: the port scanner, the connection
        rate limiter, the threat feeds, the new-device notice. Each has its own thresholds, and each
        can be turned off without affecting the others or the blocks already in place.
      </>
    ),
  },
  {
    term: 'Alert / Incident',
    definition: (
      <>
        An <strong>alert</strong> is one finding by one detector at one moment. An{' '}
        <strong>incident</strong> is the grouping of every alert about the same source address, so
        four hundred port-scan alerts from one host are one thing to acknowledge rather than four
        hundred.
      </>
    ),
  },
  {
    term: 'Mute',
    definition: (
      <>
        A standing rule that stops matching alerts from notifying you. Scoped by source address, by
        detector, or by both, and optionally with an expiry. Muted alerts are still recorded — a
        mute silences the push, it does not stop the watching.
      </>
    ),
  },
  {
    term: 'Origin: manual / auto',
    definition: (
      <>
        Who created a block. <strong>Manual</strong> is one you added, and it is permanent unless you
        gave it a lifetime. <strong>Auto</strong> is one a detector created on its own, and it
        expires after the automatic block lifetime set on this page.
      </>
    ),
  },
  {
    term: 'Cooldown',
    definition: (
      <>
        The minimum gap between two notifications about the same detector and the same source. It
        throttles the pushes, never the recording: the alerts inside the gap are stored and counted,
        and the next notification says how many there were.
      </>
    ),
  },
  {
    term: 'Quiet hours',
    definition: (
      <>
        A nightly window in which anything below a chosen severity is not pushed. Same principle as
        cooldown — the alerts are still recorded, and they are waiting on the Alerts page in the
        morning.
      </>
    ),
  },
  {
    term: 'Runtime override',
    definition: (
      <>
        A setting changed from this dashboard. Overrides live in the Skopos database, not in{' '}
        <Code>config.yaml</Code>, and they shadow the file: once a value is overridden here, editing
        the same key in the file and restarting appears to do nothing. Anything overridden is marked{' '}
        <em>changed here</em> on the Protection card, and{' '}
        <em>Reset to config.yaml</em> drops all of them at once.
      </>
    ),
  },
  {
    term: 'Inert key',
    definition: (
      <>
        A key this build parses and validates but does not read. They are kept so existing files
        keep loading, and they are named on the Configuration card when your file actually contains
        one — a setting that is accepted and ignored is worse than one that is rejected.
      </>
    ),
  },
]

// Glossary is a card rather than a separate route so that the words are on the
// page that uses most of them, one scroll from the controls they describe.
export function Glossary() {
  const [open, setOpen] = useState(false)
  return (
    <Card>
      <CardHeader
        title="What the words mean"
        sub="the vocabulary this app uses about itself"
        right={
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            aria-controls="skopos-glossary"
            className="rounded-md border border-line bg-raised px-3 py-1.5 text-sm font-medium text-fg transition-colors hover:bg-sunken active:bg-sunken"
          >
            {open ? 'Hide' : `Show ${GLOSSARY.length} terms`}
          </button>
        }
      />
      {open && (
        <dl id="skopos-glossary" className="flex flex-col gap-3 px-4 pb-4">
          {GLOSSARY.map((g) => (
            <div key={g.term} className="border-t border-line pt-3 first:border-t-0 first:pt-0">
              <dt className="text-sm font-semibold">{g.term}</dt>
              <dd className="mt-0.5 text-xs text-fg-muted">{g.definition}</dd>
            </div>
          ))}
        </dl>
      )}
    </Card>
  )
}
