import { useState, type ReactNode } from 'react'
import { useFetch } from '../lib/useFetch'
import { api, APIError, type SettingsResponse, type RuntimeSettings as RS } from '../lib/api'
import type { EnforcementState } from '../lib/contracts'
import {
  Card,
  CardHeader,
  Button,
  Pill,
  TextInput,
  Toggle,
  Segmented,
  Skeleton,
  StaleBadge,
  EmptyState,
} from './ui'
import { KernelVerdictPanel } from './KernelVerdict'
import { HelpDot, HelpPanel, SETTING_HELP, useHelpToggle } from './settingsHelp'

// SettingsPayload is GET /api/settings as the server sends it now: the
// effective settings, the YAML baseline, what has been overridden, and the
// firewall's own verdict read after the last apply.
//
// It is declared here rather than in lib/api.ts because that file is held by
// another engineer this cycle — the staging arrangement lib/contracts.ts
// documents — and it belongs there when the two are folded together.
interface SettingsPayload extends SettingsResponse {
  enforcement?: EnforcementState
}

// SaveResult is POST/DELETE /api/settings. It carries three facts and never
// merges them: whether the override was written down (stored), what the live
// subsystems made of it (applied), and what the firewall says about itself now
// that the attempt is over. 200 means stored and in effect; 202 means stored
// and not in effect, and 202 does not throw.
interface SaveResult {
  ok: boolean
  stored: boolean
  applied?: { ok: boolean; errors: { field: string; message: string }[] }
}

// Outcome is what a control learns about its own save. Four states, because
// four different things can be true afterwards and each needs its own
// sentence:
//
//   applied  the server holds the new value and every subsystem took it
//   stored   the server holds it and something refused to act on it
//   refused  nothing was stored; the server still holds what it held
//   unknown  the request was never answered, so neither may be claimed
type Outcome =
  | { kind: 'applied' }
  | { kind: 'stored'; why: string }
  | { kind: 'refused'; why: string }
  | { kind: 'unknown'; why: string }

// toDurationString converts a Go duration (nanoseconds on the wire) to a human
// string. The API accepts either, so the UI sends the readable form.
function toDurationString(ns: number): string {
  if (ns <= 0) return '0s'
  const secs = Math.round(ns / 1e9)
  if (secs % 3600 === 0) return `${secs / 3600}h`
  if (secs % 60 === 0) return `${secs / 60}m`
  return `${secs}s`
}

function clockString(hour: number, minute: number): string {
  return `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`
}

// parseClock is a shape check, not the authority — settings.Validate is, and it
// runs against the candidate the server assembles. This exists so a half-typed
// "2:" is never posted as a change to quiet hours.
function parseClock(s: string): { hour: number; minute: number } | null {
  const m = /^(\d{1,2}):([0-5]\d)$/.exec(s.trim())
  if (!m) return null
  const hour = Number(m[1])
  return hour > 23 ? null : { hour, minute: Number(m[2]) }
}

// The override path and the field it changes are spelled differently: POST
// takes rate.max_packets_per_sec, GET returns rate.max_packets_per_second, so
// round-tripping the GET body fails with "not editable at runtime". Both
// spellings are written out at the one place that has to know about it, and
// this constant disappears in a single edit once internal/settings accepts the
// long spelling.
const RATE_PPS_KEY = 'rate.max_packets_per_sec'

// refusalText keeps the server's own validation wording.
//
// humanError is deliberately not used here. It is tuned for the block path, and
// its allowlist branch would rewrite `allowlist entry "x": not an address or
// CIDR` — a message about a value that will not parse — into a sentence about
// the never-block list refusing a block. Different fact, same words.
function refusalText(e: unknown): string {
  const raw = e instanceof Error ? e.message : String(e)
  return raw.replace(/^settings:\s*/, '')
}

function outcomeOf(r: SaveResult): Outcome {
  if (r.ok) return { kind: 'applied' }
  const why = (r.applied?.errors ?? []).map((x) => `${x.field}: ${x.message}`).join('; ')
  return { kind: 'stored', why: why || 'the firewall did not end up in the state this asks for' }
}

function failureOf(e: unknown, what: string): Outcome {
  if (e instanceof APIError && e.status === 0) {
    return { kind: 'unknown', why: `The server did not answer, so whether ${what} is unknown.` }
  }
  return { kind: 'refused', why: refusalText(e) }
}

// RuntimeSettings edits the configuration subset that applies without a
// restart. The YAML stays the baseline; every change here is an override the
// operator can drop again with "Reset to config.yaml".
export function RuntimeSettings({ onUnauthorized, canWrite }: { onUnauthorized: () => void; canWrite: boolean }) {
  // Polled, because this card is no longer the only writer. /api/settings is
  // the automation surface — it is how Home Assistant arms the firewall — and
  // an unpolled card would go on showing the settings as they were when the
  // page was opened. The kernel verdict rides on the same payload and ages on
  // its own, so it has to be re-read too.
  const { data, loading, error, stale, refresh } = useFetch<SettingsPayload>('/api/settings', {
    pollMs: 10000,
    onUnauthorized,
  })
  const [busy, setBusy] = useState(false)
  const [enforceOutcome, setEnforceOutcome] = useState<Outcome | null>(null)
  const [resetOutcome, setResetOutcome] = useState<Outcome | null>(null)

  const eff = data?.effective
  const overridden = new Set(data?.overridden ?? [])

  const send = async (patch: Record<string, unknown>): Promise<Outcome> => {
    setBusy(true)
    try {
      const r = await api.post<SaveResult>('/api/settings', patch)
      // Read the settings back rather than trusting the echo. The response does
      // carry `effective`, but one source for what this card renders is the
      // whole point of the card.
      refresh()
      return outcomeOf(r)
    } catch (e) {
      return failureOf(e, 'the change was applied')
    } finally {
      setBusy(false)
    }
  }

  const reset = async () => {
    setBusy(true)
    setResetOutcome(null)
    try {
      const r = await api.del<SaveResult>('/api/settings')
      refresh()
      setResetOutcome(outcomeOf(r))
    } catch (e) {
      setResetOutcome(failureOf(e, 'the overrides were dropped'))
    } finally {
      setBusy(false)
    }
  }

  if (loading && !data) {
    return (
      <Card>
        <CardHeader title="Protection" sub="applies immediately — no restart" />
        <Skeleton variant="row" rows={5} />
      </Card>
    )
  }
  if (!eff) {
    return (
      <Card>
        <CardHeader title="Protection" />
        <EmptyState>
          Skopos did not answer with its runtime settings{error ? `: ${error}` : ''}. Nothing is shown here
          rather than something, because none of it would have been read back from the running process.
        </EmptyState>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader
        title="Protection"
        sub="changes apply immediately — no restart, no YAML editing"
        right={
          <div className="flex items-center gap-2">
            {stale && <StaleBadge error={error ?? undefined} />}
            {overridden.size > 0 && canWrite && (
              <Button onClick={() => void reset()} disabled={busy}>
                Reset to config.yaml
              </Button>
            )}
          </div>
        }
      />

      <Row label="Enforcement" helpKey="enforcement" overridden={overridden.has('enforcement')}>
        {canWrite ? (
          <Segmented<string>
            ariaLabel="Enforcement"
            value={eff.enforcement}
            onChange={(mode) => {
              void (async () => setEnforceOutcome(await send({ enforcement: mode })))()
            }}
            options={[
              { value: 'observe', label: 'Observe', tone: 'warn', hint: 'record every decision, drop nothing' },
              { value: 'enforce', label: 'Enforce', tone: 'ok', hint: 'load the blocks into the kernel' },
            ]}
          />
        ) : (
          <Pill tone={eff.enforcement === 'enforce' ? 'ok' : 'warn'}>{eff.enforcement}</Pill>
        )}
      </Row>

      {/* The setting is in the row above; this is what the kernel was found to
          hold. The card used to draw its own warning from BlocksResponse.kernel
          .ok — a field the server stopped sending — so the test read
          `!undefined` and the warning appeared under every enforce whatever the
          kernel was doing. */}
      <div className="px-4 pb-3">
        <KernelVerdictPanel state={data?.enforcement} />
        <OutcomeNote outcome={enforceOutcome} />
      </div>

      <DraftRow
        label="Automatic block lifetime"
        helpKey="block_ttl"
        hint="How long a detector-created block stays before it expires in the kernel."
        value={toDurationString(eff.block_ttl)}
        overridden={overridden.has('block_ttl')}
        canWrite={canWrite}
        busy={busy}
        onSave={(v) => send({ block_ttl: v })}
      />

      <DraftRow
        label="Alert cooldown"
        helpKey="cooldown"
        hint="At most one notification per detector and source within this window; extras are counted."
        value={toDurationString(eff.cooldown)}
        overridden={overridden.has('cooldown')}
        canWrite={canWrite}
        busy={busy}
        onSave={(v) => send({ cooldown: v })}
      />

      <AllowlistRow
        value={eff.allowlist ?? []}
        overridden={overridden.has('allowlist')}
        canWrite={canWrite}
        busy={busy}
        onSave={(list) => send({ allowlist: list })}
      />

      <DetectorRow
        label="Port-scan detection"
        helpKey="portscan.enabled"
        hint={`${eff.portscan.external.ports} ports or ${eff.portscan.external.targets} targets from outside within ${toDurationString(eff.portscan.window)}${
          eff.portscan.block ? ' · blocks the source by itself' : ''
        }`}
        enabled={eff.portscan.enabled}
        overridden={overridden.has('portscan.enabled')}
        canWrite={canWrite}
        busy={busy}
        moreLabel="Thresholds"
        onToggle={(on) => send({ 'portscan.enabled': on })}
      >
        <DraftRow
          nested
          label="Window"
          helpKey="portscan.window"
          value={toDurationString(eff.portscan.window)}
          overridden={overridden.has('portscan.window')}
          canWrite={canWrite}
          busy={busy}
          onSave={(v) => send({ 'portscan.window': v })}
        />
        <PairRow
          nested
          label="From outside"
          helpKey="portscan.external"
          values={eff.portscan.external}
          overridden={overridden.has('portscan.external')}
          canWrite={canWrite}
          busy={busy}
          onSave={(v) => send({ 'portscan.external': v })}
        />
        <PairRow
          nested
          label="From your own network"
          helpKey="portscan.internal"
          values={eff.portscan.internal}
          overridden={overridden.has('portscan.internal')}
          canWrite={canWrite}
          busy={busy}
          onSave={(v) => send({ 'portscan.internal': v })}
        />
        <ToggleRow
          nested
          label="Block the source automatically"
          helpKey="portscan.block"
          on={eff.portscan.block}
          overridden={overridden.has('portscan.block')}
          canWrite={canWrite}
          busy={busy}
          onToggle={(on) => send({ 'portscan.block': on })}
        />
      </DetectorRow>

      <DetectorRow
        label="Connection-rate detection"
        helpKey="rate.enabled"
        hint={`${eff.rate.max_new_connections} new connections or ${eff.rate.max_packets_per_second} pkt/s per source within ${toDurationString(eff.rate.window)}${
          eff.rate.block ? ' · blocks external sources by itself' : ''
        }`}
        enabled={eff.rate.enabled}
        overridden={overridden.has('rate.enabled')}
        canWrite={canWrite}
        busy={busy}
        moreLabel="Limits"
        onToggle={(on) => send({ 'rate.enabled': on })}
      >
        <DraftRow
          nested
          label="Window"
          helpKey="rate.window"
          value={toDurationString(eff.rate.window)}
          overridden={overridden.has('rate.window')}
          canWrite={canWrite}
          busy={busy}
          onSave={(v) => send({ 'rate.window': v })}
        />
        <DraftRow
          nested
          numeric
          label="Max new connections"
          helpKey="rate.max_new_connections"
          unit="per window"
          value={String(eff.rate.max_new_connections)}
          overridden={overridden.has('rate.max_new_connections')}
          canWrite={canWrite}
          busy={busy}
          onSave={(v) => send({ 'rate.max_new_connections': Number(v) })}
        />
        <DraftRow
          nested
          numeric
          label="Max packets per second"
          helpKey="rate.max_packets_per_second"
          unit="pkt/s"
          value={String(eff.rate.max_packets_per_second)}
          overridden={overridden.has(RATE_PPS_KEY)}
          canWrite={canWrite}
          busy={busy}
          onSave={(v) => send({ [RATE_PPS_KEY]: Number(v) })}
        />
        <ToggleRow
          nested
          label="Block the source automatically"
          helpKey="rate.block"
          on={eff.rate.block}
          overridden={overridden.has('rate.block')}
          canWrite={canWrite}
          busy={busy}
          onToggle={(on) => send({ 'rate.block': on })}
        />
      </DetectorRow>

      <QuietHoursRow
        value={eff.quiet_hours}
        overridden={overridden.has('quiet_hours')}
        canWrite={canWrite}
        busy={busy}
        onSave={(v) => send({ quiet_hours: v })}
      />

      {resetOutcome && resetOutcome.kind !== 'applied' && (
        <div className="border-t border-line px-4 py-3">
          <OutcomeNote outcome={resetOutcome} />
        </div>
      )}
    </Card>
  )
}

// --- shared row furniture ----------------------------------------------------

function Row({
  label,
  helpKey,
  hint,
  overridden,
  nested,
  children,
  below,
}: {
  label: string
  helpKey: string
  hint?: string
  overridden: boolean
  nested?: boolean
  children: ReactNode
  below?: ReactNode
}) {
  const help = SETTING_HELP[helpKey]
  const h = useHelpToggle(helpKey)
  return (
    <div className={nested ? 'py-2' : 'border-t border-line px-4 py-3'}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0 flex-1">
          <RowLabel label={label} helpKey={helpKey} overridden={overridden} help={h} />
          {hint && <div className="mt-0.5 text-xs text-fg-muted">{hint}</div>}
        </div>
        {children}
      </div>
      {below}
      {help && h.open && <HelpPanel id={h.panelId} help={help} />}
    </div>
  )
}

function RowLabel({
  label,
  helpKey,
  overridden,
  help,
}: {
  label: string
  helpKey: string
  overridden: boolean
  help: { open: boolean; panelId: string; toggle: () => void }
}) {
  return (
    <div className="flex items-center gap-2 text-sm font-medium">
      {label}
      {SETTING_HELP[helpKey] && (
        <HelpDot label={label} open={help.open} panelId={help.panelId} onToggle={help.toggle} />
      )}
      {overridden && (
        <Pill tone="accent" title="Set from this dashboard. It shadows the value in config.yaml.">
          changed here
        </Pill>
      )}
    </div>
  )
}

// OutcomeNote says what happened to the last save, in the row that caused it.
// The card used to collect every error into one line at the bottom, so a
// rejected value and the field still showing it were separated by six rows of
// unrelated settings.
function OutcomeNote({ outcome }: { outcome: Outcome | null }) {
  if (!outcome || outcome.kind === 'applied') return null
  const tone =
    outcome.kind === 'refused' ? 'text-crit' : outcome.kind === 'stored' ? 'text-warn' : 'text-unknown'
  const lead =
    outcome.kind === 'refused' ? 'Not saved — ' : outcome.kind === 'stored' ? 'Saved, but not in effect — ' : ''
  return (
    <p role="status" className={`mt-1.5 text-xs ${tone}`}>
      {lead}
      {outcome.why}
    </p>
  )
}

// ServerHolds is the other half of the draft fix: whenever a field is showing
// something other than what Skopos holds, it says what Skopos holds.
function ServerHolds({ value }: { value: string }) {
  return (
    <p className="mt-1.5 text-xs text-fg-muted">
      Unsaved. Skopos holds <code className="rounded-sm bg-raised px-1 py-0.5 font-mono">{value}</code>.
    </p>
  )
}

// DraftFeedback is the pair every editable row needs and no row may skip.
function DraftFeedback({ dirty, server, outcome }: { dirty: boolean; server: string; outcome: Outcome | null }) {
  return (
    <>
      <OutcomeNote outcome={outcome} />
      {dirty && <ServerHolds value={server} />}
    </>
  )
}

// --- rows --------------------------------------------------------------------

// DraftRow is where the defect this release is about actually lived.
//
// The field rendered `draft || current`, so a value the operator typed and a
// value the running process holds were drawn in the same slot in the same
// style. On a successful save that was harmless by accident — the refetch made
// the two agree — but on a rejected save the draft survived, and the row went
// on presenting it as the effective setting. Label, hint and pill around it are
// all server-derived, so the row read "Automatic block lifetime: 48h — changed
// here" while the process still held 24h.
//
// The draft is its own state now, and it is only ever shown as a draft: cleared
// on success so the field goes back to reading the server, kept on failure so
// the typing is not lost, and never without the server's own value beside it.
function DraftRow({
  label,
  helpKey,
  hint,
  value,
  unit,
  numeric,
  overridden,
  canWrite,
  busy,
  nested,
  onSave,
}: {
  label: string
  helpKey: string
  hint?: string
  // What the server holds, formatted for the field.
  value: string
  unit?: string
  // Refuse to post something the decoder will reject as null.
  numeric?: boolean
  overridden: boolean
  canWrite: boolean
  busy: boolean
  nested?: boolean
  onSave: (v: string) => Promise<Outcome>
}) {
  const [draft, setDraft] = useState<string | null>(null)
  const [outcome, setOutcome] = useState<Outcome | null>(null)
  const dirty = draft !== null && draft.trim() !== value
  const shown = draft ?? value
  const usable = !numeric || Number.isInteger(Number(shown.trim()))

  const save = async () => {
    if (draft === null) return
    const o = await onSave(draft.trim())
    setOutcome(o)
    // "Stored" counts as saved: the server does hold the value, even though a
    // subsystem would not act on it. Clearing the draft is what puts the field
    // back to reading the server.
    if (o.kind === 'applied' || o.kind === 'stored') setDraft(null)
  }

  return (
    <Row
      label={label}
      helpKey={helpKey}
      hint={hint}
      overridden={overridden}
      nested={nested}
      below={<DraftFeedback dirty={dirty} server={unit ? `${value} ${unit}` : value} outcome={outcome} />}
    >
      {canWrite ? (
        <div className="flex items-center gap-2">
          <div className="w-28">
            <TextInput
              value={shown}
              onChange={(v) => {
                setDraft(v)
                setOutcome(null)
              }}
              mono
              size={nested ? 'sm' : 'md'}
              invalid={!usable}
              placeholder={value}
            />
          </div>
          {unit && <span className="text-xs text-fg-muted">{unit}</span>}
          <Button size={nested ? 'sm' : 'md'} onClick={() => void save()} disabled={busy || !dirty || !usable}>
            Save
          </Button>
        </div>
      ) : (
        <span className="font-mono text-sm">{unit ? `${value} ${unit}` : value}</span>
      )}
    </Row>
  )
}

// PairRow edits a threshold object. The override path is the whole object —
// settings.editable has "portscan.external", not "portscan.external.ports" —
// so both numbers travel in one save and one refusal covers both.
function PairRow({
  label,
  helpKey,
  values,
  overridden,
  canWrite,
  busy,
  nested,
  onSave,
}: {
  label: string
  helpKey: string
  values: { ports: number; targets: number }
  overridden: boolean
  canWrite: boolean
  busy: boolean
  nested?: boolean
  onSave: (v: { ports: number; targets: number }) => Promise<Outcome>
}) {
  const server = `${values.ports} ports · ${values.targets} targets`
  const [ports, setPorts] = useState<string | null>(null)
  const [targets, setTargets] = useState<string | null>(null)
  const [outcome, setOutcome] = useState<Outcome | null>(null)

  const shownPorts = ports ?? String(values.ports)
  const shownTargets = targets ?? String(values.targets)
  const dirty = shownPorts !== String(values.ports) || shownTargets !== String(values.targets)
  const parsed = { ports: Number(shownPorts), targets: Number(shownTargets) }
  const usable = Number.isInteger(parsed.ports) && Number.isInteger(parsed.targets)

  const save = async () => {
    const o = await onSave(parsed)
    setOutcome(o)
    if (o.kind === 'applied' || o.kind === 'stored') {
      setPorts(null)
      setTargets(null)
    }
  }

  return (
    <Row
      label={label}
      helpKey={helpKey}
      overridden={overridden}
      nested={nested}
      below={<DraftFeedback dirty={dirty} server={server} outcome={outcome} />}
    >
      {canWrite ? (
        <div className="flex items-center gap-2">
          <NumberField
            label="ports"
            value={shownPorts}
            invalid={!Number.isInteger(parsed.ports)}
            onChange={(v) => {
              setPorts(v)
              setOutcome(null)
            }}
          />
          <NumberField
            label="targets"
            value={shownTargets}
            invalid={!Number.isInteger(parsed.targets)}
            onChange={(v) => {
              setTargets(v)
              setOutcome(null)
            }}
          />
          <Button size="sm" onClick={() => void save()} disabled={busy || !dirty || !usable}>
            Save
          </Button>
        </div>
      ) : (
        <span className="font-mono text-sm">{server}</span>
      )}
    </Row>
  )
}

function NumberField({
  label,
  value,
  invalid,
  onChange,
}: {
  label: string
  value: string
  invalid: boolean
  onChange: (v: string) => void
}) {
  return (
    <label className="flex items-center gap-1.5">
      <span className="font-mono text-label uppercase text-fg-muted">{label}</span>
      <span className="block w-16">
        <TextInput value={value} onChange={onChange} mono size="sm" invalid={invalid} />
      </span>
    </label>
  )
}

function ToggleRow({
  label,
  helpKey,
  hint,
  on,
  overridden,
  canWrite,
  busy,
  nested,
  onToggle,
}: {
  label: string
  helpKey: string
  hint?: string
  on: boolean
  overridden: boolean
  canWrite: boolean
  busy: boolean
  nested?: boolean
  onToggle: (v: boolean) => Promise<Outcome>
}) {
  const [outcome, setOutcome] = useState<Outcome | null>(null)
  const flip = async (v: boolean) => setOutcome(await onToggle(v))
  return (
    <Row
      label={label}
      helpKey={helpKey}
      hint={hint}
      overridden={overridden}
      nested={nested}
      below={<OutcomeNote outcome={outcome} />}
    >
      {canWrite ? (
        // The switch renders `on`, which is server-derived, so a refused change
        // leaves it exactly where the server left it with no work here.
        <Toggle checked={on} disabled={busy} label={label} onChange={(v) => void flip(v)} />
      ) : (
        <Pill tone={on ? 'ok' : 'neutral'}>{on ? 'On' : 'Off'}</Pill>
      )}
    </Row>
  )
}

// DetectorRow is the detector's own switch plus a disclosure holding the
// thresholds behind it. Ten runtime keys had no control at all before this —
// both auto-block switches among them — and putting all ten on one flat card
// would have buried the two that decide whether the app blocks traffic on its
// own initiative.
function DetectorRow({
  label,
  helpKey,
  hint,
  enabled,
  overridden,
  canWrite,
  busy,
  moreLabel,
  onToggle,
  children,
}: {
  label: string
  helpKey: string
  hint: string
  enabled: boolean
  overridden: boolean
  canWrite: boolean
  busy: boolean
  moreLabel: string
  onToggle: (v: boolean) => Promise<Outcome>
  children: ReactNode
}) {
  const [open, setOpen] = useState(false)
  const [outcome, setOutcome] = useState<Outcome | null>(null)
  const h = useHelpToggle(helpKey)
  const help = SETTING_HELP[helpKey]
  const panelId = `detector-${helpKey.replace(/[^a-z0-9]+/gi, '-')}`
  const flip = async (v: boolean) => setOutcome(await onToggle(v))

  return (
    <div className="border-t border-line px-4 py-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0 flex-1">
          <RowLabel label={label} helpKey={helpKey} overridden={overridden} help={h} />
          <div className="mt-0.5 text-xs text-fg-muted">{hint}</div>
        </div>
        <div className="flex items-center gap-2">
          {/* A raw button rather than the Button primitive: this one needs
              aria-expanded and aria-controls to be a disclosure at all, and
              components/ui is held by another engineer this cycle. The classes
              are the ghost variant's, copied rather than diverged. */}
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            aria-controls={panelId}
            className="inline-flex items-center justify-center gap-1.5 rounded-md border border-transparent bg-transparent px-2 py-1 text-xs font-medium text-fg-muted transition-colors hover:bg-hover hover:text-fg active:bg-active pointer-coarse:min-h-11"
          >
            <span aria-hidden>{open ? '▾' : '▸'}</span>
            {moreLabel}
          </button>
          {canWrite ? (
            <Toggle checked={enabled} disabled={busy} label={label} onChange={(v) => void flip(v)} />
          ) : (
            <Pill tone={enabled ? 'ok' : 'neutral'}>{enabled ? 'On' : 'Off'}</Pill>
          )}
        </div>
      </div>
      <OutcomeNote outcome={outcome} />
      {help && h.open && <HelpPanel id={h.panelId} help={help} />}
      {open && (
        <div id={panelId} className="mt-2 border-l-2 border-line pl-3">
          {children}
        </div>
      )}
    </div>
  )
}

function QuietHoursRow({
  value,
  overridden,
  canWrite,
  busy,
  onSave,
}: {
  value: RS['quiet_hours']
  overridden: boolean
  canWrite: boolean
  busy: boolean
  onSave: (v: RS['quiet_hours']) => Promise<Outcome>
}) {
  const serverFrom = clockString(value.from_hour, value.from_minute)
  const serverTo = clockString(value.to_hour, value.to_minute)
  const [from, setFrom] = useState<string | null>(null)
  const [to, setTo] = useState<string | null>(null)
  const [severity, setSeverity] = useState<string | null>(null)
  const [outcome, setOutcome] = useState<Outcome | null>(null)

  const shownFrom = from ?? serverFrom
  const shownTo = to ?? serverTo
  const shownSeverity = severity ?? value.min_severity
  const dirty = shownFrom !== serverFrom || shownTo !== serverTo || shownSeverity !== value.min_severity
  const parsedFrom = parseClock(shownFrom)
  const parsedTo = parseClock(shownTo)
  const server = `${serverFrom}–${serverTo}, ${value.min_severity || 'unset'} and above`

  // quiet_hours is overridden as one object — settings.editable has no path
  // into its fields — so every control here posts the whole thing.
  const patched = (over: Partial<RS['quiet_hours']>): RS['quiet_hours'] => ({ ...value, ...over })

  const saveWindow = async () => {
    if (!parsedFrom || !parsedTo) return
    const o = await onSave(
      patched({
        from_hour: parsedFrom.hour,
        from_minute: parsedFrom.minute,
        to_hour: parsedTo.hour,
        to_minute: parsedTo.minute,
        min_severity: shownSeverity,
      }),
    )
    setOutcome(o)
    if (o.kind === 'applied' || o.kind === 'stored') {
      setFrom(null)
      setTo(null)
      setSeverity(null)
    }
  }

  const flip = async (v: boolean) => setOutcome(await onSave(patched({ enabled: v })))

  return (
    <Row
      label="Quiet hours"
      helpKey="quiet_hours"
      hint={
        value.enabled
          ? `Between ${serverFrom} and ${serverTo}, only ${value.min_severity || 'critical'} and above is pushed. Everything is still recorded.`
          : 'Off — every alert that clears the cooldown is pushed, at any hour.'
      }
      overridden={overridden}
      below={
        <>
          {canWrite && (
            <div className="mt-2 flex flex-wrap items-end gap-3">
              <ClockField
                label="From"
                value={shownFrom}
                invalid={!parsedFrom}
                onChange={(v) => {
                  setFrom(v)
                  setOutcome(null)
                }}
              />
              <ClockField
                label="To"
                value={shownTo}
                invalid={!parsedTo}
                onChange={(v) => {
                  setTo(v)
                  setOutcome(null)
                }}
              />
              <div className="flex flex-col gap-1">
                <span className="font-mono text-label uppercase text-fg-muted">Still delivered</span>
                <Segmented<string>
                  ariaLabel="Lowest severity still delivered during quiet hours"
                  size="sm"
                  value={shownSeverity}
                  onChange={(v) => {
                    setSeverity(v)
                    setOutcome(null)
                  }}
                  options={[
                    { value: 'info', label: 'Info', hint: 'everything — the same as switching this off' },
                    { value: 'warning', label: 'Warning' },
                    { value: 'critical', label: 'Critical' },
                  ]}
                />
              </div>
              <Button
                size="sm"
                onClick={() => void saveWindow()}
                disabled={busy || !dirty || !parsedFrom || !parsedTo}
              >
                Save
              </Button>
            </div>
          )}
          {/* An empty min_severity is a real state the server holds, and the
              policy engine treats it as critical. Painting "critical" into the
              control would be this page answering a question only config.yaml
              can answer. */}
          {value.min_severity === '' && (
            <p className="mt-1.5 text-xs text-fg-muted">
              No minimum severity is set in your configuration. Skopos treats that as <strong>critical</strong>.
            </p>
          )}
          <DraftFeedback dirty={dirty} server={server} outcome={outcome} />
        </>
      }
    >
      {canWrite ? (
        <Toggle checked={value.enabled} disabled={busy} label="Quiet hours" onChange={(v) => void flip(v)} />
      ) : (
        <Pill tone={value.enabled ? 'ok' : 'neutral'}>{value.enabled ? 'On' : 'Off'}</Pill>
      )}
    </Row>
  )
}

function ClockField({
  label,
  value,
  invalid,
  onChange,
}: {
  label: string
  value: string
  invalid: boolean
  onChange: (v: string) => void
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="font-mono text-label uppercase text-fg-muted">{label}</span>
      <span className="block w-28">
        <TextInput value={value} onChange={onChange} type="time" mono size="sm" invalid={invalid} />
      </span>
    </label>
  )
}

function AllowlistRow({
  value,
  overridden,
  canWrite,
  busy,
  onSave,
}: {
  value: string[]
  overridden: boolean
  canWrite: boolean
  busy: boolean
  onSave: (list: string[]) => Promise<Outcome>
}) {
  const [entry, setEntry] = useState('')
  const [outcome, setOutcome] = useState<Outcome | null>(null)
  const h = useHelpToggle('allowlist')
  const help = SETTING_HELP.allowlist

  // The input used to be cleared synchronously beside an un-awaited save, so a
  // rejected entry took the operator's typing with it and left nothing to
  // correct. It is cleared on the outcome now, not on the click.
  const add = async () => {
    const e = entry.trim()
    if (!e) return
    const o = await onSave([...value, e])
    setOutcome(o)
    if (o.kind === 'applied' || o.kind === 'stored') setEntry('')
  }

  const remove = async (v: string) => setOutcome(await onSave(value.filter((x) => x !== v)))

  return (
    <div className="border-t border-line px-4 py-3">
      <div className="flex items-center gap-2 text-sm font-medium">
        Never-block allowlist
        <HelpDot label="the never-block allowlist" open={h.open} panelId={h.panelId} onToggle={h.toggle} />
        {overridden && (
          <Pill tone="accent" title="Set from this dashboard. It shadows the value in config.yaml.">
            changed here
          </Pill>
        )}
      </div>
      <div className="mt-0.5 text-xs text-fg-muted">
        These addresses are never blocked, whatever a detector says. Your gateway is on the list too, and
        Skopos will not take it off.
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        {value.length === 0 && <span className="text-xs text-fg-muted">Nothing beyond the gateway.</span>}
        {value.map((v) => (
          <Pill key={v} onRemove={canWrite && !busy ? () => void remove(v) : undefined} title={v}>
            <span className="font-mono">{v}</span>
          </Pill>
        ))}
      </div>
      {canWrite && (
        <div className="mt-2 flex items-center gap-2">
          <div className="w-56">
            <TextInput
              value={entry}
              onChange={(v) => {
                setEntry(v)
                setOutcome(null)
              }}
              mono
              placeholder="192.168.1.10 or 10.0.0.0/8"
              onKeyDown={(e) => {
                if (e.key === 'Enter') void add()
              }}
            />
          </div>
          <Button onClick={() => void add()} disabled={busy || !entry.trim()}>
            Add
          </Button>
        </div>
      )}
      <OutcomeNote outcome={outcome} />
      {help && h.open && <HelpPanel id={h.panelId} help={help} />}
    </div>
  )
}

export type { RS }
