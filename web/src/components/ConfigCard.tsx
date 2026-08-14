import type { ReactNode } from 'react'
import { useFetch } from '../lib/useFetch'
import { Card, CardHeader, Pill, Banner, Code, NoData, Skeleton } from './ui'
import { formatTime } from '../lib/format'

// ConfigReport is GET /api/config: what the running process actually loaded,
// as opposed to what any form on this page has been typed into.
//
// It is declared here rather than in lib/api.ts because that file is held by
// another engineer this cycle — the staging arrangement lib/contracts.ts
// documents — and it belongs there when the two are folded together.
//
// Nothing in this shape is a secret and nothing is a masked stand-in for one.
// A masked secret is still a claim about a secret, and the only claim this card
// is allowed to make is whether one is set.
export interface ConfigReport {
  // The path the process tried to load, present whether or not it was there.
  // This is the field that makes a mistyped bind mount visible: without the
  // path, "not found" cannot be acted on.
  path: string
  found: boolean
  loaded_at?: string
  // Keys present in the operator's own file that this build parses, validates
  // and then does not read. Only keys actually in the file — listing every
  // inert key in the schema would be noise on a correct install.
  inert_keys?: string[] | null
  notify: {
    ntfy: { configured: boolean; url?: string; topic?: string }
    webhook: { configured: boolean; url?: string }
  }
}

// ConfigCard answers the question no screen in this app could answer: is the
// running process using the file you think it is?
//
// config.Load treats a missing file as success and runs on built-in defaults,
// and LoadInfo.Missing reaches exactly one place — a line on stderr at
// startup. So one typo in a Docker volume mount produces a Skopos that comes
// up healthy, observes instead of enforcing, has no allowlist and none of the
// thresholds the operator tuned, and looks identical to a correct install.
//
// Every line here is read back from the server. None of it is derived from the
// forms on this page: a settings screen that reports the state of its own
// inputs is the purest form of the defect this release is about.
export function ConfigCard({
  onUnauthorized,
  cloudflare,
  cloudflareError,
}: {
  onUnauthorized: () => void
  // Server-derived Cloudflare state, already fetched by the Settings view and
  // passed down rather than fetched again. Two requests for one fact can
  // disagree on screen, and the disagreement would be between two halves of
  // the same page.
  cloudflare: { connected: boolean; zones: number } | null
  cloudflareError: string | null
}) {
  const { data, loading, error } = useFetch<ConfigReport>('/api/config', { onUnauthorized })

  return (
    <Card>
      <CardHeader
        title="Configuration"
        sub="what the running process loaded — read back from the server, not from this page"
      />

      {loading && !data && !error ? (
        <Skeleton variant="row" rows={4} />
      ) : error ? (
        <div className="px-4 pb-4">
          {/* Loud rather than absent. The whole reason this card exists is that
              "Skopos cannot tell you which file it read" and "Skopos read your
              file" used to look the same, and a silent failure here would
              reproduce that exactly. */}
          <Banner tone="warn" title="Skopos did not say where its configuration came from">
            <code className="font-mono">GET /api/config</code> failed: {error}. Until it answers, nothing on
            this page can tell you whether your config.yaml was read — a mistyped volume mount looks exactly
            like a correct one.
          </Banner>
        </div>
      ) : data ? (
        <>
          <Fact
            label="Configuration file"
            pill={
              data.found ? (
                <Pill tone="ok">Loaded</Pill>
              ) : (
                <Pill tone="warn">Not found</Pill>
              )
            }
            detail={
              data.found
                ? data.loaded_at
                  ? `Read at ${formatTime(data.loaded_at)}. Restart Skopos to pick up an edit.`
                  : 'Restart Skopos to pick up an edit.'
                : 'Skopos is running on its built-in defaults: observe mode, no allowlist, default thresholds and retention. Everything in your file is being ignored — check the path above against your volume mount.'
            }
          >
            <Code>{data.path}</Code>
          </Fact>

          <Fact
            label="Keys with no effect"
            pill={
              data.inert_keys && data.inert_keys.length > 0 ? (
                <Pill tone="warn">{data.inert_keys.length}</Pill>
              ) : (
                <Pill tone="ok">None</Pill>
              )
            }
            detail={
              data.inert_keys && data.inert_keys.length > 0
                ? 'This build parses and validates these and then reads none of them. They are kept so existing files keep loading; setting them changes nothing.'
                : 'Every key in your file is read by this build.'
            }
          >
            {data.inert_keys && data.inert_keys.length > 0 ? (
              <span className="flex flex-wrap gap-1.5">
                {data.inert_keys.map((k) => (
                  <Code key={k}>{k}</Code>
                ))}
              </span>
            ) : (
              <span className="text-sm text-fg-muted">—none in your file</span>
            )}
          </Fact>

          <Fact
            label="ntfy"
            pill={
              data.notify.ntfy.configured ? <Pill tone="ok">Configured</Pill> : <Pill tone="neutral">Not configured</Pill>
            }
            detail={
              data.notify.ntfy.configured
                ? 'The credential, if any, is read from the environment and is never sent to this page.'
                : 'No ntfy server is set in notify.ntfy.url, so alerts have nowhere to be pushed.'
            }
          >
            {data.notify.ntfy.configured ? (
              <span className="text-sm">
                <Code>{data.notify.ntfy.url ?? 'server not reported'}</Code>
                {data.notify.ntfy.topic && (
                  <>
                    {' → '}
                    <Code>{data.notify.ntfy.topic}</Code>
                  </>
                )}
              </span>
            ) : (
              <NoData reason="nothing set" inline />
            )}
          </Fact>

          <Fact
            label="Webhook"
            pill={
              data.notify.webhook.configured ? (
                <Pill tone="ok">Configured</Pill>
              ) : (
                <Pill tone="neutral">Not configured</Pill>
              )
            }
          >
            {data.notify.webhook.configured ? (
              <Code>{data.notify.webhook.url ?? 'endpoint not reported'}</Code>
            ) : (
              <NoData reason="nothing set" inline />
            )}
          </Fact>

          {!data.notify.ntfy.configured && !data.notify.webhook.configured && (
            <div className="px-4 pb-3">
              <Banner tone="warn" title="No notification channel is configured">
                Skopos will keep detecting and recording, and it has nowhere to send any of it. A test
                notification below will report the same thing.
              </Banner>
            </div>
          )}
        </>
      ) : null}

      <Fact
        label="Cloudflare"
        pill={
          cloudflareError ? (
            <Pill tone="unknown">Unknown</Pill>
          ) : cloudflare === null ? (
            <Pill tone="unknown">Checking</Pill>
          ) : cloudflare.connected ? (
            <Pill tone="ok">Connected</Pill>
          ) : (
            <Pill tone="neutral">Not connected</Pill>
          )
        }
        detail={
          cloudflareError
            ? undefined
            : 'The API token is write-only: it is stored sealed and no endpoint returns it. Only its identifier is ever shown, on the Cloudflare page.'
        }
      >
        {cloudflareError ? (
          <NoData reason={`Skopos could not be asked: ${cloudflareError}`} inline />
        ) : cloudflare === null ? (
          <NoData reason="asking the server" inline />
        ) : cloudflare.connected ? (
          <span className="text-sm">
            {cloudflare.zones} zone{cloudflare.zones === 1 ? '' : 's'} monitored
          </span>
        ) : (
          <NoData reason="no token stored" inline />
        )}
      </Fact>

      <p className="px-4 pb-4 pt-3 text-xs text-fg-muted" style={{ borderTop: '1px solid var(--sk-line)' }}>
        Settings changed from the dashboard live in the Skopos database, not in this file, and they shadow it
        — a key overridden here keeps its dashboard value even after you edit the file and restart. The
        Protection card marks each one <em>changed here</em> and can drop them all at once.
      </p>
    </Card>
  )
}

// Fact is one server-reported statement: what it is, the value, a verdict, and
// what it means when the verdict is bad. The last part is the one that is
// normally left off, and it is the reason the card exists — "not found" without
// "so your thresholds are being ignored" is a status, not information.
function Fact({
  label,
  pill,
  detail,
  children,
}: {
  label: string
  pill: ReactNode
  detail?: string
  children: ReactNode
}) {
  return (
    <div className="border-t border-line px-4 py-3">
      <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium">{label}</div>
          <div className="mt-1 min-w-0 break-words">{children}</div>
        </div>
        {pill}
      </div>
      {detail && <p className="mt-1.5 text-xs text-fg-muted">{detail}</p>}
    </div>
  )
}
