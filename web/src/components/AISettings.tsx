import { useState } from 'react'
import { api, type AIProvider, type AIStatus } from '../lib/api'
import { useFetch } from '../lib/useFetch'
import { Button, Card, CardHeader, Field, Pill, Segmented, TextInput, Toggle, useToast } from './ui'


// The AI integration's settings card.
//
// The disclosure below is not boilerplate and is deliberately not a checkbox
// with "I agree". Every other feature in Skopos runs on the NAS and sends
// nothing anywhere; this one does not, and it is the only place the product's
// central promise stops being true. A household network carries the browsing
// of people who never agreed to any of it, so the copy says that in those
// words rather than in the language of a privacy policy.

export function AISettings({ canWrite }: { canWrite: boolean }) {
  const st = useFetch<AIStatus>('/api/integrations/ai')
  const [provider, setProvider] = useState<AIProvider | ''>('')
  const [key, setKey] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const toast = useToast()

  const data = st.data
  const providers = data?.providers ?? []
  const chosen = providers.find((p) => p.id === provider)

  async function connect() {
    if (!provider) return
    setBusy(true)
    setErr('')
    try {
      await api.post('/api/integrations/ai', { provider, key: key.trim() })
      // The plaintext leaves React state the moment the server has it.
      setKey('')
      st.refresh()
      toast.show({ tone: 'good', message: 'Key verified and stored' })
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  async function patch(body: Record<string, unknown>, note: string) {
    setBusy(true)
    setErr('')
    try {
      await api.patch('/api/integrations/ai', body)
      st.refresh()
      toast.show({ tone: 'good', message: note })
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  async function disconnect() {
    setBusy(true)
    setErr('')
    try {
      await api.del('/api/integrations/ai')
      st.refresh()
      toast.show({ tone: 'good', message: 'Key deleted' })
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader
        title="AI explanations"
        sub="turn one alert into one paragraph, on demand"
      />

      <div className="space-y-4 px-4 py-4 text-sm" style={{ borderTop: '1px solid var(--border)' }}>
        {data?.configured ? (
          <div className="flex flex-wrap items-center gap-3">
            <Pill tone={data.enabled ? 'good' : 'neutral'}>
              {data.enabled ? 'On' : 'Off'}
            </Pill>
            <span style={{ color: 'var(--muted)' }}>
              {providers.find((p) => p.id === data.provider)?.label ?? data.provider}
              {' · '}key ending {data.key_tail}
              {data.model ? ` · ${data.model}` : ''}
            </span>
          </div>
        ) : (
          <Pill tone="neutral">Not configured</Pill>
        )}

        <Disclosure providerLabel={
          data?.configured
            ? providers.find((p) => p.id === data.provider)?.label ?? 'the provider'
            : chosen?.label ?? 'the provider you pick'
        } />

        {!data?.configured && (
          <>
            {/* The provider is chosen before the key field appears. The three
                key formats differ, and asking for a key without knowing which
                service it is for invites pasting the wrong one. */}
            <Field label="Provider" hint="pick where the explanation is generated">
              <Segmented
                ariaLabel="AI provider"
                value={provider}
                onChange={(v) => setProvider(v as AIProvider)}
                options={[
                  { value: '', label: 'Choose…' },
                  ...providers.map((p) => ({ value: p.id, label: p.label })),
                ]}
              />
            </Field>

            {chosen && (
              <Field
                label="API key"
                hint={
                  <>
                    Starts with <code>{chosen.key_prefix}</code>. Create one at{' '}
                    <a
                      href={chosen.keys_url}
                      target="_blank"
                      rel="noreferrer"
                      className="underline"
                      style={{ color: 'var(--accent-strong)' }}
                    >
                      {new URL(chosen.keys_url).host}
                    </a>
                    . It is checked against {chosen.label} before anything is stored.
                  </>
                }
                error={err}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <TextInput
                    value={key}
                    onChange={setKey}
                    mono
                    type="password"
                    autoComplete="off"
                    spellCheck={false}
                    placeholder={chosen.key_prefix + '…'}
                    disabled={!canWrite || busy}
                    onKeyDown={(e) => e.key === 'Enter' && connect()}
                  />
                  <Button
                    variant="primary"
                    onClick={connect}
                    loading={busy}
                    disabled={!canWrite || !key.trim()}
                  >
                    Verify &amp; save
                  </Button>
                </div>
                {key.trim() !== '' && !key.trim().startsWith(chosen.key_prefix) && (
                  <div className="mt-1 text-xs" style={{ color: 'var(--warn)' }}>
                    That does not look like a {chosen.label} key — they usually start with{' '}
                    <code>{chosen.key_prefix}</code>. It will still be tried.
                  </div>
                )}
              </Field>
            )}
          </>
        )}

        {data?.configured && (
          <>
            <Field
              label="Send data to the provider"
              hint="off means no request is made, not even a test one"
            >
              <Toggle
                checked={data.enabled}
                onChange={(v) => patch({ enabled: v }, v ? 'AI explanations on' : 'AI explanations off')}
                disabled={!canWrite || busy}
                label="Enabled"
              />
            </Field>

            <ModelField
              current={data.model ?? ''}
              placeholder={providers.find((p) => p.id === data.provider)?.default_model}
              disabled={!canWrite || busy}
              onCommit={(v) => patch({ model: v }, 'Model changed')}
            />

            {err && <div className="text-xs" style={{ color: 'var(--crit)' }}>{err}</div>}

            <Button variant="danger" onClick={disconnect} disabled={!canWrite || busy}>
              Delete key
            </Button>
          </>
        )}
      </div>
    </Card>
  )
}

// ModelField holds the typed value locally and commits on Enter or an explicit
// Save.
//
// Bound straight to the PATCH, it fired one request per keystroke — a dozen
// round trips and a dozen audit entries to type one model name, each racing
// the next.
function ModelField({
  current,
  placeholder,
  disabled,
  onCommit,
}: {
  current: string
  placeholder?: string
  disabled?: boolean
  onCommit: (v: string) => void
}) {
  const [draft, setDraft] = useState(current)
  // Re-sync when the server's value changes underneath, during render rather
  // than in an effect. Keying on the last value seen means a poll landing
  // mid-edit does not silently discard what is being typed.
  const [seen, setSeen] = useState(current)
  if (seen !== current) {
    setSeen(current)
    setDraft(current)
  }
  const dirty = draft.trim() !== current && draft.trim() !== ''
  return (
    <Field label="Model" hint="a cheap, fast model is enough for a paragraph">
      <div className="flex flex-wrap items-center gap-2">
        <TextInput
          value={draft}
          onChange={setDraft}
          mono
          disabled={disabled}
          placeholder={placeholder}
          onKeyDown={(e) => e.key === 'Enter' && dirty && onCommit(draft.trim())}
        />
        {dirty && (
          <Button onClick={() => onCommit(draft.trim())} disabled={disabled}>
            Save
          </Button>
        )}
      </div>
    </Field>
  )
}

// Disclosure states what turning this on actually does, before it is turned on.
function Disclosure({ providerLabel }: { providerLabel: string }) {
  return (
    <div
      className="space-y-2 rounded-md px-3 py-2.5 text-xs"
      style={{ background: 'var(--surface-2)', color: 'var(--muted)' }}
    >
      <p style={{ color: 'var(--text)' }}>
        <strong>This sends data about your network to a company on the internet.</strong>
      </p>
      <p>
        Everything else Skopos captures stays on this machine. This does not. When you press
        “Explain”, a short description of that one alert goes to {providerLabel} and the reply
        is shown to you.
      </p>
      <p>
        <strong style={{ color: 'var(--text)' }}>What is sent:</strong> the detector name and
        severity, counts, the country, and addresses reduced to a shape like{' '}
        <code>192.168.1.x</code>.{' '}
        <strong style={{ color: 'var(--text)' }}>What is never sent:</strong> MAC addresses,
        device names you typed, DHCP hostnames, your public IP, packet contents, or your
        configuration. Every answer shows you the exact payload that left.
      </p>
      <p>
        <strong style={{ color: 'var(--text)' }}>Only when you click.</strong> Nothing is sent on
        a schedule or in the background.
      </p>
      <p>
        This is not only your data. A home network carries the browsing of everyone in the
        household, and they have not agreed to this. The provider’s terms apply, not Skopos’ —
        nothing can be recalled once it is sent. Answers come from a language model and{' '}
        <strong style={{ color: 'var(--text)' }}>can be confidently wrong</strong>; treat them as
        a starting point, never as a finding.
      </p>
    </div>
  )
}
