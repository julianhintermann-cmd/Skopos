import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api, type AIStatus } from '../lib/api'
import { useFetch } from '../lib/useFetch'
import { Button, Card, CardHeader } from './ui'

// "Explain this" — the one place the AI integration is used.
//
// It is a button, never a poll and never a page load, and that is the whole
// design. A request only ever happens because somebody pressed this, which
// bounds what it can cost, keeps the privacy exposure legible to the person
// who caused it, and makes a failure a visible error rather than a silent
// nightly leak.
//
// It mounts on both detail pages, because there are two. The alerts list opens
// episodes and an ntfy push opens a single alert; shipped on only one of them,
// the feature was invisible to anyone arriving the ordinary way.
//
// The card renders nothing at all until a provider is configured. An operator
// who has not opted in should not be shown a button whose only function is to
// ask them to opt in — an alert page does not owe a paid third-party service
// any advertising.
//
// Configured-but-switched-off is a different state, and it is the one that
// traps people: the key was pasted, the toast said it was stored, and then this
// page looks exactly like it did before. Rendering nothing there is not
// restraint, it is a dead end. That state gets one line and the way out.

interface ExplainResponse {
  answer: string
  // The exact redacted payload that was sent. Shown on request, so "what
  // leaves this machine" is something the operator can read rather than a
  // claim in a settings page they have to take on faith.
  sent: unknown
}

// Subject is a union rather than two optional numbers so that "neither" and
// "both" are not states a caller can reach.
export type ExplainSubject = { alert: number } | { incident: number }

export function Explain({ subject, canWrite }: { subject: ExplainSubject; canWrite: boolean }) {
  const ai = useFetch<AIStatus>('/api/integrations/ai')
  const [answer, setAnswer] = useState<ExplainResponse | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [showSent, setShowSent] = useState(false)

  if (!ai.data?.configured) return null

  const label =
    ai.data.providers?.find((p) => p.id === ai.data?.provider)?.label ?? ai.data.provider

  if (!ai.data.enabled) {
    return (
      <Card>
        <CardHeader title="Explain this" sub="a key is stored, but sending is switched off" />
        <div
          className="px-4 py-3 text-sm"
          style={{ borderTop: '1px solid var(--border)', color: 'var(--muted)' }}
        >
          Your {label} key is saved. Nothing is sent anywhere until you turn sending on, so there
          is no button here yet —{' '}
          <Link to="/settings" className="underline" style={{ color: 'var(--accent-strong)' }}>
            switch it on under “AI explanations”
          </Link>
          .
        </div>
      </Card>
    )
  }

  const noun = 'alert' in subject ? 'alert' : 'episode'
  const body = 'alert' in subject ? { alert_id: subject.alert } : { incident_id: subject.incident }

  async function explain() {
    setBusy(true)
    setErr('')
    try {
      setAnswer(await api.post<ExplainResponse>('/api/integrations/ai/explain', body))
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader
        title="Explain this"
        sub={`a language model's reading of the finding — ${label}`}
      />
      <div className="space-y-3 px-4 py-3 text-sm" style={{ borderTop: '1px solid var(--border)' }}>
        {!answer && (
          <div className="flex flex-wrap items-center gap-3">
            <Button onClick={explain} loading={busy} disabled={!canWrite}>
              Explain this {noun}
            </Button>
            <span className="text-xs" style={{ color: 'var(--muted)' }}>
              Sends a redacted description of this one {noun} to {label}.
            </span>
          </div>
        )}

        {err && (
          <div className="text-xs" style={{ color: 'var(--crit)' }}>
            {err}
          </div>
        )}

        {answer && (
          <>
            {/* Visually separated from Skopos' own findings on purpose. This
                paragraph is the one thing on the page that is not a
                measurement, and it must not read like one. */}
            <div
              className="animate-appear whitespace-pre-wrap rounded-md px-3 py-2.5"
              style={{ background: 'var(--surface-2)' }}
            >
              {answer.answer}
            </div>
            <div className="flex flex-wrap items-center gap-3 text-xs" style={{ color: 'var(--muted)' }}>
              <span>
                Written by a language model. It can be confidently wrong — the measurements above
                are the record.
              </span>
              <button
                type="button"
                className="underline transition-colors"
                style={{ color: 'var(--accent-strong)' }}
                onClick={() => setShowSent((v) => !v)}
              >
                {showSent ? 'Hide' : 'What was sent?'}
              </button>
              <button
                type="button"
                className="underline transition-colors"
                style={{ color: 'var(--accent-strong)' }}
                onClick={() => {
                  setAnswer(null)
                  setShowSent(false)
                }}
              >
                Ask again
              </button>
            </div>
            {showSent && (
              <pre
                className="animate-appear overflow-x-auto rounded-md px-3 py-2 font-mono text-xs"
                style={{ background: 'var(--surface-3)', color: 'var(--muted)' }}
              >
                {JSON.stringify(answer.sent, null, 2)}
              </pre>
            )}
          </>
        )}
      </div>
    </Card>
  )
}
