import { useState } from 'react'
import { api, type AIStatus } from '../lib/api'
import { useFetch } from '../lib/useFetch'
import { Button, Card, CardHeader } from './ui'

// "Explain this alert" — the one place the AI integration is used.
//
// It is a button, never a poll and never a page load, and that is the whole
// design. A request only ever happens because somebody pressed this, which
// bounds what it can cost, keeps the privacy exposure legible to the person
// who caused it, and makes a failure a visible error rather than a silent
// nightly leak.
//
// The card renders nothing at all until a provider is configured and switched
// on. An operator who has not opted in should not be shown a button whose only
// function is to ask them to opt in.

interface ExplainResponse {
  answer: string
  // The exact redacted payload that was sent. Shown on request, so "what
  // leaves this machine" is something the operator can read rather than a
  // claim in a settings page they have to take on faith.
  sent: unknown
}

export function ExplainAlert({ alertID, canWrite }: { alertID: number; canWrite: boolean }) {
  const ai = useFetch<AIStatus>('/api/integrations/ai')
  const [answer, setAnswer] = useState<ExplainResponse | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [showSent, setShowSent] = useState(false)

  if (!ai.data?.configured || !ai.data.enabled) return null

  async function explain() {
    setBusy(true)
    setErr('')
    try {
      setAnswer(await api.post<ExplainResponse>('/api/integrations/ai/explain', { alert_id: alertID }))
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
        sub={`a language model's reading of the finding — ${ai.data.provider}`}
      />
      <div className="space-y-3 px-4 py-3 text-sm" style={{ borderTop: '1px solid var(--border)' }}>
        {!answer && (
          <div className="flex flex-wrap items-center gap-3">
            <Button onClick={explain} loading={busy} disabled={!canWrite}>
              Explain this alert
            </Button>
            <span className="text-xs" style={{ color: 'var(--muted)' }}>
              Sends a redacted description of this one alert to {ai.data.provider}.
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
