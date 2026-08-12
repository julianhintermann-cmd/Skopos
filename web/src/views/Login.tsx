import { useState } from 'react'
import { api, APIError } from '../lib/api'
import { Logo } from '../components/Logo'
import { Button } from '../components/ui'
import { ThemeToggle } from '../components/ThemeToggle'

export function Login({ onSuccess }: { onSuccess: () => void }) {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      await api.post('/api/auth/login', { username, password })
      onSuccess()
    } catch (err) {
      if (err instanceof APIError && err.status === 429) {
        setError('Too many attempts. Please wait a moment.')
      } else {
        setError('Invalid credentials.')
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4" style={{ background: 'var(--bg)' }}>
      <div className="absolute right-4 top-4">
        <ThemeToggle />
      </div>
      <div
        className="w-full max-w-sm rounded-xl border p-7"
        style={{ background: 'var(--surface)', borderColor: 'var(--border)' }}
      >
        <div className="mb-6 flex items-center gap-3">
          <Logo size={34} />
          <div>
            <div className="font-mono text-base font-semibold uppercase tracking-[0.3em]">Skopos</div>
            <div className="text-xs" style={{ color: 'var(--muted)' }}>
              σκοπός — the watcher
            </div>
          </div>
        </div>
        <form onSubmit={submit} className="flex flex-col gap-3">
          <label className="flex flex-col gap-1">
            <span className="font-mono text-[0.62rem] font-semibold uppercase tracking-[0.1em]" style={{ color: 'var(--muted)' }}>
              Username
            </span>
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              className="rounded-md border px-3 py-2 text-sm"
              style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text)' }}
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className="font-mono text-[0.62rem] font-semibold uppercase tracking-[0.1em]" style={{ color: 'var(--muted)' }}>
              Password
            </span>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              className="rounded-md border px-3 py-2 text-sm"
              style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text)' }}
            />
          </label>
          {error && <p className="text-xs" style={{ color: 'var(--crit)' }}>{error}</p>}
          <Button type="submit" variant="primary" disabled={busy || !password} className="mt-1 w-full">
            {busy ? 'Signing in…' : 'Sign in'}
          </Button>
        </form>
      </div>
    </div>
  )
}
