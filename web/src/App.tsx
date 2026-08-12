import { useCallback, useEffect, useState } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { api, APIError, type Me } from './lib/api'
import { Layout } from './components/Layout'
import { Login } from './views/Login'
import { Overview } from './views/Overview'
import { Traffic } from './views/Traffic'
import { Devices } from './views/Devices'
import { Firewall } from './views/Firewall'
import { Alerts } from './views/Alerts'
import { System } from './views/System'

type AuthState = 'loading' | 'authenticated' | 'anonymous'

export default function App() {
  const [auth, setAuth] = useState<AuthState>('loading')
  const [me, setMe] = useState<Me | null>(null)

  const loadMe = useCallback(async () => {
    try {
      const m = await api.get<Me>('/api/me')
      setMe(m)
      setAuth('authenticated')
    } catch (e) {
      if (e instanceof APIError && e.status === 401) {
        setAuth('anonymous')
      } else {
        // Network hiccup: retry shortly rather than bouncing to login.
        setTimeout(loadMe, 2000)
      }
    }
  }, [])

  useEffect(() => {
    loadMe()
  }, [loadMe])

  const onUnauthorized = useCallback(() => setAuth('anonymous'), [])
  const logout = useCallback(async () => {
    await api.post('/api/auth/logout').catch(() => {})
    setAuth('anonymous')
    setMe(null)
  }, [])

  if (auth === 'loading') {
    return (
      <div className="flex min-h-screen items-center justify-center" style={{ color: 'var(--muted)' }}>
        <span className="font-mono text-sm tracking-[0.3em] uppercase">Skopos</span>
      </div>
    )
  }

  if (auth === 'anonymous') {
    return <Login onSuccess={loadMe} />
  }

  const canWrite = !me?.auth || me?.scope === 'write'

  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout me={me} onLogout={logout} />}>
          <Route index element={<Overview onUnauthorized={onUnauthorized} />} />
          <Route path="traffic" element={<Traffic onUnauthorized={onUnauthorized} />} />
          <Route path="devices" element={<Devices onUnauthorized={onUnauthorized} />} />
          <Route path="firewall" element={<Firewall onUnauthorized={onUnauthorized} canWrite={canWrite} />} />
          <Route path="alerts" element={<Alerts onUnauthorized={onUnauthorized} canWrite={canWrite} />} />
          <Route path="system" element={<System onUnauthorized={onUnauthorized} canWrite={canWrite} />} />
          <Route path="alerts/:id" element={<Alerts onUnauthorized={onUnauthorized} canWrite={canWrite} />} />
          <Route path="*" element={<Overview onUnauthorized={onUnauthorized} />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
