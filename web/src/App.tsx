import { useCallback, useEffect, useState } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { api, APIError, type Me } from './lib/api'
import { Layout } from './components/Layout'
import { Login } from './views/Login'
import { Now } from './views/Now'
import { DeviceDetail } from './views/DeviceDetail'
import { Traffic } from './views/Traffic'
import { Devices } from './views/Devices'
import { Firewall } from './views/Firewall'
import { Alerts } from './views/Alerts'
import { AlertDetail } from './views/AlertDetail'
import { IncidentDetail } from './views/IncidentDetail'
import { IPDossier } from './views/IPDossier'
import { DomainDetail } from './views/DomainDetail'
import { Cloudflare } from './views/Cloudflare'
import { Settings } from './views/Settings'
import { System } from './views/System'
import { NotFound } from './views/NotFound'

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

  // Eight destinations and five entity routes. /live and /domains are gone as
  // pages — they are a position on Traffic's time control and a lens on it —
  // and `*` is a real 404 rather than the dashboard wearing someone else's
  // address.
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout me={me} onLogout={logout} onUnauthorized={onUnauthorized} />}>
          <Route index element={<Now onUnauthorized={onUnauthorized} />} />
          <Route path="traffic" element={<Traffic onUnauthorized={onUnauthorized} />} />
          <Route path="devices" element={<Devices onUnauthorized={onUnauthorized} canWrite={canWrite} />} />
          <Route path="devices/:mac" element={<DeviceDetail onUnauthorized={onUnauthorized} canWrite={canWrite} />} />
          <Route path="cloudflare" element={<Cloudflare onUnauthorized={onUnauthorized} canWrite={canWrite} />} />
          <Route path="alerts" element={<Alerts onUnauthorized={onUnauthorized} canWrite={canWrite} />} />
          {/* The ntfy landing target: every push links here. */}
          <Route path="alerts/:id" element={<AlertDetail onUnauthorized={onUnauthorized} canWrite={canWrite} />} />
          <Route path="incidents/:id" element={<IncidentDetail onUnauthorized={onUnauthorized} canWrite={canWrite} />} />
          <Route path="firewall" element={<Firewall onUnauthorized={onUnauthorized} canWrite={canWrite} />} />
          <Route path="ip/:addr" element={<IPDossier onUnauthorized={onUnauthorized} canWrite={canWrite} />} />
          <Route path="domain/:name" element={<DomainDetail onUnauthorized={onUnauthorized} />} />
          <Route path="system" element={<System onUnauthorized={onUnauthorized} canWrite={canWrite} />} />
          <Route path="settings" element={<Settings onUnauthorized={onUnauthorized} canWrite={canWrite} />} />
          <Route path="*" element={<NotFound onUnauthorized={onUnauthorized} />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
