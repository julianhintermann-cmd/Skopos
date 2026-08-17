import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import { Splash } from './components/Splash'
import { ThemeProvider } from './lib/theme'
import './index.css'

// Splash is a sibling of App, not a wrapper around it. It overlays the real
// application while that application mounts, fetches and renders underneath —
// so the startup animation cannot delay, gate or break anything below it, and
// what it reveals at the end is the actual dashboard rather than a stand-in.
// It needs the theme, so it sits inside ThemeProvider.
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ThemeProvider>
      <App />
      <Splash />
    </ThemeProvider>
  </StrictMode>,
)
