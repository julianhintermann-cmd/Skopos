// Captures dashboard screenshots from a running demo instance, in both light
// and dark themes. Reproducible from the demo mode, so screenshots never go
// stale. Usage: node screenshots.mjs <baseURL> <outDir>
import { chromium } from 'playwright'
import { mkdirSync } from 'node:fs'

const base = process.argv[2] || 'http://localhost:18787'
const outDir = process.argv[3] || '../docs/screenshots'
mkdirSync(outDir, { recursive: true })

const views = [
  { path: '/', name: 'overview' },
  { path: '/traffic', name: 'traffic' },
  { path: '/devices', name: 'devices' },
  { path: '/firewall', name: 'firewall' },
  { path: '/alerts', name: 'alerts' },
  { path: '/system', name: 'system' },
]

const executablePath = '/opt/pw-browsers/chromium-1194/chrome-linux/chrome'

const browser = await chromium.launch({
  executablePath,
  args: ['--no-sandbox', '--disable-dev-shm-usage'],
})

for (const theme of ['dark', 'light']) {
  const ctx = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 2,
    colorScheme: theme,
  })
  const page = await ctx.newPage()
  // Seed the theme choice so the app renders the intended appearance.
  await page.addInitScript((t) => localStorage.setItem('skopos-theme', t), theme)

  for (const v of views) {
    await page.goto(base + v.path, { waitUntil: 'networkidle' })
    await page.waitForTimeout(1200)
    const suffix = theme === 'dark' ? '' : '-light'
    await page.screenshot({ path: `${outDir}/${v.name}${suffix}.png` })
    console.log(`captured ${v.name} (${theme})`)
  }
  await ctx.close()
}

await browser.close()
console.log('done')
