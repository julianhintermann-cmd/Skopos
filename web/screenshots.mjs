// Captures dashboard screenshots from a running demo instance, in both light
// and dark themes. Reproducible from the demo mode, so screenshots never go
// stale.
//
// Playwright is not a project dependency (it would make every `npm ci` pull a
// browser). Install it on demand first:
//   npm install --no-save playwright
//   node screenshots.mjs <baseURL> <outDir>
// PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 plus a system Chromium works too.
import { chromium } from 'playwright'
import { mkdirSync } from 'node:fs'

const base = process.argv[2] || 'http://localhost:18787'
const outDir = process.argv[3] || '../docs/screenshots'
// Optional: capture only the named view (e.g. `node screenshots.mjs URL DIR cloudflare`).
const only = process.argv[4] || ''
mkdirSync(outDir, { recursive: true })

const views = [
  { path: '/', name: 'overview' },
  { path: '/live', name: 'live', wait: 4500 },
  { path: '/traffic', name: 'traffic' },
  { path: '/devices', name: 'devices' },
  { path: '/firewall', name: 'firewall' },
  { path: '/alerts', name: 'alerts' },
  { path: '/cloudflare', name: 'cloudflare', full: true },
  { path: '/settings', name: 'settings' },
  { path: '/system', name: 'system' },
]

const executablePath = '/opt/pw-browsers/chromium-1194/chrome-linux/chrome'

// The demo has no Cloudflare account, so the /cloudflare shot would only ever
// show the connect screen. Feed the view a deterministic sample instead, so the
// screenshot demonstrates the connected experience. Pure route interception —
// the app code is untouched and the data is clearly synthetic.
async function mockCloudflare(page) {
  await page.route('**/api/integrations/cloudflare', (route) =>
    route.fulfill({
      json: {
        connected: true,
        token_id: 'a1b2c3d4e5f6a7b8',
        expires_on: '',
        zones: [
          { id: 'z1', name: 'example.com', status: 'active', monitored: true },
          { id: 'z2', name: 'blog.example.net', status: 'active', monitored: true },
          { id: 'z3', name: 'staging.example.dev', status: 'active', monitored: false },
        ],
      },
    }),
  )
  await page.route('**/api/integrations/cloudflare/analytics**', (route) => {
    const until = Date.parse('2026-08-12T18:00:00Z')
    const points = Array.from({ length: 24 }, (_, i) => {
      const t = new Date(until - (23 - i) * 3600_000).toISOString()
      const requests = Math.round(520 + 260 * Math.sin((i - 2) / 3.4) + i * 28)
      return {
        time: t,
        requests,
        bytes: requests * 5300,
        cached_requests: Math.round(requests * 0.63),
        cached_bytes: Math.round(requests * 5300 * 0.55),
        threats: i === 15 ? 6 : i === 16 ? 2 : 0,
      }
    })
    route.fulfill({ json: { zone_id: 'z1', since: points[0].time, until: new Date(until).toISOString(), points } })
  })
}

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
  await mockCloudflare(page)

  for (const v of views) {
    if (only && v.name !== only) continue
    await page.goto(base + v.path, { waitUntil: 'networkidle' })
    await page.waitForTimeout(v.wait ?? 1200)
    const suffix = theme === 'dark' ? '' : '-light'
    await page.screenshot({ path: `${outDir}/${v.name}${suffix}.png`, fullPage: v.full ?? false })
    console.log(`captured ${v.name} (${theme})`)
  }
  await ctx.close()
}

await browser.close()
console.log('done')
