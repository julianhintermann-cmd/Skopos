import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Dev server proxies API calls to a locally running backend
// (e.g. `make run-demo` on :8686). Production builds are embedded
// into the Go binary and served from the same origin.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8686',
        changeOrigin: false,
      },
    },
  },
})
