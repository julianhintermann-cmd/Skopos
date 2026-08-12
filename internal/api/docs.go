package api

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.yaml
var openAPISpec []byte

func (s *Server) handleOpenAPISpec(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(openAPISpec)
}

// handleDocs serves a self-contained API reference page. It is dependency-free
// and offline-safe (no CDN): it fetches the embedded spec and renders it.
func (s *Server) handleDocs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(docsHTML))
}

const docsHTML = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Skopos API</title>
<style>
:root{color-scheme:light dark}
body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:60rem;margin:0 auto;padding:2rem 1.25rem;line-height:1.6;background:#0c1211;color:#dde8e4}
@media (prefers-color-scheme:light){body{background:#f2f6f5;color:#182220}}
h1{font-size:1.4rem;letter-spacing:-.01em}
a{color:#4cbcae}
pre{overflow:auto;padding:1rem;border-radius:8px;background:#00000022;font-size:.8rem;line-height:1.5}
.k{font-family:ui-monospace,Menlo,monospace}
</style></head><body>
<h1>Skopos API reference</h1>
<p>Machine-readable spec: <a href="/api/openapi.yaml" class="k">/api/openapi.yaml</a> (OpenAPI 3.1).
Paste it into any OpenAPI viewer, or generate a client from it.</p>
<pre id="spec">Loading /api/openapi.yaml …</pre>
<script>
fetch('/api/openapi.yaml').then(r=>r.text()).then(t=>{
  document.getElementById('spec').textContent = t;
}).catch(e=>{document.getElementById('spec').textContent = 'Failed to load spec: '+e});
</script>
</body></html>`
