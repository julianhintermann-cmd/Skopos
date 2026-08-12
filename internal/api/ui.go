package api

import (
	"io/fs"
	"net/http"
	"strings"
)

// uiFS holds the embedded dashboard build. It is set by RegisterUI from the
// package that owns the go:embed directive (so this package has no build-time
// dependency on the web/dist directory existing).
var uiFS fs.FS

// RegisterUI installs the embedded dashboard filesystem. Call once at startup
// with an fs.FS rooted at the built assets.
func RegisterUI(f fs.FS) { uiFS = f }

// uiHandler serves the embedded single-page app: static assets by path, with a
// fallback to index.html for client-side routes. When no UI is embedded (e.g.
// a backend-only dev build) it serves a small placeholder.
func (s *Server) uiHandler() http.Handler {
	if uiFS == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(placeholderHTML))
		})
	}

	fileServer := http.FileServer(http.FS(uiFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Never let SPA fallback swallow API 404s.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		// Serve the asset if it exists; otherwise fall back to index.html so
		// deep links into the SPA work on reload.
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if _, err := fs.Stat(uiFS, path); err != nil {
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			serveIndex(w, r2)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(uiFS, "index.html")
	if err != nil {
		http.Error(w, "index not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

const placeholderHTML = `<!doctype html><html><head><meta charset="utf-8">` +
	`<title>Skopos</title></head><body style="font-family:system-ui;background:#0c1211;color:#dde8e4;` +
	`display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0">` +
	`<div style="text-align:center"><h1 style="letter-spacing:.3em;text-transform:uppercase;font-size:1rem">Skopos</h1>` +
	`<p style="color:#8ba39b">API is running. The dashboard build is not embedded in this binary.</p>` +
	`<p style="color:#8ba39b">Try <code>GET /api/health</code> or <code>/api/docs</code>.</p></div></body></html>`
