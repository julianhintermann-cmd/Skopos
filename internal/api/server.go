package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/config"
	"github.com/julianhintermann-cmd/skopos/internal/firewall"
	"github.com/julianhintermann-cmd/skopos/internal/notify"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

// LiveProvider supplies the current live throughput snapshot for the overview
// and stream. The runtime injects the real one; a nil provider yields zeros.
type LiveProvider interface {
	Snapshot() LiveStats
}

// LiveStats is a point-in-time traffic snapshot.
type LiveStats struct {
	BitsPerSecond    float64 `json:"bits_per_second"`
	PacketsPerSecond float64 `json:"packets_per_second"`
	Sampling         bool    `json:"sampling"`
	ObservedPPS      int     `json:"observed_pps"`
}

// Deps are the server's dependencies.
type Deps struct {
	Store     *store.Store
	Firewall  *firewall.Service
	Notifier  *notify.Dispatcher
	Config    *config.Config
	Live      LiveProvider
	LiveFlows LiveFlowProvider
	Clock     func() time.Time
	// Health reports subsystem health for /api/health.
	Health func() Health
}

// Server is the HTTP API and dashboard server.
type Server struct {
	deps    Deps
	mux     *http.ServeMux
	hub     *sseHub
	signer  *sessionSigner
	tokens  *tokenAuth
	limiter *loginLimiter
	authOff bool
	clock   func() time.Time
	log     func(string, ...any)
}

const sessionCookie = "skopos_session"

// New builds a Server. It loads or creates the session signing key and indexes
// the configured API tokens.
func New(deps Deps) (*Server, error) {
	clock := deps.Clock
	if clock == nil {
		clock = time.Now
	}
	signer, err := newSessionSigner(deps.Store, deps.Config.Server.Auth.SessionTTL.Std())
	if err != nil {
		return nil, err
	}
	tokens := newTokenAuth()
	for _, tk := range deps.Config.Server.Tokens {
		tokens.add(tk.Name, tk.Token, Scope(tk.Scope))
	}

	s := &Server{
		deps:    deps,
		mux:     http.NewServeMux(),
		hub:     newSSEHub(),
		signer:  signer,
		tokens:  tokens,
		limiter: newLoginLimiter(),
		authOff: deps.Config.Server.Auth.Mode == "none",
		clock:   clock,
		log:     func(string, ...any) {},
	}
	s.routes()
	return s, nil
}

// SetLogger installs a logging callback.
func (s *Server) SetLogger(f func(string, ...any)) { s.log = f }

// Hub exposes the SSE hub so the runtime can publish live events and alerts.
func (s *Server) Hub() *sseHub { return s.hub }

// Handler returns the root HTTP handler (API plus embedded UI).
func (s *Server) Handler() http.Handler { return s.mux }

// routes registers every endpoint. Read endpoints require any authenticated
// identity; mutating endpoints require write scope.
func (s *Server) routes() {
	// Public endpoints.
	s.mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	s.mux.HandleFunc("GET /api/health", s.handleHealth)

	// Read endpoints.
	s.mux.Handle("GET /api/stream", s.requireRead(http.HandlerFunc(s.handleStream)))
	s.mux.Handle("GET /api/overview", s.requireRead(http.HandlerFunc(s.handleOverview)))
	s.mux.Handle("GET /api/flows", s.requireRead(http.HandlerFunc(s.handleFlows)))
	s.mux.Handle("GET /api/live/flows", s.requireRead(http.HandlerFunc(s.handleLiveFlows)))
	s.mux.Handle("GET /api/devices", s.requireRead(http.HandlerFunc(s.handleDevices)))
	s.mux.Handle("GET /api/alerts", s.requireRead(http.HandlerFunc(s.handleAlerts)))
	s.mux.Handle("GET /api/blocks", s.requireRead(http.HandlerFunc(s.handleListBlocks)))
	s.mux.Handle("GET /api/rules", s.requireRead(http.HandlerFunc(s.handleRules)))
	s.mux.Handle("GET /api/audit", s.requireRead(http.HandlerFunc(s.handleAudit)))
	s.mux.Handle("GET /api/me", s.requireRead(http.HandlerFunc(s.handleMe)))

	// Write endpoints.
	s.mux.Handle("POST /api/devices/{mac}/label", s.requireWrite(http.HandlerFunc(s.handleSetDeviceLabel)))
	s.mux.Handle("POST /api/alerts/{id}/ack", s.requireWrite(http.HandlerFunc(s.handleAckAlert)))
	s.mux.Handle("POST /api/blocks", s.requireWrite(http.HandlerFunc(s.handleAddBlock)))
	s.mux.Handle("DELETE /api/blocks", s.requireWrite(http.HandlerFunc(s.handleDeleteBlock)))
	s.mux.Handle("POST /api/config/validate", s.requireWrite(http.HandlerFunc(s.handleValidateConfig)))
	s.mux.Handle("POST /api/notify/test", s.requireWrite(http.HandlerFunc(s.handleNotifyTest)))

	// API docs.
	s.mux.HandleFunc("GET /api/openapi.yaml", s.handleOpenAPISpec)
	s.mux.HandleFunc("GET /api/docs", s.handleDocs)

	// Everything else: the embedded dashboard (with SPA fallback).
	s.mux.Handle("/", s.uiHandler())
}

// clientIP extracts a stable client identifier for rate limiting.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if i := strings.IndexByte(fwd, ','); i >= 0 {
			return strings.TrimSpace(fwd[:i])
		}
		return strings.TrimSpace(fwd)
	}
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return host
}

// Snapshot is a nil-safe accessor for live stats.
func (s *Server) liveSnapshot() LiveStats {
	if s.deps.Live == nil {
		return LiveStats{}
	}
	return s.deps.Live.Snapshot()
}

// withTimeout derives a short request context for store queries.
func reqCtx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 15*time.Second)
}
