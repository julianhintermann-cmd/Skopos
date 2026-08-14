package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/blockwatch"
	"github.com/julianhintermann-cmd/skopos/internal/config"
	"github.com/julianhintermann-cmd/skopos/internal/firewall"
	"github.com/julianhintermann-cmd/skopos/internal/geoip"
	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/notify"
	"github.com/julianhintermann-cmd/skopos/internal/reputation"
	"github.com/julianhintermann-cmd/skopos/internal/store"
	"github.com/julianhintermann-cmd/skopos/internal/updatecheck"
)

// LiveProvider supplies the current live throughput snapshot for the overview
// and stream. The runtime injects the real one; a nil provider yields zeros.
type LiveProvider interface {
	Snapshot() LiveStats
}

// LiveStats is a point-in-time traffic snapshot.
//
// Every measured field is a pointer and omitted when absent. A rate of zero
// and "there is no measurement" used to travel as the same four numbers, so a
// dead capture rendered as a quiet network; the reader must be able to tell
// the two apart from the payload alone.
type LiveStats struct {
	BitsPerSecond    *float64 `json:"bits_per_second,omitempty"`
	PacketsPerSecond *float64 `json:"packets_per_second,omitempty"`
	Sampling         bool     `json:"sampling,omitempty"`
	ObservedPPS      *int     `json:"observed_pps,omitempty"`
	// KeepRate qualifies the rates above: under sampling they count only the
	// packets that survived, so they are a floor and the estimate is
	// floor/keep_rate. It was computed and discarded until now.
	KeepRate *float64 `json:"keep_rate,omitempty"`
	// Capture is the measured state of the capture sources — up, partial,
	// down or starting — decided server-side from the source registry so every
	// surface agrees, and never inferred client-side from silence.
	Capture      string     `json:"capture,omitempty"`
	SourcesUp    *int       `json:"sources_up,omitempty"`
	SourcesTotal *int       `json:"sources_total,omitempty"`
	LastPacketAt *time.Time `json:"last_packet_at,omitempty"` // absent = none since start
	MeasuredAt   *time.Time `json:"measured_at,omitempty"`
}

// Deps are the server's dependencies.
type Deps struct {
	Store    *store.Store
	Firewall *firewall.Service
	Notifier *notify.Dispatcher
	Config   *config.Config
	// ConfigInfo says where the configuration came from: the path tried,
	// whether it was there, and which keys in it are inert. A mistyped mount
	// is otherwise invisible from the dashboard.
	ConfigInfo config.LoadInfo
	Live       LiveProvider
	LiveFlows  LiveFlowProvider
	Cloudflare CloudflareService
	Clock      func() time.Time
	// WakeFunc sends a Wake-on-LAN magic packet for a MAC. Defaults to
	// wol.Wake; injectable so tests never touch the network.
	WakeFunc func(mac string) error
	// Speedtest runs one measurement and persists it (nil disables the
	// endpoint). The runtime injects the real runner or the demo fake.
	Speedtest func(ctx context.Context) (model.SpeedtestResult, error)
	// GeoIP resolves addresses to countries (nil or unavailable → the country
	// view reports itself as not ready).
	GeoIP geoip.Provider
	// Countries is the operator's blocked-country list.
	Countries *geoip.Blocklist
	// Reputation answers who an external address belongs to.
	Reputation *reputation.Service
	// ReloadMutes re-reads the suppression rules into the policy engine after
	// an edit. Nil-safe.
	ReloadMutes func()
	// ApplyDevicePolicies pushes per-device rules to the kernel right after
	// an edit, instead of waiting for the periodic sync. Nil-safe.
	//
	// It returns an error because the kernel can refuse: a device policy is
	// stored and then programmed, and those are two outcomes. Without the
	// return the endpoint answered success for a quarantine the kernel never
	// took — the device shows as restricted and reaches the internet anyway,
	// which is the failure mode with the largest gap between what the page
	// says and what is true.
	ApplyDevicePolicies func() error
	// Settings owns the runtime-editable configuration subset (nil disables
	// the settings endpoints).
	Settings SettingsManager
	// Updates reports whether a newer release exists (nil disables the
	// endpoint's answer).
	Updates func() updatecheck.Status
	// PolicyDropped reports findings the policy worker discarded because its
	// queue was full — the price of never blocking packet capture.
	PolicyDropped func() uint64
	// BlockStats returns per-block packet tallies observed since start; the
	// capture tap sees blocked packets before netfilter drops them, so these
	// are the drops (enforce) or would-be drops (observe). Nil-safe.
	BlockStats func() map[string]blockwatch.Stat
	// CountryBlockStats returns per-country preventive prefix counts and
	// whether they are loaded. Nil-safe.
	CountryBlockStats func() (map[string]int, bool)
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
	// trustedProxies are the peers whose X-Forwarded-For is believed. Empty
	// means nobody's, which is the default and the right answer for a NAS a
	// browser reaches directly.
	trustedProxies []netip.Prefix
}

const sessionCookie = "skopos_session"

// New builds a Server. It loads or creates the session signing key and indexes
// the configured API tokens.
func New(deps Deps) (*Server, error) {
	clock := deps.Clock
	if clock == nil {
		clock = time.Now
	}
	// Configuration is checked before anything is opened: a bad value should
	// cost nothing to find, and reporting it only after the database is touched
	// buries it behind unrelated failures.
	//
	// A malformed entry is refused rather than skipped. Dropping it silently
	// would leave an operator believing their proxy is trusted when it is not,
	// and the symptom — every client looking alike to the rate limiter — is the
	// sort of thing nobody notices until it locks out the household.
	var proxies []netip.Prefix
	for _, raw := range deps.Config.Server.TrustedProxies {
		p, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("server.trusted_proxies: %q is not a CIDR range: %w", raw, err)
		}
		proxies = append(proxies, p.Masked())
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

		trustedProxies: proxies,
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
	// Notification buttons. The signed, single-purpose token in the path is
	// the credential; see actions.go.
	s.mux.HandleFunc("GET /api/actions/{token}", s.handleAction)

	// Read endpoints.
	s.mux.Handle("GET /api/stream", s.requireRead(http.HandlerFunc(s.handleStream)))
	s.mux.Handle("GET /api/overview", s.requireRead(http.HandlerFunc(s.handleOverview)))
	s.mux.Handle("GET /api/flows", s.requireRead(http.HandlerFunc(s.handleFlows)))
	s.mux.Handle("GET /api/live/flows", s.requireRead(http.HandlerFunc(s.handleLiveFlows)))
	s.mux.Handle("GET /api/devices", s.requireRead(http.HandlerFunc(s.handleDevices)))
	s.mux.Handle("GET /api/devices/{mac}/detail", s.requireRead(http.HandlerFunc(s.handleDeviceDetail)))
	s.mux.Handle("GET /api/alerts", s.requireRead(http.HandlerFunc(s.handleAlerts)))
	s.mux.Handle("GET /api/blocks", s.requireRead(http.HandlerFunc(s.handleListBlocks)))
	s.mux.Handle("GET /api/firewall/kernel", s.requireRead(http.HandlerFunc(s.handleKernelDump)))
	s.mux.Handle("GET /api/config", s.requireRead(http.HandlerFunc(s.handleConfig)))
	s.mux.Handle("GET /api/rules", s.requireRead(http.HandlerFunc(s.handleRules)))
	s.mux.Handle("GET /api/audit", s.requireRead(http.HandlerFunc(s.handleAudit)))
	s.mux.Handle("GET /api/me", s.requireRead(http.HandlerFunc(s.handleMe)))
	s.mux.Handle("GET /api/auth/totp", s.requireRead(http.HandlerFunc(s.handleTOTPStatus)))
	s.mux.Handle("GET /api/integrations/cloudflare", s.requireRead(http.HandlerFunc(s.handleCFStatus)))
	s.mux.Handle("GET /api/integrations/cloudflare/analytics", s.requireRead(http.HandlerFunc(s.handleCFAnalytics)))
	s.mux.Handle("GET /api/export/flows.csv", s.requireRead(http.HandlerFunc(s.handleExportFlows)))
	s.mux.Handle("GET /api/export/devices.csv", s.requireRead(http.HandlerFunc(s.handleExportDevices)))
	s.mux.Handle("GET /api/export/alerts.csv", s.requireRead(http.HandlerFunc(s.handleExportAlerts)))
	s.mux.Handle("GET /api/speedtest", s.requireRead(http.HandlerFunc(s.handleSpeedtestHistory)))
	s.mux.Handle("GET /api/geoip/summary", s.requireRead(http.HandlerFunc(s.handleGeoIPSummary)))
	s.mux.Handle("GET /api/reputation", s.requireRead(http.HandlerFunc(s.handleReputation)))
	s.mux.Handle("GET /metrics", s.requireRead(http.HandlerFunc(s.handleMetrics)))
	s.mux.Handle("GET /api/updates", s.requireRead(http.HandlerFunc(s.handleUpdates)))
	s.mux.Handle("GET /api/domains", s.requireRead(http.HandlerFunc(s.handleDomains)))
	s.mux.Handle("GET /api/search", s.requireRead(http.HandlerFunc(s.handleSearch)))
	s.mux.Handle("GET /api/settings", s.requireRead(http.HandlerFunc(s.handleGetSettings)))
	s.mux.Handle("GET /api/incidents", s.requireRead(http.HandlerFunc(s.handleIncidents)))
	s.mux.Handle("GET /api/incidents/{id}", s.requireRead(http.HandlerFunc(s.handleIncident)))
	s.mux.Handle("GET /api/mutes", s.requireRead(http.HandlerFunc(s.handleListMutes)))

	// Write endpoints.
	s.mux.Handle("POST /api/devices/{mac}/label", s.requireWrite(http.HandlerFunc(s.handleSetDeviceLabel)))
	s.mux.Handle("POST /api/devices/{mac}/wake", s.requireWrite(http.HandlerFunc(s.handleWakeDevice)))
	s.mux.Handle("POST /api/devices/{mac}/policy", s.requireWrite(http.HandlerFunc(s.handleSetDevicePolicy)))
	s.mux.Handle("POST /api/devices/{mac}/presence", s.requireWrite(http.HandlerFunc(s.handleSetDevicePresence)))
	s.mux.Handle("POST /api/devices/forget", s.requireWrite(http.HandlerFunc(s.handleForgetDevices)))
	s.mux.Handle("POST /api/speedtest/run", s.requireWrite(http.HandlerFunc(s.handleSpeedtestRun)))
	s.mux.Handle("POST /api/geoip/blocked", s.requireWrite(http.HandlerFunc(s.handleSetBlockedCountries)))
	s.mux.Handle("POST /api/auth/totp/setup", s.requireWrite(http.HandlerFunc(s.handleTOTPSetup)))
	s.mux.Handle("POST /api/auth/totp/enable", s.requireWrite(http.HandlerFunc(s.handleTOTPEnable)))
	s.mux.Handle("POST /api/auth/totp/disable", s.requireWrite(http.HandlerFunc(s.handleTOTPDisable)))
	s.mux.Handle("POST /api/alerts/{id}/ack", s.requireWrite(http.HandlerFunc(s.handleAckAlert)))
	s.mux.Handle("POST /api/blocks", s.requireWrite(http.HandlerFunc(s.handleAddBlock)))
	s.mux.Handle("DELETE /api/blocks", s.requireWrite(http.HandlerFunc(s.handleDeleteBlock)))
	s.mux.Handle("POST /api/incidents/{id}/ack", s.requireWrite(http.HandlerFunc(s.handleAckIncident)))
	s.mux.Handle("POST /api/mutes", s.requireWrite(http.HandlerFunc(s.handleAddMute)))
	s.mux.Handle("DELETE /api/mutes/{id}", s.requireWrite(http.HandlerFunc(s.handleDeleteMute)))
	s.mux.Handle("POST /api/settings", s.requireWrite(http.HandlerFunc(s.handleUpdateSettings)))
	s.mux.Handle("DELETE /api/settings", s.requireWrite(http.HandlerFunc(s.handleResetSettings)))
	s.mux.Handle("POST /api/config/validate", s.requireWrite(http.HandlerFunc(s.handleValidateConfig)))
	s.mux.Handle("POST /api/notify/test", s.requireWrite(http.HandlerFunc(s.handleNotifyTest)))
	s.mux.Handle("POST /api/integrations/cloudflare", s.requireWrite(http.HandlerFunc(s.handleCFConnect)))
	s.mux.Handle("DELETE /api/integrations/cloudflare", s.requireWrite(http.HandlerFunc(s.handleCFDisconnect)))
	s.mux.Handle("POST /api/integrations/cloudflare/zones/{id}", s.requireWrite(http.HandlerFunc(s.handleCFSetZone)))

	// API docs.
	s.mux.HandleFunc("GET /api/openapi.yaml", s.handleOpenAPISpec)
	s.mux.HandleFunc("GET /api/docs", s.handleDocs)

	// Everything else: the embedded dashboard (with SPA fallback).
	s.mux.Handle("/", s.uiHandler())
}

// clientIP extracts a stable client identifier for rate limiting.
//
// X-Forwarded-For is only read when the connection itself came from a
// configured proxy. It used to be read unconditionally, which quietly undid the
// login rate limiter it feeds: the limiter counts failed attempts per client,
// and a header anyone can set means an attacker is a new client on every
// request, so the count never reaches the threshold. Whoever peers with us is
// the one fact about a request that cannot be forged, and it is the fact that
// decides here.
func (s *Server) clientIP(r *http.Request) string {
	peer := peerIP(r.RemoteAddr)
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" && s.trusted(peer) {
		if i := strings.IndexByte(fwd, ','); i >= 0 {
			return strings.TrimSpace(fwd[:i])
		}
		return strings.TrimSpace(fwd)
	}
	return peer
}

// peerIP is the address the connection actually came from.
func peerIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// trusted reports whether a peer may speak for someone else.
func (s *Server) trusted(peer string) bool {
	if len(s.trustedProxies) == 0 {
		return false
	}
	addr, err := netip.ParseAddr(peer)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range s.trustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
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
