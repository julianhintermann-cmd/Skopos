package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// identity is the authenticated caller attached to a request context.
type identity struct {
	name  string
	scope Scope
}

type ctxKey int

const identityKey ctxKey = 0

func withIdentity(r *http.Request, id identity) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), identityKey, id))
}

func identityFrom(r *http.Request) (identity, bool) {
	id, ok := r.Context().Value(identityKey).(identity)
	return id, ok
}

// authenticate resolves the caller from a session cookie or bearer token. When
// auth is disabled it returns an implicit write identity so a trusted-LAN
// deployment works without login.
func (s *Server) authenticate(r *http.Request) (identity, bool) {
	if s.authOff {
		return identity{name: "anonymous", scope: ScopeWrite}, true
	}
	// Bearer token (automation).
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		if info, ok := s.tokens.check(strings.TrimPrefix(h, "Bearer ")); ok {
			return identity(info), true
		}
		return identity{}, false
	}
	// Session cookie (dashboard).
	if c, err := r.Cookie(sessionCookie); err == nil {
		if user, ok := s.signer.verify(c.Value, s.clock()); ok {
			return identity{name: user, scope: ScopeWrite}, true
		}
	}
	return identity{}, false
}

// requireRead admits any authenticated caller.
func (s *Server) requireRead(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.authenticate(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next.ServeHTTP(w, withIdentity(r, id))
	})
}

// requireWrite admits only callers with write scope.
func (s *Server) requireWrite(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.authenticate(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if id.scope != ScopeWrite {
			writeError(w, http.StatusForbidden, "write scope required")
			return
		}
		next.ServeHTTP(w, withIdentity(r, id))
	})
}

// handleLogin authenticates the admin and issues a session cookie.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.authOff {
		writeError(w, http.StatusBadRequest, "authentication is disabled")
		return
	}
	client := clientIP(r)
	now := s.clock()
	if !s.limiter.allowed(client, now) {
		w.Header().Set("Retry-After", retrySeconds(s.limiter.retryAfter(client, now)))
		writeError(w, http.StatusTooManyRequests, "too many attempts, try again later")
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	auth := s.deps.Config.Server.Auth
	ok, _ := VerifyPassword(req.Password, auth.PasswordHash)
	valid := ok && subtleEqual(req.Username, auth.Username)
	s.limiter.record(client, valid, now)

	if !valid {
		_ = s.deps.Store.Audit(r.Context(), model.AuditEntry{
			Actor: req.Username, Action: "login_failed", Target: client,
		})
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	token := s.signer.issue(auth.Username, now)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
		Expires:  now.Add(s.deps.Config.Server.Auth.SessionTTL.Std()),
	})
	_ = s.deps.Store.Audit(r.Context(), model.AuditEntry{Actor: auth.Username, Action: "login", Target: client})
	writeJSON(w, http.StatusOK, map[string]any{"username": auth.Username})
}

// handleLogout clears the session cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, MaxAge: -1,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleMe reports the current identity and whether auth is enabled.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"username":  id.name,
		"scope":     id.scope,
		"auth":      !s.authOff,
		"enforcing": s.deps.Firewall.Enforcing(),
	})
}

func retrySeconds(d time.Duration) string {
	secs := int(d.Seconds())
	if secs < 1 {
		secs = 1
	}
	return itoa(secs)
}
