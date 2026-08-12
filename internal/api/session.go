package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// KeyStore persists the session-signing key so login sessions survive a
// restart. The store's meta table satisfies it.
type KeyStore interface {
	GetMeta(key string) (string, bool, error)
	SetMeta(key, value string) error
}

const sessionKeyName = "session_hmac_key"

// sessionSigner issues and verifies stateless, HMAC-signed session tokens.
// A token is "<username>|<expiryUnix>|<sig>"; the signature covers the first
// two fields, so no server-side session table is needed and tokens survive
// restarts as long as the key does.
type sessionSigner struct {
	key []byte
	ttl time.Duration
}

// loadOrCreateKey returns the persisted signing key, generating and storing a
// new one on first run.
func loadOrCreateKey(ks KeyStore) ([]byte, error) {
	if v, ok, err := ks.GetMeta(sessionKeyName); err != nil {
		return nil, err
	} else if ok && v != "" {
		return base64.RawStdEncoding.DecodeString(v)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := ks.SetMeta(sessionKeyName, base64.RawStdEncoding.EncodeToString(key)); err != nil {
		return nil, err
	}
	return key, nil
}

func newSessionSigner(ks KeyStore, ttl time.Duration) (*sessionSigner, error) {
	key, err := loadOrCreateKey(ks)
	if err != nil {
		return nil, err
	}
	if ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}
	return &sessionSigner{key: key, ttl: ttl}, nil
}

// issue creates a signed token for username valid for the configured TTL.
func (s *sessionSigner) issue(username string, now time.Time) string {
	expiry := now.Add(s.ttl).Unix()
	payload := username + "|" + strconv.FormatInt(expiry, 10)
	return payload + "|" + s.sign(payload)
}

// verify checks a token's signature and expiry, returning the username.
func (s *sessionSigner) verify(token string, now time.Time) (string, bool) {
	parts := strings.Split(token, "|")
	if len(parts) != 3 {
		return "", false
	}
	payload := parts[0] + "|" + parts[1]
	if !hmac.Equal([]byte(parts[2]), []byte(s.sign(payload))) {
		return "", false
	}
	expiry, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || now.Unix() >= expiry {
		return "", false
	}
	return parts[0], true
}

func (s *sessionSigner) sign(payload string) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Scope is an API token's permission level.
type Scope string

const (
	ScopeRead  Scope = "read"
	ScopeWrite Scope = "write"
)

// tokenAuth checks bearer tokens against the configured set in constant time.
type tokenAuth struct {
	tokens map[string]tokenInfo
}

type tokenInfo struct {
	name  string
	scope Scope
}

func newTokenAuth() *tokenAuth { return &tokenAuth{tokens: map[string]tokenInfo{}} }

func (t *tokenAuth) add(name, token string, scope Scope) {
	t.tokens[token] = tokenInfo{name: name, scope: scope}
}

// check returns the token's info if the presented value matches one exactly.
// It compares against every configured token in constant time to avoid
// leaking which token (if any) was close.
func (t *tokenAuth) check(presented string) (tokenInfo, bool) {
	var found tokenInfo
	ok := false
	for token, info := range t.tokens {
		if subtle.ConstantTimeCompare([]byte(token), []byte(presented)) == 1 {
			found = info
			ok = true
		}
	}
	return found, ok
}

// loginLimiter throttles failed logins per client with exponential backoff, so
// a password on the LAN cannot be brute-forced cheaply.
type loginLimiter struct {
	attempts map[string]*attemptState
	base     time.Duration
	max      time.Duration
}

type attemptState struct {
	fails     int
	nextAllow time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		attempts: map[string]*attemptState{},
		base:     time.Second,
		max:      5 * time.Minute,
	}
}

// allowed reports whether client may attempt a login now.
func (l *loginLimiter) allowed(client string, now time.Time) bool {
	st := l.attempts[client]
	return st == nil || !now.Before(st.nextAllow)
}

// record updates the limiter after an attempt. A success clears the state; a
// failure grows the backoff.
func (l *loginLimiter) record(client string, success bool, now time.Time) {
	if success {
		delete(l.attempts, client)
		return
	}
	st := l.attempts[client]
	if st == nil {
		st = &attemptState{}
		l.attempts[client] = st
	}
	st.fails++
	backoff := l.base * (1 << min(st.fails-1, 8))
	if backoff > l.max {
		backoff = l.max
	}
	st.nextAllow = now.Add(backoff)
}

// retryAfter returns how long client must wait, or 0.
func (l *loginLimiter) retryAfter(client string, now time.Time) time.Duration {
	st := l.attempts[client]
	if st == nil || now.After(st.nextAllow) {
		return 0
	}
	return st.nextAllow.Sub(now)
}

func (s *sessionSigner) String() string { return fmt.Sprintf("sessionSigner(ttl=%s)", s.ttl) }
