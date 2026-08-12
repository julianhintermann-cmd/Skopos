package api

import (
	"strings"
	"testing"
	"time"
)

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("hash format = %q", hash)
	}
	ok, err := VerifyPassword("correct horse battery staple", hash)
	if err != nil || !ok {
		t.Errorf("correct password should verify: ok=%v err=%v", ok, err)
	}
	ok, _ = VerifyPassword("wrong", hash)
	if ok {
		t.Error("wrong password must not verify")
	}
}

func TestHashesAreSalted(t *testing.T) {
	a, _ := HashPassword("same")
	b, _ := HashPassword("same")
	if a == b {
		t.Error("two hashes of the same password must differ (random salt)")
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "plaintext", "$argon2id$bad", "$md5$x$y$z$w"} {
		if ok, err := VerifyPassword("x", bad); ok || err == nil {
			t.Errorf("garbage hash %q should error, got ok=%v err=%v", bad, ok, err)
		}
	}
}

// memKeyStore is an in-memory KeyStore for session tests.
type memKeyStore struct{ m map[string]string }

func (k *memKeyStore) GetMeta(key string) (string, bool, error) {
	v, ok := k.m[key]
	return v, ok, nil
}
func (k *memKeyStore) SetMeta(key, value string) error {
	if k.m == nil {
		k.m = map[string]string{}
	}
	k.m[key] = value
	return nil
}

func TestSessionIssueAndVerify(t *testing.T) {
	ks := &memKeyStore{}
	s, err := newSessionSigner(ks, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	token := s.issue("admin", now)

	user, ok := s.verify(token, now.Add(time.Minute))
	if !ok || user != "admin" {
		t.Errorf("valid token should verify as admin, got %q ok=%v", user, ok)
	}
}

func TestSessionExpires(t *testing.T) {
	ks := &memKeyStore{}
	s, _ := newSessionSigner(ks, time.Hour)
	now := time.Unix(1_700_000_000, 0)
	token := s.issue("admin", now)

	if _, ok := s.verify(token, now.Add(2*time.Hour)); ok {
		t.Error("expired token must not verify")
	}
}

func TestSessionTamperResistant(t *testing.T) {
	ks := &memKeyStore{}
	s, _ := newSessionSigner(ks, time.Hour)
	now := time.Unix(1_700_000_000, 0)
	token := s.issue("admin", now)

	// Swap the username but keep the old signature.
	parts := strings.SplitN(token, "|", 3)
	forged := "attacker|" + parts[1] + "|" + parts[2]
	if _, ok := s.verify(forged, now); ok {
		t.Error("token with forged username must not verify")
	}
}

func TestSessionKeyPersists(t *testing.T) {
	ks := &memKeyStore{}
	s1, _ := newSessionSigner(ks, time.Hour)
	now := time.Unix(1_700_000_000, 0)
	token := s1.issue("admin", now)

	// A new signer loading the same key store must accept tokens from the old
	// one — this is what lets sessions survive a restart.
	s2, _ := newSessionSigner(ks, time.Hour)
	if _, ok := s2.verify(token, now.Add(time.Minute)); !ok {
		t.Error("session should survive across signer instances sharing a key store")
	}
}

func TestTokenAuth(t *testing.T) {
	ta := newTokenAuth()
	ta.add("homeassistant", "tok_read_123456789012", ScopeRead)
	ta.add("scripts", "tok_write_98765432109", ScopeWrite)

	if info, ok := ta.check("tok_read_123456789012"); !ok || info.scope != ScopeRead {
		t.Errorf("read token = %+v ok=%v", info, ok)
	}
	if info, ok := ta.check("tok_write_98765432109"); !ok || info.scope != ScopeWrite {
		t.Errorf("write token = %+v ok=%v", info, ok)
	}
	if _, ok := ta.check("nope"); ok {
		t.Error("unknown token must not authenticate")
	}
}

func TestLoginLimiterBacksOff(t *testing.T) {
	l := newLoginLimiter()
	now := time.Unix(1000, 0)
	client := "192.168.1.5"

	if !l.allowed(client, now) {
		t.Fatal("first attempt should be allowed")
	}
	// A few failures are tolerated (grace); beyond that, backoff blocks
	// immediate retries.
	for i := 0; i < l.grace+1; i++ {
		l.record(client, false, now)
	}
	if l.allowed(client, now) {
		t.Error("should be blocked after exceeding the grace allowance")
	}
	if l.retryAfter(client, now) <= 0 {
		t.Error("retryAfter should be positive while blocked")
	}
	// A success clears the limiter.
	l.record(client, true, now.Add(time.Hour))
	if !l.allowed(client, now.Add(time.Hour)) {
		t.Error("successful login should clear backoff")
	}
}
