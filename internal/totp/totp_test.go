package totp

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// rfcSecret is RFC 6238's test secret ("12345678901234567890") in base32.
var rfcSecret = base32.StdEncoding.WithPadding(base32.NoPadding).
	EncodeToString([]byte("12345678901234567890"))

// TestRFC6238Vectors checks the SHA-1 reference vectors (truncated to the
// 6-digit codes every authenticator app uses).
func TestRFC6238Vectors(t *testing.T) {
	for _, tc := range []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	} {
		got, err := Code(rfcSecret, time.Unix(tc.unix, 0))
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("Code(t=%d) = %s, want %s", tc.unix, got, tc.want)
		}
	}
}

func TestVerifyAcceptsSkew(t *testing.T) {
	now := time.Unix(1111111109, 0)
	code, _ := Code(rfcSecret, now)

	if !Verify(rfcSecret, code, now) {
		t.Error("exact time must verify")
	}
	if !Verify(rfcSecret, code, now.Add(29*time.Second)) {
		t.Error("one step of skew must verify")
	}
	if Verify(rfcSecret, code, now.Add(2*time.Minute)) {
		t.Error("stale codes must fail")
	}
	if Verify(rfcSecret, "000000", now) && code != "000000" {
		t.Error("wrong code must fail")
	}
	if Verify(rfcSecret, "12345", now) {
		t.Error("wrong length must fail")
	}
}

func TestGenerateSecretAndURI(t *testing.T) {
	s, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 32 { // 20 bytes → 32 base32 chars
		t.Errorf("secret length = %d, want 32", len(s))
	}
	uri := URI(s, "admin", "Skopos")
	if !strings.HasPrefix(uri, "otpauth://totp/Skopos:admin?secret="+s) {
		t.Errorf("uri = %s", uri)
	}
}
