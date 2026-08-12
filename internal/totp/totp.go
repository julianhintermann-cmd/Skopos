// Package totp implements RFC 6238 time-based one-time passwords (the codes
// Google Authenticator, Aegis and friends generate) with no dependencies:
// HMAC-SHA1, 30-second steps, 6 digits — the parameters every authenticator
// app defaults to.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 mandates HMAC-SHA1; not used for hashing secrets
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	step   = 30 * time.Second
	digits = 6
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret returns a new random secret in the base32 form authenticator
// apps expect (160 bits, per RFC 4226's recommendation).
func GenerateSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return b32.EncodeToString(raw), nil
}

// URI builds the otpauth:// provisioning URI encoded into setup QR codes.
func URI(secret, account, issuer string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d",
		url.PathEscape(issuer), url.PathEscape(account), secret, url.QueryEscape(issuer), digits, int(step.Seconds()))
}

// Code computes the code for a secret at time t.
func Code(secret string, t time.Time) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil {
		return "", fmt.Errorf("totp: invalid secret: %w", err)
	}
	counter := uint64(t.Unix()) / uint64(step.Seconds())

	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff) % 1_000_000
	return fmt.Sprintf("%06d", code), nil
}

// Verify checks a code against the secret, accepting the previous and next
// time step so a slightly skewed phone clock still works.
func Verify(secret, code string, t time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != digits {
		return false
	}
	for _, offset := range []time.Duration{0, -step, step} {
		want, err := Code(secret, t.Add(offset))
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}
