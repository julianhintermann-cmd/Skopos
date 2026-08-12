// Package secret seals small operator secrets — like a Cloudflare API token —
// at rest with AES-256-GCM. The key is kept in the store's meta table and
// generated on first use, mirroring the session-signing key: a sealed secret
// survives restarts, but never appears in the config file or on disk in the
// clear, and is never returned to the UI.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// KeyStore is the persistence the box needs for its key. The store's meta table
// satisfies it.
type KeyStore interface {
	GetMeta(key string) (string, bool, error)
	SetMeta(key, value string) error
}

const keyName = "secret_box_key"

// Box seals and opens secrets with an AEAD.
type Box struct{ aead cipher.AEAD }

// NewBox builds a Box from a 32-byte key.
func NewBox(key []byte) (*Box, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// FromStore loads the persisted key, generating and storing one on first use,
// and returns a Box.
func FromStore(ks KeyStore) (*Box, error) {
	key, err := loadOrCreateKey(ks)
	if err != nil {
		return nil, err
	}
	return NewBox(key)
}

func loadOrCreateKey(ks KeyStore) ([]byte, error) {
	if v, ok, err := ks.GetMeta(keyName); err != nil {
		return nil, err
	} else if ok && v != "" {
		return base64.RawStdEncoding.DecodeString(v)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := ks.SetMeta(keyName, base64.RawStdEncoding.EncodeToString(key)); err != nil {
		return nil, err
	}
	return key, nil
}

// Seal encrypts plaintext and returns a base64 string of nonce||ciphertext.
func (b *Box) Seal(plaintext []byte) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := b.aead.Seal(nonce, nonce, plaintext, nil)
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

// Open reverses Seal. It fails if the input is malformed or the key is wrong.
func (b *Box) Open(s string) ([]byte, error) {
	raw, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	ns := b.aead.NonceSize()
	if len(raw) < ns {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	return b.aead.Open(nil, nonce, ct, nil)
}
