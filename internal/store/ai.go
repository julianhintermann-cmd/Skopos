package store

import "context"

// The AI integration keeps two rows in meta, deliberately apart.
//
// aiKeyKey holds the AES-GCM-sealed provider API key; the plaintext never
// touches disk, the config file, or a response body. aiMetaKey holds the
// non-secret settings beside it in the clear — which provider, which model,
// when the key was last verified — so the settings page can render the current
// state without a round trip to the provider and without ever unsealing
// anything.
//
// Neither goes through the runtime-settings override layer. That layer returns
// its whole effective struct on GET /api/settings and persists overrides as
// plaintext JSON, which is correct for a poll interval and disqualifying for a
// credential.
const (
	aiKeyKey  = "ai_key"
	aiMetaKey = "ai_meta"
)

// AISetKey stores the sealed provider key (opaque ciphertext).
func (s *Store) AISetKey(sealed string) error { return s.SetMeta(aiKeyKey, sealed) }

// AIKey returns the sealed key and whether one is set.
func (s *Store) AIKey() (string, bool, error) { return s.GetMeta(aiKeyKey) }

// AIDeleteKey removes the sealed key.
func (s *Store) AIDeleteKey(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM meta WHERE key = ?`, aiKeyKey)
	return err
}

// AISetMeta stores the non-secret settings blob (JSON).
func (s *Store) AISetMeta(v string) error { return s.SetMeta(aiMetaKey, v) }

// AIMeta returns the non-secret settings blob and whether one is set.
func (s *Store) AIMeta() (string, bool, error) { return s.GetMeta(aiMetaKey) }

// AIDeleteMeta removes the non-secret settings blob.
func (s *Store) AIDeleteMeta(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM meta WHERE key = ?`, aiMetaKey)
	return err
}
