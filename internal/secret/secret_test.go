package secret

import "testing"

type memKV struct{ m map[string]string }

func (k *memKV) GetMeta(key string) (string, bool, error) {
	v, ok := k.m[key]
	return v, ok, nil
}
func (k *memKV) SetMeta(key, value string) error {
	k.m[key] = value
	return nil
}

func TestSealOpenRoundTrip(t *testing.T) {
	kv := &memKV{m: map[string]string{}}
	box, err := FromStore(kv)
	if err != nil {
		t.Fatal(err)
	}

	secret := []byte("cf_token_abc123")
	sealed, err := box.Seal(secret)
	if err != nil {
		t.Fatal(err)
	}
	if sealed == string(secret) {
		t.Fatal("sealed value equals plaintext — not encrypted")
	}

	// A second box built from the same store (same persisted key) opens it.
	box2, err := FromStore(kv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := box2.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(secret) {
		t.Errorf("round-trip = %q, want %q", got, secret)
	}
}

func TestOpenRejectsGarbageAndWrongKey(t *testing.T) {
	kv := &memKV{m: map[string]string{}}
	box, _ := FromStore(kv)
	if _, err := box.Open("not-base64!!"); err == nil {
		t.Error("garbage should not open")
	}
	if _, err := box.Open(""); err == nil {
		t.Error("empty should not open")
	}

	sealed, _ := box.Seal([]byte("x"))
	// A box with a different key must not open it.
	other, _ := FromStore(&memKV{m: map[string]string{}})
	if _, err := other.Open(sealed); err == nil {
		t.Error("wrong key should not open")
	}
}
