package geoip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

type memKV struct{ m map[string]string }

func (k *memKV) GetMeta(key string) (string, bool, error) { v, ok := k.m[key]; return v, ok, nil }
func (k *memKV) SetMeta(key, value string) error          { k.m[key] = value; return nil }

func TestBlocklistPersistsAndValidates(t *testing.T) {
	kv := &memKV{m: map[string]string{}}
	b, err := NewBlocklist(kv)
	if err != nil {
		t.Fatal(err)
	}
	if !b.Empty() {
		t.Fatal("fresh blocklist should be empty")
	}
	if err := b.Set([]string{"ru", " CN ", ""}); err != nil {
		t.Fatal(err)
	}
	if !b.Contains("RU") || !b.Contains("CN") || b.Contains("US") {
		t.Errorf("contains wrong: %v", b.Countries())
	}
	if got := b.Countries(); len(got) != 2 || got[0] != "CN" {
		t.Errorf("countries = %v, want sorted [CN RU]", got)
	}
	// Garbage is rejected before anything is persisted.
	if err := b.Set([]string{"USA"}); err == nil {
		t.Error("three-letter code should be rejected")
	}
	// A second instance sees the persisted list.
	b2, err := NewBlocklist(kv)
	if err != nil {
		t.Fatal(err)
	}
	if !b2.Contains("RU") {
		t.Error("persisted list not loaded")
	}
}

func TestDemoProviderCoversDemoTraffic(t *testing.T) {
	d := NewDemoProvider()
	if !d.Available() {
		t.Fatal("demo provider must always be available")
	}
	for ip, want := range map[string]string{
		"9.9.9.9":        "CH",
		"1.1.1.1":        "US",
		"91.209.108.172": "RU",
		"82.13.29.40":    "GB",
	} {
		got, ok := d.Lookup(netip.MustParseAddr(ip))
		if !ok || got != want {
			t.Errorf("Lookup(%s) = %q/%v, want %s", ip, got, ok, want)
		}
	}
	if _, ok := d.Lookup(netip.MustParseAddr("203.0.113.7")); ok {
		t.Error("unknown ranges must miss, not guess")
	}
}

func TestManagerRejectsInvalidDownload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// gzip of garbage — valid gzip, not a valid mmdb.
		_, _ = w.Write([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0, 0x2b, 0x4a, 0x4c, 0x4a, 0x02, 0x00, 0xf9, 0xef, 0xbe, 0x71, 0x04, 0x00, 0x00, 0x00})
	}))
	defer srv.Close()

	m := NewManager(t.TempDir(), time.Now)
	m.HTTP = srv.Client()
	m.URLTemplate = srv.URL + "/%s.mmdb.gz"
	if err := m.refresh(context.Background()); err == nil {
		t.Error("an invalid mmdb must be rejected")
	}
	if m.Available() {
		t.Error("manager must stay unavailable after a rejected download")
	}
}
