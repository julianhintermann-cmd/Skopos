package reputation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/secret"
)

type memKV struct{ m map[string]string }

func (k *memKV) GetMeta(key string) (string, bool, error) { v, ok := k.m[key]; return v, ok, nil }
func (k *memKV) SetMeta(key, value string) error          { k.m[key] = value; return nil }

func testService(t *testing.T, h http.Handler) (*Service, *httptest.Server) {
	t.Helper()
	kv := &memKV{m: map[string]string{}}
	box, err := secret.FromStore(kv)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	s := New(kv, box, time.Now)
	s.HTTP = srv.Client()
	s.RDAPBase = srv.URL
	s.AbuseBase = srv.URL
	return s, srv
}

func rdapAbuseMux(rdapCalls, abuseCalls *int) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ip/", func(w http.ResponseWriter, r *http.Request) {
		*rdapCalls++
		_, _ = w.Write([]byte(`{"name":"EXAMPLE-NET","handle":"EX-1","country":"DE"}`))
	})
	mux.HandleFunc("/api/v2/check", func(w http.ResponseWriter, r *http.Request) {
		*abuseCalls++
		if r.Header.Get("Key") != "good-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"abuseConfidenceScore":87,"totalReports":42,"isp":"Evil ISP","usageType":"Data Center","countryCode":"DE"}}`))
	})
	return mux
}

func TestLookupRDAPOnlyAndCaches(t *testing.T) {
	var rdap, abuse int
	s, _ := testService(t, rdapAbuseMux(&rdap, &abuse))

	info, err := s.Lookup(context.Background(), netip.MustParseAddr("203.0.113.5"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Org != "EXAMPLE-NET" || info.Country != "DE" || info.AbuseScore != nil {
		t.Errorf("info = %+v", info)
	}
	// Second lookup is served from cache.
	if _, err := s.Lookup(context.Background(), netip.MustParseAddr("203.0.113.5")); err != nil {
		t.Fatal(err)
	}
	if rdap != 1 || abuse != 0 {
		t.Errorf("calls rdap=%d abuse=%d, want 1/0", rdap, abuse)
	}
}

func TestAbuseKeyLifecycleAndScores(t *testing.T) {
	var rdap, abuse int
	s, _ := testService(t, rdapAbuseMux(&rdap, &abuse))
	ctx := context.Background()

	if s.HasAbuseKey() {
		t.Fatal("should start without a key")
	}
	if err := s.SetAbuseKey(ctx, "bad-key"); err == nil {
		t.Fatal("a rejected key must not be stored")
	}
	if err := s.SetAbuseKey(ctx, "good-key"); err != nil {
		t.Fatal(err)
	}
	if !s.HasAbuseKey() {
		t.Fatal("key should be stored")
	}

	info, err := s.Lookup(ctx, netip.MustParseAddr("198.51.100.9"))
	if err != nil {
		t.Fatal(err)
	}
	if info.AbuseScore == nil || *info.AbuseScore != 87 || info.ISP != "Evil ISP" {
		t.Errorf("info = %+v, want abuse fields", info)
	}

	if err := s.DeleteAbuseKey(); err != nil {
		t.Fatal(err)
	}
	if s.HasAbuseKey() {
		t.Error("key should be gone")
	}
}
