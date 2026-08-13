package updatecheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"0.3.0", "0.2.2", true},
		{"0.2.3", "0.2.2", true},
		{"1.0.0", "0.9.9", true},
		{"0.2.2", "0.2.2", false},
		{"0.2.1", "0.2.2", false},
		{"0.2.10", "0.2.9", true},
		// A local build is ahead of the release line, never behind.
		{"9.9.9", "dev", false},
		{"", "0.2.2", false},
		{"v0.3.0", "v0.2.2", true},
		// Pre-release suffixes compare on the numeric core.
		{"0.3.0-rc1", "0.2.2", true},
	}
	for _, c := range cases {
		if got := newer(c.latest, c.current); got != c.want {
			t.Errorf("newer(%q, %q) = %v, want %v", c.latest, c.current, got, c.want)
		}
	}
}

func TestCheckReportsUpdate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v0.3.0","html_url":"https://example.test/r/0.3.0"}`))
	}))
	defer srv.Close()

	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	c := New("0.2.2", func() time.Time { return now })
	c.URL = srv.URL

	st := c.check(context.Background())
	if !st.Checked || !st.UpdateAvailable {
		t.Fatalf("status = %+v, want checked with update", st)
	}
	if st.Latest != "0.3.0" || st.URL != "https://example.test/r/0.3.0" {
		t.Errorf("latest = %q url = %q", st.Latest, st.URL)
	}
	if st.LastCheck == nil || !st.LastCheck.Equal(now) {
		t.Errorf("last check = %v, want %v", st.LastCheck, now)
	}
	if st.Error != "" {
		t.Errorf("unexpected error %q", st.Error)
	}
}

func TestCheckUpToDateAndFailures(t *testing.T) {
	same := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v0.2.2","html_url":"u"}`))
	}))
	defer same.Close()
	c := New("0.2.2", nil)
	c.URL = same.URL
	if st := c.check(context.Background()); !st.Checked || st.UpdateAvailable {
		t.Errorf("same version: status = %+v", st)
	}

	// A failing endpoint records the error and keeps the previous answer's
	// shape, so the UI can say "could not tell" instead of "up to date".
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer broken.Close()
	c.URL = broken.URL
	st := c.check(context.Background())
	if st.Error == "" {
		t.Error("expected an error to be recorded")
	}
	if st.UpdateAvailable {
		t.Error("a failed check must not claim an update")
	}
}

func TestPrereleaseIsIgnored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v0.4.0","prerelease":true}`))
	}))
	defer srv.Close()
	c := New("0.2.2", nil)
	c.URL = srv.URL
	if st := c.check(context.Background()); st.UpdateAvailable || st.Error == "" {
		t.Errorf("prerelease must not count as an update: %+v", st)
	}
}
