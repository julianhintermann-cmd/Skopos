package speedtest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func testRunner(t *testing.T) (*Runner, *httptest.Server) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/__down", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("bytes"))
		_, _ = w.Write(make([]byte, n))
	})
	mux.HandleFunc("/__up", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(200)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	r := New(time.Now)
	r.HTTP = srv.Client()
	r.BaseURL = srv.URL
	r.DownloadBytes = 64 << 10
	r.UploadBytes = 64 << 10
	return r, srv
}

func TestRunMeasuresAllThree(t *testing.T) {
	r, _ := testRunner(t)
	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.DownMbps <= 0 || res.UpMbps <= 0 || res.LatencyMs <= 0 {
		t.Errorf("result = %+v, want positive figures", res)
	}
	if res.Time.IsZero() {
		t.Error("result must be timestamped")
	}
}

func TestRunSurfacesServerErrors(t *testing.T) {
	r, _ := testRunner(t)
	r.BaseURL += "/missing"
	if _, err := r.Run(context.Background()); err == nil {
		t.Error("404 endpoints should error")
	}
}

func TestMbps(t *testing.T) {
	// 1 MB in 1 second = 8 Mbps.
	if got := mbps(1_000_000, time.Second); got < 7.9 || got > 8.1 {
		t.Errorf("mbps = %f, want ~8", got)
	}
}
