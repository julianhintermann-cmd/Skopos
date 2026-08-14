package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

func decodeBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	return out
}

// A query that failed must omit its key, not fill in a zero. "Unacked alerts
// 0" in green was what an unreachable database used to look like on the
// overview: four errors discarded into `_` and four confident numbers.
func TestOverviewOmitsCountsWhenTheStoreIsUnavailable(t *testing.T) {
	srv, st := newTestServer(t, "none")
	if err := st.Close(); err != nil {
		t.Fatalf("closing store: %v", err)
	}

	resp := do(t, srv.Handler(), "GET", "/api/overview", "", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := decodeBody(t, resp)

	for _, key := range []string{"unacked_alerts", "active_blocks", "throughput_1h", "top_talkers"} {
		if v, ok := body[key]; ok {
			t.Errorf("%s = %v is present after a failed query; it must be omitted", key, v)
		}
	}
	missing, ok := body["unavailable"].([]any)
	if !ok || len(missing) != 4 {
		t.Fatalf("unavailable = %v, want the four keys that could not be answered", body["unavailable"])
	}
}

// The overview's series must be dense and self-describing: one point per
// bucket, each saying what its numbers mean, plus the bucket length so the
// chart never has to re-derive it.
func TestOverviewSeriesIsDenseAndStated(t *testing.T) {
	srv, st := newTestServer(t, "none")
	now := time.Unix(1_700_000_000, 0)

	if err := st.WriteCoverage([]model.Coverage{{
		Bucket: now.Add(-2 * time.Minute), SourcesTotal: 1, SourcesUp: 1, SecondsCovered: 60,
	}}); err != nil {
		t.Fatal(err)
	}

	body := decodeBody(t, do(t, srv.Handler(), "GET", "/api/overview", "", nil, nil))
	if got := body["bucket_seconds"]; got != float64(60) {
		t.Errorf("bucket_seconds = %v, want 60", got)
	}
	series, ok := body["throughput_1h"].([]any)
	if !ok || len(series) < 60 {
		t.Fatalf("throughput_1h has %d points, want one per minute of the hour window", len(series))
	}
	var prev time.Time
	for i, raw := range series {
		p := raw.(map[string]any)
		// Dense means consecutive: an omitted bucket is one uPlot draws a
		// straight line across.
		at, err := time.Parse(time.RFC3339, p["time"].(string))
		if err != nil {
			t.Fatalf("point %d has an unparseable time: %v", i, err)
		}
		if i > 0 && !at.Equal(prev.Add(time.Minute)) {
			t.Fatalf("point %d is at %s, one bucket after %s expected — the series has a hole", i, at, prev)
		}
		prev = at

		state, _ := p["state"].(string)
		switch store.PointState(state) {
		case store.StateMeasured, store.StateSampled:
			if p["bytes"] == nil {
				t.Errorf("state %q carries a null byte count", state)
			}
		case store.StateDown, store.StateNoData:
			if p["bytes"] != nil {
				t.Errorf("state %q carries bytes %v; it must be a gap", state, p["bytes"])
			}
		default:
			t.Errorf("point has no state discriminator: %v", p)
		}
	}
	cov, ok := body["coverage"].(map[string]any)
	if !ok {
		t.Fatal("no coverage histogram: a caller cannot say how much of the window was captured")
	}
	if cov["measured"] != float64(1) {
		t.Errorf("coverage = %v, want exactly one measured minute", cov)
	}
}

// A dead capture must not be reported as a zero rate. With no live provider
// wired there is no measurement at all, and every rate field stays absent.
func TestOverviewLiveOmitsRatesWithoutAProvider(t *testing.T) {
	srv, _ := newTestServer(t, "none")
	body := decodeBody(t, do(t, srv.Handler(), "GET", "/api/overview", "", nil, nil))

	live, ok := body["live"].(map[string]any)
	if !ok {
		t.Fatal("no live block")
	}
	for _, key := range []string{"bits_per_second", "packets_per_second", "observed_pps", "keep_rate"} {
		if v, present := live[key]; present {
			t.Errorf("live.%s = %v with no measurement behind it; it must be omitted", key, v)
		}
	}
}
