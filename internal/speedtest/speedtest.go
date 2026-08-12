// Package speedtest measures the internet connection against Cloudflare's
// speed endpoints (speed.cloudflare.com) — plain HTTPS transfers, no external
// binary, no account. Measurements are deliberately short: enough bytes for a
// stable estimate, small enough not to distort a metered or busy line.
package speedtest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

const (
	defaultBase   = "https://speed.cloudflare.com"
	downloadBytes = 25 << 20 // 25 MiB
	uploadBytes   = 8 << 20  // 8 MiB
	latencyProbes = 5
)

// Runner performs measurements. BaseURL and HTTP are injectable for tests.
type Runner struct {
	HTTP    *http.Client
	BaseURL string
	// Down/Up sizes are fields so tests can use tiny transfers.
	DownloadBytes int64
	UploadBytes   int64
	clock         func() time.Time
}

// New returns a Runner with production settings.
func New(clock func() time.Time) *Runner {
	if clock == nil {
		clock = time.Now
	}
	return &Runner{
		HTTP:          &http.Client{Timeout: 90 * time.Second},
		BaseURL:       defaultBase,
		DownloadBytes: downloadBytes,
		UploadBytes:   uploadBytes,
		clock:         clock,
	}
}

// Run measures latency, download and upload, in that order.
func (r *Runner) Run(ctx context.Context) (model.SpeedtestResult, error) {
	res := model.SpeedtestResult{Time: r.clock()}

	lat, err := r.latency(ctx)
	if err != nil {
		return res, fmt.Errorf("speedtest: latency: %w", err)
	}
	res.LatencyMs = lat

	down, err := r.download(ctx)
	if err != nil {
		return res, fmt.Errorf("speedtest: download: %w", err)
	}
	res.DownMbps = down

	up, err := r.upload(ctx)
	if err != nil {
		return res, fmt.Errorf("speedtest: upload: %w", err)
	}
	res.UpMbps = up
	return res, nil
}

// latency times several tiny downloads and keeps the fastest — the closest
// approximation of pure round-trip time an HTTP probe can give.
func (r *Runner) latency(ctx context.Context) (float64, error) {
	best := -1.0
	for i := 0; i < latencyProbes; i++ {
		start := time.Now()
		if err := r.fetch(ctx, 1); err != nil {
			return 0, err
		}
		ms := float64(time.Since(start).Microseconds()) / 1000
		if best < 0 || ms < best {
			best = ms
		}
	}
	return best, nil
}

func (r *Runner) download(ctx context.Context) (float64, error) {
	start := time.Now()
	if err := r.fetch(ctx, r.DownloadBytes); err != nil {
		return 0, err
	}
	return mbps(r.DownloadBytes, time.Since(start)), nil
}

func (r *Runner) upload(ctx context.Context) (float64, error) {
	payload := bytes.Repeat([]byte{'0'}, int(r.UploadBytes))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.BaseURL+"/__up", bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	start := time.Now()
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("unexpected status %s", resp.Status)
	}
	return mbps(r.UploadBytes, time.Since(start)), nil
}

// fetch downloads n bytes from the __down endpoint and discards them.
func (r *Runner) fetch(ctx context.Context, n int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/__down?bytes=%d", r.BaseURL, n), nil)
	if err != nil {
		return err
	}
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}
	_, err = io.Copy(io.Discard, resp.Body)
	return err
}

func mbps(bytes int64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(bytes) * 8 / d.Seconds() / 1e6
}
