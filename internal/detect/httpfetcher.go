package detect

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPFetcher is the production Fetcher: a plain HTTP GET with an ETag
// conditional request and a hard body-size limit so a hostile or broken feed
// cannot exhaust memory.
type HTTPFetcher struct {
	Client  *http.Client
	MaxSize int64
}

// NewHTTPFetcher returns a Fetcher with sensible timeouts and a 32 MiB cap.
func NewHTTPFetcher() *HTTPFetcher {
	return &HTTPFetcher{
		Client:  &http.Client{Timeout: 30 * time.Second},
		MaxSize: 32 << 20,
	}
}

// Fetch implements Fetcher.
func (h *HTTPFetcher) Fetch(ctx context.Context, url, etag string) (FeedResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return FeedResult{}, err
	}
	req.Header.Set("User-Agent", "skopos-feeds/1")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := h.Client.Do(req)
	if err != nil {
		return FeedResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotModified {
		return FeedResult{NotModified: true, ETag: etag}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return FeedResult{}, fmt.Errorf("unexpected status %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, h.MaxSize))
	if err != nil {
		return FeedResult{}, err
	}
	return FeedResult{Body: body, ETag: resp.Header.Get("ETag")}, nil
}
