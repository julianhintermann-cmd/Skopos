// Package cloudflare connects Skopos to the Cloudflare API so an operator can
// monitor request traffic for their own domains alongside their LAN. It uses a
// scoped API token (entered in the UI, sealed at rest) rather than OAuth:
// Cloudflare offers no public OAuth for self-hosted third-party apps, and a
// read-only token the operator can revoke at any time is both sufficient and
// safer for a self-hosted tool.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	defaultBaseURL    = "https://api.cloudflare.com/client/v4"
	defaultGraphQLURL = "https://api.cloudflare.com/client/v4/graphql"
	maxBody           = 8 << 20
)

// Client talks to the Cloudflare REST and GraphQL Analytics APIs. BaseURL and
// GraphQLURL are fields so tests can point them at an httptest server; HTTP is
// injectable for the same reason.
type Client struct {
	HTTP       *http.Client
	BaseURL    string
	GraphQLURL string
}

// NewClient returns a Client with production endpoints and a bounded timeout.
func NewClient() *Client {
	return &Client{
		HTTP:       &http.Client{Timeout: 20 * time.Second},
		BaseURL:    defaultBaseURL,
		GraphQLURL: defaultGraphQLURL,
	}
}

// Zone is a Cloudflare zone (a domain) the token can see.
type Zone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// TokenStatus is the result of verifying an API token.
type TokenStatus struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	ExpiresOn string `json:"expires_on"`
}

// Active reports whether the token is currently usable.
func (t TokenStatus) Active() bool { return t.Status == "active" }

// AnalyticsPoint is one time bucket of zone request traffic.
type AnalyticsPoint struct {
	Time           time.Time `json:"time"`
	Requests       uint64    `json:"requests"`
	Bytes          uint64    `json:"bytes"`
	CachedRequests uint64    `json:"cached_requests"`
	CachedBytes    uint64    `json:"cached_bytes"`
	Threats        uint64    `json:"threats"`
}

// AnalyticsSeries is a zone's request traffic over a window.
type AnalyticsSeries struct {
	ZoneID string           `json:"zone_id"`
	Since  time.Time        `json:"since"`
	Until  time.Time        `json:"until"`
	Points []AnalyticsPoint `json:"points"`
}

// apiError carries Cloudflare's structured error array.
type apiError struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

func (e apiError) err() error {
	if len(e.Errors) == 0 {
		return fmt.Errorf("cloudflare: request failed")
	}
	msgs := make([]string, 0, len(e.Errors))
	for _, x := range e.Errors {
		msgs = append(msgs, x.Message)
	}
	return fmt.Errorf("cloudflare: %s", strings.Join(msgs, "; "))
}

// VerifyToken checks that the token is valid and active.
func (c *Client) VerifyToken(ctx context.Context, token string) (TokenStatus, error) {
	var out struct {
		apiError
		Result TokenStatus `json:"result"`
	}
	if err := c.getJSON(ctx, token, "/user/tokens/verify", &out); err != nil {
		return TokenStatus{}, err
	}
	if !out.Success {
		return TokenStatus{}, out.err()
	}
	return out.Result, nil
}

// ListZones returns every zone the token can read, following pagination.
func (c *Client) ListZones(ctx context.Context, token string) ([]Zone, error) {
	var zones []Zone
	for page := 1; page <= 50; page++ {
		var out struct {
			apiError
			Result     []Zone `json:"result"`
			ResultInfo struct {
				Page       int `json:"page"`
				TotalPages int `json:"total_pages"`
			} `json:"result_info"`
		}
		path := fmt.Sprintf("/zones?per_page=50&page=%d", page)
		if err := c.getJSON(ctx, token, path, &out); err != nil {
			return nil, err
		}
		if !out.Success {
			return nil, out.err()
		}
		zones = append(zones, out.Result...)
		if out.ResultInfo.TotalPages <= page {
			break
		}
	}
	return zones, nil
}

// Analytics fetches per-hour request traffic for a zone between since and until.
func (c *Client) Analytics(ctx context.Context, token, zoneID string, since, until time.Time) (AnalyticsSeries, error) {
	const query = `query($zoneTag: String!, $since: Time!, $until: Time!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      httpRequests1hGroups(limit: 720, filter: {datetime_geq: $since, datetime_lt: $until}, orderBy: [datetime_ASC]) {
        dimensions { datetime }
        sum { requests bytes cachedRequests cachedBytes threats }
      }
    }
  }
}`
	body, _ := json.Marshal(map[string]any{
		"query": query,
		"variables": map[string]any{
			"zoneTag": zoneID,
			"since":   since.UTC().Format(time.RFC3339),
			"until":   until.UTC().Format(time.RFC3339),
		},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.GraphQLURL, bytes.NewReader(body))
	if err != nil {
		return AnalyticsSeries{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	raw, err := c.do(req)
	if err != nil {
		return AnalyticsSeries{}, err
	}

	var gql struct {
		Data struct {
			Viewer struct {
				Zones []struct {
					Groups []struct {
						Dimensions struct {
							Datetime string `json:"datetime"`
						} `json:"dimensions"`
						Sum struct {
							Requests       uint64 `json:"requests"`
							Bytes          uint64 `json:"bytes"`
							CachedRequests uint64 `json:"cachedRequests"`
							CachedBytes    uint64 `json:"cachedBytes"`
							Threats        uint64 `json:"threats"`
						} `json:"sum"`
					} `json:"httpRequests1hGroups"`
				} `json:"zones"`
			} `json:"viewer"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &gql); err != nil {
		return AnalyticsSeries{}, fmt.Errorf("cloudflare: decoding analytics: %w", err)
	}
	if len(gql.Errors) > 0 {
		return AnalyticsSeries{}, fmt.Errorf("cloudflare: %s", gql.Errors[0].Message)
	}

	series := AnalyticsSeries{ZoneID: zoneID, Since: since.UTC(), Until: until.UTC()}
	if len(gql.Data.Viewer.Zones) > 0 {
		for _, g := range gql.Data.Viewer.Zones[0].Groups {
			ts, _ := time.Parse(time.RFC3339, g.Dimensions.Datetime)
			series.Points = append(series.Points, AnalyticsPoint{
				Time:           ts,
				Requests:       g.Sum.Requests,
				Bytes:          g.Sum.Bytes,
				CachedRequests: g.Sum.CachedRequests,
				CachedBytes:    g.Sum.CachedBytes,
				Threats:        g.Sum.Threats,
			})
		}
	}
	return series, nil
}

// getJSON performs an authenticated GET and decodes the JSON body into v.
func (c *Client) getJSON(ctx context.Context, token, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	raw, err := c.do(req)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// do sends the request and returns a size-limited body, mapping transport-level
// auth failures to a clear error.
func (c *Client) do(req *http.Request) ([]byte, error) {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("cloudflare: token rejected (%s)", resp.Status)
	}
	return raw, nil
}
