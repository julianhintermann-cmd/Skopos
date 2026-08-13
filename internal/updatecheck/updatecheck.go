// Package updatecheck asks GitHub once a day whether a newer Skopos release
// exists. It answers a failure mode that bit this project in practice: a
// moving image tag can quietly stay behind, and nothing in the dashboard
// would say so. Only the public releases endpoint is contacted, no
// identifying data is sent, and the whole thing is off unless enabled.
package updatecheck

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// defaultURL is the public latest-release endpoint (no authentication, no
// telemetry — a plain GET).
const defaultURL = "https://api.github.com/repos/julianhintermann-cmd/skopos/releases/latest"

// Status is what the API reports to the dashboard.
type Status struct {
	// Checked is true once a check has completed successfully.
	Checked bool `json:"checked"`
	// Current is the running version ("dev" for local builds).
	Current string `json:"current"`
	// Latest is the newest published release tag, without the leading "v".
	Latest string `json:"latest,omitempty"`
	// UpdateAvailable is true when Latest is newer than Current.
	UpdateAvailable bool `json:"update_available"`
	// URL links to the release page.
	URL string `json:"url,omitempty"`
	// LastCheck is when the last successful check completed.
	LastCheck *time.Time `json:"last_check,omitempty"`
	// Error carries the last failure, so the UI can distinguish "up to date"
	// from "could not tell".
	Error string `json:"error,omitempty"`
}

// Checker polls for new releases and remembers the last answer.
type Checker struct {
	HTTP    *http.Client
	URL     string
	current string
	clock   func() time.Time
	notify  func(version, url string)

	mu     sync.RWMutex
	status Status
}

// New creates a checker for the given running version.
func New(current string, clock func() time.Time) *Checker {
	if clock == nil {
		clock = time.Now
	}
	return &Checker{
		HTTP:    &http.Client{Timeout: 20 * time.Second},
		URL:     defaultURL,
		current: current,
		clock:   clock,
		status:  Status{Current: current},
	}
}

// SetNotifier installs a callback fired once per newly discovered version, so
// a release is announced through ntfy exactly once instead of daily.
func (c *Checker) SetNotifier(f func(version, url string)) { c.notify = f }

// Status returns the last known state.
func (c *Checker) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

// Run checks immediately and then daily until ctx is cancelled.
func (c *Checker) Run(ctx context.Context) {
	// Stagger the first check so a restart storm does not hammer the API and
	// startup stays free of network work.
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Minute):
	}
	var announced string
	for {
		if st := c.check(ctx); st.UpdateAvailable && st.Latest != announced && c.notify != nil {
			announced = st.Latest
			c.notify(st.Latest, st.URL)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(24 * time.Hour):
		}
	}
}

// check performs one lookup and records the result.
func (c *Checker) check(ctx context.Context) Status {
	latest, url, err := c.fetch(ctx)

	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.status.Error = err.Error()
		return c.status
	}
	now := c.clock()
	c.status = Status{
		Checked:         true,
		Current:         c.current,
		Latest:          latest,
		UpdateAvailable: newer(latest, c.current),
		URL:             url,
		LastCheck:       &now,
	}
	return c.status
}

func (c *Checker) fetch(ctx context.Context) (version, url string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("release check returned %s", resp.Status)
	}
	var rel struct {
		TagName    string `json:"tag_name"`
		HTMLURL    string `json:"html_url"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", "", err
	}
	if rel.Draft || rel.Prerelease {
		return "", "", fmt.Errorf("latest release is a draft or prerelease")
	}
	return strings.TrimPrefix(rel.TagName, "v"), rel.HTMLURL, nil
}

// newer reports whether latest is a higher semantic version than current.
// Non-release builds ("dev", "") never claim an update: a developer running a
// local build is ahead, not behind.
func newer(latest, current string) bool {
	lv, ok := parseSemver(latest)
	if !ok {
		return false
	}
	cv, ok := parseSemver(current)
	if !ok {
		return false
	}
	for i := range lv {
		if lv[i] != cv[i] {
			return lv[i] > cv[i]
		}
	}
	return false
}

// parseSemver splits "1.2.3" (with optional pre-release suffix) into its
// numeric components.
func parseSemver(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
