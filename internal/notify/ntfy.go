package notify

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// NtfyConfig configures the ntfy channel.
type NtfyConfig struct {
	URL      string // base URL, e.g. https://ntfy.example.com or https://ntfy.sh
	Topic    string
	Token    string // Bearer access token (preferred)
	Username string // basic-auth alternative
	Password string
}

// Ntfy publishes messages to an ntfy server (self-hosted or ntfy.sh — same
// API). Auth is optional: Bearer token, basic auth, or none.
type Ntfy struct {
	cfg    NtfyConfig
	client *http.Client
}

// NewNtfy creates an ntfy channel. Returns nil when no URL is configured, so
// the dispatcher can simply skip an unconfigured channel.
func NewNtfy(cfg NtfyConfig, client *http.Client) *Ntfy {
	if cfg.URL == "" || cfg.Topic == "" {
		return nil
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &Ntfy{cfg: cfg, client: client}
}

// Name implements Channel.
func (n *Ntfy) Name() string { return "ntfy" }

// Send implements Channel: it POSTs the message body to {url}/{topic} with the
// ntfy metadata headers.
func (n *Ntfy) Send(ctx context.Context, m Message) error {
	endpoint := strings.TrimRight(n.cfg.URL, "/") + "/" + n.cfg.Topic
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(m.Body))
	if err != nil {
		return err
	}

	if m.Title != "" {
		req.Header.Set("Title", m.Title)
	}
	req.Header.Set("Priority", strconv.Itoa(ntfyPriority(m.Severity)))

	tags := m.Tags
	if len(tags) == 0 {
		tags = []string{defaultTag(m.Severity)}
	}
	req.Header.Set("Tags", strings.Join(tags, ","))

	if len(m.Actions) > 0 {
		specs := make([]string, 0, len(m.Actions))
		for _, a := range m.Actions {
			// ntfy separates action fields with commas, so a label or URL
			// containing one would split the spec; ours never do, and
			// sanitising keeps that true for future callers.
			specs = append(specs, fmt.Sprintf("http, %s, %s, method=GET, clear=true",
				sanitizeAction(a.Label), sanitizeAction(a.URL)))
		}
		req.Header.Set("Actions", strings.Join(specs, "; "))
	}
	if m.ClickURL != "" {
		req.Header.Set("Click", m.ClickURL)
	}

	switch {
	case n.cfg.Token != "":
		req.Header.Set("Authorization", "Bearer "+n.cfg.Token)
	case n.cfg.Username != "":
		req.SetBasicAuth(n.cfg.Username, n.cfg.Password)
	}

	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("ntfy returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

// sanitizeAction strips the characters ntfy's action syntax reserves.
func sanitizeAction(s string) string {
	return strings.NewReplacer(",", " ", ";", " ", "\n", " ").Replace(s)
}
