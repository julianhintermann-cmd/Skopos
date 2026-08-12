package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// WebhookConfig configures the generic webhook channel.
type WebhookConfig struct {
	URL string
}

// Webhook posts each message as JSON to a configurable URL, so Skopos can feed
// home automation, a chat bridge or any custom endpoint.
type Webhook struct {
	url    string
	client *http.Client
}

// NewWebhook creates a webhook channel, or nil when no URL is configured.
func NewWebhook(cfg WebhookConfig, client *http.Client) *Webhook {
	if cfg.URL == "" {
		return nil
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &Webhook{url: cfg.URL, client: client}
}

// Name implements Channel.
func (w *Webhook) Name() string { return "webhook" }

// webhookPayload is the JSON shape posted to the webhook.
type webhookPayload struct {
	Title    string   `json:"title"`
	Body     string   `json:"body"`
	Severity string   `json:"severity"`
	Category string   `json:"category"`
	Tags     []string `json:"tags,omitempty"`
	ClickURL string   `json:"click_url,omitempty"`
}

// Send implements Channel.
func (w *Webhook) Send(ctx context.Context, m Message) error {
	payload := webhookPayload{
		Title:    m.Title,
		Body:     m.Body,
		Severity: string(m.Severity),
		Category: string(m.Category),
		Tags:     m.Tags,
		ClickURL: m.ClickURL,
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}
