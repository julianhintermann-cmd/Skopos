package notify

import (
	"net/http"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/config"
)

// FromConfig builds a Dispatcher from the notify and server sections of the
// configuration, wiring up whichever channels are configured. Channels with no
// URL are simply absent.
func FromConfig(cfg *config.Config) *Dispatcher {
	client := &http.Client{Timeout: 15 * time.Second}

	channels := []Channel{
		NewNtfy(NtfyConfig{
			URL:      cfg.Notify.Ntfy.URL,
			Topic:    cfg.Notify.Ntfy.Topic,
			Token:    cfg.Notify.Ntfy.Token,
			Username: cfg.Notify.Ntfy.Username,
			Password: cfg.Notify.Ntfy.Password,
		}, client),
		NewWebhook(WebhookConfig{URL: cfg.Notify.Webhook.URL}, client),
	}

	return New(Options{
		Channels:      channels,
		ExternalURL:   cfg.Server.ExternalURL,
		SystemEnabled: cfg.Notify.System.Enabled,
	})
}
