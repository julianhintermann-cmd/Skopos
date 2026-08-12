// Package notify delivers alerts and operational messages to the outside
// world. A Dispatcher fans each message out to the configured channels (ntfy
// and a generic webhook in v1); both speak the same Message shape so adding a
// channel never touches the policy layer.
package notify

import (
	"context"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// Category distinguishes detection alerts from operational/system messages so
// channels and users can treat them differently.
type Category string

const (
	CategoryAlert  Category = "alert"
	CategorySystem Category = "system"
)

// Message is one notification, independent of any channel.
type Message struct {
	Title    string
	Body     string
	Severity model.Severity
	Category Category
	Tags     []string
	// ClickURL, when set, is where tapping the notification should take the
	// user (the dashboard alert, usually).
	ClickURL string
}

// ntfyPriority maps a severity to ntfy's 1–5 priority scale.
func ntfyPriority(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 5 // urgent
	case model.SeverityWarning:
		return 4 // high
	case model.SeverityInfo:
		return 3 // default
	default:
		return 3
	}
}

// defaultTag returns an emoji tag for a severity, used when a message carries
// no explicit tags.
func defaultTag(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "rotating_light"
	case model.SeverityWarning:
		return "warning"
	default:
		return "information_source"
	}
}

// Channel delivers a Message. Implementations are responsible for their own
// transport, auth and timeouts.
type Channel interface {
	Send(ctx context.Context, m Message) error
	Name() string
}
