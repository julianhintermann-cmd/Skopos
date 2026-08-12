package notify

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// isNil reports whether an interface holds a nil pointer. The channel
// constructors return a typed nil (*Ntfy)(nil) when unconfigured, which is not
// == nil once boxed in the Channel interface, so guard against it explicitly.
func isNil(c Channel) bool {
	v := reflect.ValueOf(c)
	return v.Kind() == reflect.Ptr && v.IsNil()
}

// Dispatcher fans a message out to every configured channel. It implements
// policy.Notifier (Notify) and adds operational system messages and a test
// send. Channel failures are isolated: one channel erroring never stops the
// others, and the error is surfaced through the logger.
type Dispatcher struct {
	channels      []Channel
	externalURL   string
	systemEnabled bool
	log           func(string, ...any)
}

// Options configures a Dispatcher.
type Options struct {
	// Channels are the delivery channels; nil entries (unconfigured) are
	// skipped.
	Channels []Channel
	// ExternalURL is the dashboard base URL used to build notification click
	// targets, e.g. https://skopos.example.com.
	ExternalURL string
	// SystemEnabled toggles operational (system-category) notifications.
	SystemEnabled bool
}

// New creates a Dispatcher, dropping any nil channels.
func New(opts Options) *Dispatcher {
	var active []Channel
	for _, c := range opts.Channels {
		if c != nil && !isNil(c) {
			active = append(active, c)
		}
	}
	return &Dispatcher{
		channels:      active,
		externalURL:   strings.TrimRight(opts.ExternalURL, "/"),
		systemEnabled: opts.SystemEnabled,
		log:           func(string, ...any) {},
	}
}

// SetLogger installs a logging callback for channel failures.
func (d *Dispatcher) SetLogger(f func(string, ...any)) { d.log = f }

// HasChannels reports whether any delivery channel is configured.
func (d *Dispatcher) HasChannels() bool { return len(d.channels) > 0 }

// Notify implements policy.Notifier: it turns an alert into a message and
// delivers it.
func (d *Dispatcher) Notify(ctx context.Context, a model.Alert) {
	m := Message{
		Title:    a.Title,
		Body:     d.alertBody(a),
		Severity: a.Severity,
		Category: CategoryAlert,
		ClickURL: d.alertClickURL(a),
	}
	d.deliver(ctx, m)
}

// System sends an operational message (start after crash, firewall degraded,
// cold storage unreachable, feed update failed, update available). It is a
// no-op when system notifications are disabled.
func (d *Dispatcher) System(ctx context.Context, severity model.Severity, title, body string) {
	if !d.systemEnabled {
		return
	}
	d.deliver(ctx, Message{
		Title:    title,
		Body:     body,
		Severity: severity,
		Category: CategorySystem,
		Tags:     []string{"gear"},
	})
}

// Test sends a confirmation message to every channel and returns a combined
// error if any failed. Used by `skopos notify-test` and the settings UI.
func (d *Dispatcher) Test(ctx context.Context) error {
	if !d.HasChannels() {
		return fmt.Errorf("no notification channels are configured")
	}
	m := Message{
		Title:    "Skopos test notification",
		Body:     "If you can read this, Skopos can reach your notification channel.",
		Severity: model.SeverityInfo,
		Category: CategorySystem,
		Tags:     []string{"white_check_mark"},
	}
	var failures []string
	for _, c := range d.channels {
		if err := c.Send(ctx, m); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", c.Name(), err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return nil
}

// deliver sends to every channel, isolating failures.
func (d *Dispatcher) deliver(ctx context.Context, m Message) {
	for _, c := range d.channels {
		if err := c.Send(ctx, m); err != nil {
			d.log("notify: channel %s failed: %v", c.Name(), err)
		}
	}
}

func (d *Dispatcher) alertBody(a model.Alert) string {
	var b strings.Builder
	if a.Detail != "" {
		b.WriteString(a.Detail)
	}
	if a.Source.IsValid() {
		fmt.Fprintf(&b, "\nSource: %s", a.Source)
	}
	if a.Count > 1 {
		fmt.Fprintf(&b, "\n(%d occurrences)", a.Count)
	}
	return strings.TrimSpace(b.String())
}

func (d *Dispatcher) alertClickURL(a model.Alert) string {
	if d.externalURL == "" || a.ID == 0 {
		return d.externalURL
	}
	return fmt.Sprintf("%s/alerts/%d", d.externalURL, a.ID)
}
