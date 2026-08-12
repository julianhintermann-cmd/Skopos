package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

func TestNtfySendSetsHeaders(t *testing.T) {
	var gotTitle, gotPriority, gotTags, gotClick, gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTitle = r.Header.Get("Title")
		gotPriority = r.Header.Get("Priority")
		gotTags = r.Header.Get("Tags")
		gotClick = r.Header.Get("Click")
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		if !strings.HasSuffix(r.URL.Path, "/skopos") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	n := NewNtfy(NtfyConfig{URL: srv.URL, Topic: "skopos", Token: "tok_secret"}, srv.Client())
	if n == nil {
		t.Fatal("expected a channel")
	}
	err := n.Send(context.Background(), Message{
		Title: "Port scan", Body: "detail here", Severity: model.SeverityCritical,
		ClickURL: "https://skopos.example.com/alerts/1",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotTitle != "Port scan" {
		t.Errorf("Title = %q", gotTitle)
	}
	if gotPriority != "5" {
		t.Errorf("Priority = %q, want 5 for critical", gotPriority)
	}
	if gotTags == "" {
		t.Error("expected a default tag")
	}
	if gotClick != "https://skopos.example.com/alerts/1" {
		t.Errorf("Click = %q", gotClick)
	}
	if gotAuth != "Bearer tok_secret" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotBody != "detail here" {
		t.Errorf("Body = %q", gotBody)
	}
}

func TestNtfyBasicAuth(t *testing.T) {
	var user, pass string
	var ok bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok = r.BasicAuth()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	n := NewNtfy(NtfyConfig{URL: srv.URL, Topic: "t", Username: "u", Password: "p"}, srv.Client())
	_ = n.Send(context.Background(), Message{Body: "x", Severity: model.SeverityInfo})
	if !ok || user != "u" || pass != "p" {
		t.Errorf("basic auth = %q/%q ok=%v", user, pass, ok)
	}
}

func TestNtfyUnconfiguredReturnsNil(t *testing.T) {
	if NewNtfy(NtfyConfig{Topic: "t"}, nil) != nil {
		t.Error("no URL should yield a nil channel")
	}
}

func TestNtfyServerErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden topic", http.StatusForbidden)
	}))
	defer srv.Close()
	n := NewNtfy(NtfyConfig{URL: srv.URL, Topic: "t"}, srv.Client())
	if err := n.Send(context.Background(), Message{Body: "x"}); err == nil {
		t.Error("expected error on non-2xx response")
	}
}

func TestWebhookPostsJSON(t *testing.T) {
	var payload webhookPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wh := NewWebhook(WebhookConfig{URL: srv.URL}, srv.Client())
	err := wh.Send(context.Background(), Message{
		Title: "t", Body: "b", Severity: model.SeverityWarning, Category: CategoryAlert,
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if payload.Title != "t" || payload.Severity != "warning" || payload.Category != "alert" {
		t.Errorf("payload = %+v", payload)
	}
}

// recordChannel is a Channel that records messages and can be made to fail.
type recordChannel struct {
	mu   sync.Mutex
	msgs []Message
	fail bool
	name string
}

func (r *recordChannel) Name() string { return r.name }
func (r *recordChannel) Send(_ context.Context, m Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return io.ErrUnexpectedEOF
	}
	r.msgs = append(r.msgs, m)
	return nil
}

func TestDispatcherFanOutAndClickURL(t *testing.T) {
	a := &recordChannel{name: "a"}
	b := &recordChannel{name: "b"}
	d := New(Options{Channels: []Channel{a, b}, ExternalURL: "https://skopos.example.com/", SystemEnabled: true})

	alert := model.Alert{
		ID: 42, Detector: "portscan", Severity: model.SeverityWarning,
		Source: netip.MustParseAddr("203.0.113.5"), Title: "Scan", Detail: "15 ports", Count: 3,
	}
	d.Notify(context.Background(), alert)

	for _, c := range []*recordChannel{a, b} {
		if len(c.msgs) != 1 {
			t.Fatalf("channel %s got %d messages", c.name, len(c.msgs))
		}
		m := c.msgs[0]
		if m.ClickURL != "https://skopos.example.com/alerts/42" {
			t.Errorf("click url = %q", m.ClickURL)
		}
		if !strings.Contains(m.Body, "203.0.113.5") || !strings.Contains(m.Body, "3 occurrences") {
			t.Errorf("body missing source/count: %q", m.Body)
		}
	}
}

func TestDispatcherIsolatesChannelFailure(t *testing.T) {
	failing := &recordChannel{name: "bad", fail: true}
	good := &recordChannel{name: "good"}
	d := New(Options{Channels: []Channel{failing, good}})

	d.Notify(context.Background(), model.Alert{Title: "x", Severity: model.SeverityInfo})
	if len(good.msgs) != 1 {
		t.Error("a failing channel must not stop the others")
	}
}

func TestDispatcherSkipsNilChannels(t *testing.T) {
	// Unconfigured constructors return typed nils; the dispatcher must drop
	// them rather than panic on Send.
	d := New(Options{Channels: []Channel{NewNtfy(NtfyConfig{}, nil), NewWebhook(WebhookConfig{}, nil)}})
	if d.HasChannels() {
		t.Error("all channels were unconfigured; HasChannels should be false")
	}
	// Notify must not panic with no channels.
	d.Notify(context.Background(), model.Alert{Title: "x"})
	if err := d.Test(context.Background()); err == nil {
		t.Error("Test with no channels should error")
	}
}

func TestDispatcherSystemGatedByToggle(t *testing.T) {
	c := &recordChannel{name: "c"}
	off := New(Options{Channels: []Channel{c}, SystemEnabled: false})
	off.System(context.Background(), model.SeverityWarning, "t", "b")
	if len(c.msgs) != 0 {
		t.Error("system messages should be suppressed when disabled")
	}

	c2 := &recordChannel{name: "c2"}
	on := New(Options{Channels: []Channel{c2}, SystemEnabled: true})
	on.System(context.Background(), model.SeverityWarning, "t", "b")
	if len(c2.msgs) != 1 {
		t.Error("system messages should be delivered when enabled")
	}
}
