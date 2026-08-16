package ai

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testClient points every provider at one stub server.
func testClient(t *testing.T, h http.Handler) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := NewClient()
	c.BaseURLs = map[Provider]string{}
	for _, p := range Providers() {
		c.BaseURLs[p] = srv.URL
	}
	return c
}

// The three providers authenticate differently, and getting any of them wrong
// produces a 401 the operator would read as "my key is bad". The exact header
// values are asserted rather than merely "some auth header is present".
func TestAuthHeadersPerProvider(t *testing.T) {
	cases := []struct {
		provider Provider
		check    func(t *testing.T, r *http.Request)
	}{
		{ProviderOpenAI, func(t *testing.T, r *http.Request) {
			if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
				t.Errorf("Authorization = %q", got)
			}
			if got := r.Header.Get("x-api-key"); got != "" {
				t.Errorf("openai must not send x-api-key, got %q", got)
			}
		}},
		{ProviderAnthropic, func(t *testing.T, r *http.Request) {
			if got := r.Header.Get("x-api-key"); got != "test-key" {
				t.Errorf("x-api-key = %q", got)
			}
			// Required, not optional: without it the call is rejected.
			if got := r.Header.Get("anthropic-version"); got != anthropicVersion {
				t.Errorf("anthropic-version = %q, want %q", got, anthropicVersion)
			}
			if got := r.Header.Get("Authorization"); got != "" {
				t.Errorf("anthropic must not send Authorization, got %q", got)
			}
		}},
		{ProviderOpenRouter, func(t *testing.T, r *http.Request) {
			if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
				t.Errorf("Authorization = %q", got)
			}
			if got := r.Header.Get("HTTP-Referer"); got == "" {
				t.Error("openrouter asks callers to identify themselves")
			}
		}},
	}

	for _, c := range cases {
		t.Run(string(c.provider), func(t *testing.T) {
			cl := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c.check(t, r)
				// The verify replies differ in shape: a model list is an
				// array, OpenRouter's key endpoint is an object.
				if r.URL.Path == "/api/v1/key" {
					_, _ = w.Write([]byte(`{"data":{"limit_remaining":1}}`))
					return
				}
				_, _ = w.Write([]byte(`{"data":[]}`))
			}))
			if _, err := cl.Verify(context.Background(), c.provider, "test-key"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// The finding that would otherwise have shipped a real bug.
//
// OpenAI and Anthropic authenticate GET /v1/models, so it is a perfect
// zero-token key check. OpenRouter's /api/v1/models is PUBLIC — it answers 200
// for any key, including a garbage one — so validating against it would tell
// the operator that "hunter2" is a valid key. The authenticated endpoint is
// /api/v1/key.
func TestVerifyUsesAnAuthenticatedEndpointOnEveryProvider(t *testing.T) {
	want := map[Provider]string{
		ProviderOpenAI:     "/v1/models",
		ProviderAnthropic:  "/v1/models",
		ProviderOpenRouter: "/api/v1/key",
	}
	for p, path := range want {
		if got := specs[p].VerifyPath; got != path {
			t.Errorf("%s verifies against %q, want %q", p, got, path)
		}
	}
	if specs[ProviderOpenRouter].VerifyPath == "/api/v1/models" {
		t.Error("openrouter's model list is unauthenticated; it cannot validate a key")
	}
}

// OpenRouter's key endpoint also reports the remaining balance, which lets the
// UI warn before the operator's first real request fails with a 402.
func TestVerifyReadsOpenRouterCredit(t *testing.T) {
	cl := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"label":"sk-or-v1-...890","limit_remaining":74.5}}`))
	}))
	st, err := cl.Verify(context.Background(), ProviderOpenRouter, "sk-or-v1-x")
	if err != nil {
		t.Fatal(err)
	}
	if st.CreditRemaining == nil || *st.CreditRemaining != 74.5 {
		t.Errorf("credit = %v, want 74.5", st.CreditRemaining)
	}
}

// Anthropic takes the system prompt as a top-level field and rejects a message
// with role "system"; the other two take it as the first message. Sending the
// wrong shape is a 400 that would read as an outage.
func TestChatBodyShapePerProvider(t *testing.T) {
	t.Run("anthropic", func(t *testing.T) {
		b := chatBody(ProviderAnthropic, "m", "SYS", "USER", 512)
		if b["system"] != "SYS" {
			t.Errorf("system = %v, want it top-level", b["system"])
		}
		if _, ok := b["max_tokens"]; !ok {
			t.Error("anthropic requires max_tokens")
		}
		msgs := b["messages"].([]map[string]string)
		for _, m := range msgs {
			if m["role"] == "system" {
				t.Error("anthropic rejects a system message; it must be the top-level field")
			}
		}
	})

	for _, p := range []Provider{ProviderOpenAI, ProviderOpenRouter} {
		t.Run(string(p), func(t *testing.T) {
			b := chatBody(p, "m", "SYS", "USER", 512)
			if _, ok := b["system"]; ok {
				t.Error("openai-shaped providers take the system prompt as a message")
			}
			msgs := b["messages"].([]map[string]string)
			if len(msgs) != 2 || msgs[0]["role"] != "system" || msgs[0]["content"] != "SYS" {
				t.Errorf("messages = %v", msgs)
			}
		})
	}
}

// Anthropic returns an array of content blocks and text is not always first —
// a thinking-capable model emits other block types ahead of it — so the reader
// searches for the text block rather than indexing [0].
func TestParseCompletionFindsTheTextBlock(t *testing.T) {
	body := []byte(`{"content":[{"type":"thinking","thinking":""},{"type":"text","text":"the answer"}]}`)
	got, err := parseCompletion(ProviderAnthropic, body)
	if err != nil {
		t.Fatal(err)
	}
	if got != "the answer" {
		t.Errorf("got %q", got)
	}

	openaiBody := []byte(`{"choices":[{"message":{"content":"the answer"}}]}`)
	if got, err := parseCompletion(ProviderOpenAI, openaiBody); err != nil || got != "the answer" {
		t.Errorf("got %q, %v", got, err)
	}
}

// Failures must be distinguishable. Telling an operator their key was rejected
// when they were rate limited sends them to regenerate a key that is fine.
func TestStatusErrorsAreDistinguishable(t *testing.T) {
	cases := []struct {
		code int
		want error
	}{
		{http.StatusUnauthorized, ErrBadKey},
		{http.StatusPaymentRequired, ErrNoCredit},
		{http.StatusForbidden, ErrForbidden},
		{http.StatusTooManyRequests, ErrRateLimited},
		{http.StatusInternalServerError, ErrProviderDown},
		{http.StatusServiceUnavailable, ErrProviderDown},
	}
	for _, c := range cases {
		cl := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(c.code)
			_, _ = w.Write([]byte(`{"error":{"message":"upstream said so"}}`))
		}))
		_, err := cl.Verify(context.Background(), ProviderOpenAI, "k")
		if !errors.Is(err, c.want) {
			t.Errorf("status %d gave %v, want %v", c.code, err, c.want)
		}
		// The upstream's own wording survives, so the operator can act on it.
		if err != nil && !contains(err.Error(), "upstream said so") {
			t.Errorf("status %d lost the upstream message: %v", c.code, err)
		}
	}
}

// 401 and 403 must not be collapsed. OpenRouter answers 403 when a moderation
// rule blocked a request made with a perfectly valid key.
func TestForbiddenIsNotReportedAsABadKey(t *testing.T) {
	cl := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	_, err := cl.Verify(context.Background(), ProviderOpenRouter, "k")
	if errors.Is(err, ErrBadKey) {
		t.Error("a 403 was reported as a bad key; the operator would regenerate a working key")
	}
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("got %v, want ErrForbidden", err)
	}
}

// OpenRouter can answer 200 with an error object when the failure happened
// after the model began producing output, so a 200 is not proof of success.
func TestErrorInsideA200IsNotSuccess(t *testing.T) {
	cl := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"error":{"message":"upstream model died mid-stream"}}`))
	}))
	_, err := cl.Complete(context.Background(), ProviderOpenRouter, "k", "m", "s", "u", 256)
	if err == nil {
		t.Fatal("a 200 carrying an error object was treated as success")
	}
	if !contains(err.Error(), "died mid-stream") {
		t.Errorf("lost the message: %v", err)
	}
}

// Complete runs the redaction gate before the bytes leave. A caller that builds
// a prompt by hand and slips an address in must be refused, not merely warned.
func TestCompleteRefusesAnUnredactedPrompt(t *testing.T) {
	var reached bool
	cl := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	_, err := cl.Complete(context.Background(), ProviderOpenAI, "k", "m",
		"you explain alerts", "the device at 192.168.1.47 did something", 256)
	if err == nil {
		t.Fatal("an unredacted prompt was sent")
	}
	if reached {
		t.Error("the request reached the provider despite failing the gate")
	}
}

// A well-formed request reaches the provider and the answer comes back.
func TestCompleteRoundTrip(t *testing.T) {
	cl := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var v map[string]any
		if err := json.Unmarshal(body, &v); err != nil {
			t.Errorf("unreadable request: %v", err)
		}
		if v["model"] != "gpt-5.4-mini" {
			t.Errorf("model = %v", v["model"])
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"a port scan is..."}}]}`))
	}))
	got, err := cl.Complete(context.Background(), ProviderOpenAI, "k", "gpt-5.4-mini",
		"you explain alerts", "detector portscan, 23 ports from 192.168.1.x", 256)
	if err != nil {
		t.Fatal(err)
	}
	if got != "a port scan is..." {
		t.Errorf("got %q", got)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
