// Package ai talks to a language-model provider on the operator's behalf, to
// turn one opaque technical artefact — an alert, a device's destination list —
// into one sentence a person can read.
//
// Three things about this package are deliberate and load-bearing.
//
// It is configured entirely through the web UI. The key is entered there,
// sealed with the same AES-GCM box that holds the Cloudflare token, and never
// returned by any endpoint. Nothing here reads config.yaml, because a secret in
// a YAML file is a secret in a backup, in a paste, and in a screenshot.
//
// Nothing in this package is ever called by a background job. Every request
// traces to a click. That single constraint bounds the cost, keeps the privacy
// exposure legible to the operator — they sent it, because they pressed the
// button — and makes the failure mode a visible error rather than a silent
// nightly leak.
//
// And everything that leaves goes through redact.go first. Skopos' README says
// captured data never leaves the NAS; this package is the one exception to that
// promise, so what it may send is decided in one place, by a typed function,
// with its own tests — not by whatever a prompt happens to interpolate.
package ai

import (
	"fmt"
	"net/http"
	"strings"
)

// Provider is one of the three the operator can pick in the UI.
type Provider string

const (
	ProviderOpenAI     Provider = "openai"
	ProviderAnthropic  Provider = "anthropic"
	ProviderOpenRouter Provider = "openrouter"
)

// Providers lists the supported providers in the order the dropdown shows them.
func Providers() []Provider {
	return []Provider{ProviderOpenAI, ProviderAnthropic, ProviderOpenRouter}
}

// Valid reports whether p is one Skopos knows how to talk to.
func (p Provider) Valid() bool {
	switch p {
	case ProviderOpenAI, ProviderAnthropic, ProviderOpenRouter:
		return true
	}
	return false
}

// spec is everything that differs between the three providers, gathered in one
// table so the client below can stay provider-agnostic.
type spec struct {
	// Label is what the UI shows.
	Label string
	// BaseURL is overridable per-Client so tests can point at httptest.
	BaseURL string
	// ChatPath is the completion endpoint, relative to BaseURL.
	ChatPath string
	// VerifyPath is a cheap authenticated endpoint used to check a key.
	//
	// This differs per provider and getting it wrong is not cosmetic. OpenAI
	// and Anthropic both authenticate GET /v1/models, so it costs zero tokens
	// and answers exactly the question "is this key real". OpenRouter's
	// /api/v1/models is PUBLIC — it answers 200 for a key of "hunter2", for an
	// empty key, for no header at all — so validating against it would print
	// "key accepted" for any string the operator pasted. /api/v1/key is the
	// authenticated one, and it also reports the remaining credit.
	VerifyPath string
	// KeyPrefix is the documented prefix for this provider's keys, used only to
	// catch an obviously-wrong paste before spending a request. It is never a
	// hard gate: prefixes are a convention, not a contract, and refusing a key
	// that would have worked is worse than one wasted round trip.
	KeyPrefix string
	// KeysURL is where the operator goes to create a key.
	KeysURL string
	// DefaultModel is a cheap, fast model suited to one-paragraph explanation.
	DefaultModel string
}

var specs = map[Provider]spec{
	ProviderOpenAI: {
		Label:        "OpenAI (ChatGPT)",
		BaseURL:      "https://api.openai.com",
		ChatPath:     "/v1/chat/completions",
		VerifyPath:   "/v1/models",
		KeyPrefix:    "sk-",
		KeysURL:      "https://platform.openai.com/api-keys",
		DefaultModel: "gpt-5.4-mini",
	},
	ProviderAnthropic: {
		Label:        "Anthropic (Claude)",
		BaseURL:      "https://api.anthropic.com",
		ChatPath:     "/v1/messages",
		VerifyPath:   "/v1/models",
		KeyPrefix:    "sk-ant-",
		KeysURL:      "https://console.anthropic.com/settings/keys",
		DefaultModel: "claude-haiku-4-5",
	},
	ProviderOpenRouter: {
		Label:    "OpenRouter",
		BaseURL:  "https://openrouter.ai",
		ChatPath: "/api/v1/chat/completions",
		// Not /api/v1/models — that one is unauthenticated. See VerifyPath.
		VerifyPath:   "/api/v1/key",
		KeyPrefix:    "sk-or-",
		KeysURL:      "https://openrouter.ai/keys",
		DefaultModel: "anthropic/claude-haiku-4-5",
	},
}

// anthropicVersion is the API version Anthropic requires on every request. It
// is a required header, not an optional one: without it the call is rejected.
const anthropicVersion = "2023-06-01"

// referer and title identify Skopos to OpenRouter, which asks callers to
// identify themselves so usage can be attributed.
const (
	openRouterReferer = "https://github.com/julianhintermann-cmd/skopos"
	openRouterTitle   = "Skopos"
)

// Info describes a provider for the UI's dropdown. It carries no secret.
type Info struct {
	ID           Provider `json:"id"`
	Label        string   `json:"label"`
	KeyPrefix    string   `json:"key_prefix"`
	KeysURL      string   `json:"keys_url"`
	DefaultModel string   `json:"default_model"`
}

// Catalog describes every supported provider, for the settings page.
func Catalog() []Info {
	out := make([]Info, 0, len(specs))
	for _, p := range Providers() {
		s := specs[p]
		out = append(out, Info{
			ID: p, Label: s.Label, KeyPrefix: s.KeyPrefix,
			KeysURL: s.KeysURL, DefaultModel: s.DefaultModel,
		})
	}
	return out
}

// LooksLikeKey reports whether key carries the provider's documented prefix.
// A false answer is a warning for the UI, never a refusal — see KeyPrefix.
func LooksLikeKey(p Provider, key string) bool {
	s, ok := specs[p]
	if !ok {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(key), s.KeyPrefix)
}

// DefaultModel returns the cheap model Skopos picks when the operator has not
// chosen one.
func DefaultModel(p Provider) string { return specs[p].DefaultModel }

// authorize applies the provider's authentication scheme to req. The three
// disagree: OpenAI and OpenRouter take a bearer token, Anthropic takes the key
// in x-api-key and additionally requires a version header.
func authorize(p Provider, req *http.Request, key string) {
	switch p {
	case ProviderAnthropic:
		req.Header.Set("x-api-key", key)
		req.Header.Set("anthropic-version", anthropicVersion)
	case ProviderOpenRouter:
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("HTTP-Referer", openRouterReferer)
		req.Header.Set("X-OpenRouter-Title", openRouterTitle)
	default:
		req.Header.Set("Authorization", "Bearer "+key)
	}
}

// chatBody builds the provider's request body for a single-turn completion.
//
// The shapes are not interchangeable. OpenAI and OpenRouter carry the system
// prompt as the first message; Anthropic takes it as a top-level field and
// rejects a message with role "system". Anthropic also requires max_tokens,
// where the other two default it.
func chatBody(p Provider, model, system, user string, maxTokens int) map[string]any {
	if p == ProviderAnthropic {
		return map[string]any{
			"model":      model,
			"max_tokens": maxTokens,
			"system":     system,
			"messages": []map[string]string{
				{"role": "user", "content": user},
			},
		}
	}
	return map[string]any{
		"model":      model,
		"max_tokens": maxTokens,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
	}
}

// errUnsupported reports a provider the UI should never have offered.
func errUnsupported(p Provider) error {
	return fmt.Errorf("ai: unsupported provider %q", p)
}
