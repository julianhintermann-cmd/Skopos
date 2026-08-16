package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxBody caps a provider response, mirroring the Cloudflare client.
const maxBody = 8 << 20

// Failure classes. The three providers disagree on which status means what, so
// the client normalises here and every caller above works in these terms.
//
// ErrBadKey and ErrForbidden are deliberately separate. The Cloudflare client
// collapses 401 and 403 into one "token rejected" message, which is right for
// Cloudflare and wrong here: OpenRouter answers 403 when a moderation rule
// blocked a request made with a perfectly good key, and telling the operator
// their key was rejected would send them off to regenerate a key that is fine.
var (
	ErrBadKey        = errors.New("ai: the provider rejected this key")
	ErrNoCredit      = errors.New("ai: the provider reports no remaining credit")
	ErrForbidden     = errors.New("ai: the provider refused this request")
	ErrRateLimited   = errors.New("ai: the provider is rate limiting this key")
	ErrProviderDown  = errors.New("ai: the provider is unavailable")
	ErrNotConfigured = errors.New("ai: no provider is configured")
)

// Client talks to one provider. It holds no key: like the Cloudflare client,
// the credential is a method parameter, so the long-lived object never carries
// a secret and tests can exercise every path without one.
type Client struct {
	HTTP *http.Client
	// BaseURLs overrides a provider's endpoint. Tests point it at httptest;
	// in production it is empty and the table in provider.go is used.
	BaseURLs map[Provider]string
}

// NewClient builds a Client with the same 20-second ceiling the Cloudflare
// client uses.
func NewClient() *Client {
	return &Client{HTTP: &http.Client{Timeout: 20 * time.Second}}
}

func (c *Client) base(p Provider) string {
	if u, ok := c.BaseURLs[p]; ok && u != "" {
		return u
	}
	return specs[p].BaseURL
}

// KeyStatus is what Verify learned. It carries no secret.
type KeyStatus struct {
	// Models is the provider's model list, when the verify call returned one.
	// OpenRouter's authenticated endpoint reports credit rather than models,
	// so this is empty there.
	Models []string `json:"models,omitempty"`
	// CreditRemaining is OpenRouter's remaining balance, when reported.
	CreditRemaining *float64 `json:"credit_remaining,omitempty"`
}

// Verify checks a key against the provider, as cheaply as the provider allows.
// For OpenAI and Anthropic that is an authenticated model list, which runs no
// inference and costs no tokens; for OpenRouter it is the key endpoint, because
// its model list is public and would accept anything.
func (c *Client) Verify(ctx context.Context, p Provider, key string) (KeyStatus, error) {
	s, ok := specs[p]
	if !ok {
		return KeyStatus{}, errUnsupported(p)
	}
	body, err := c.do(ctx, p, http.MethodGet, s.VerifyPath, key, nil)
	if err != nil {
		return KeyStatus{}, err
	}

	var out KeyStatus
	switch p {
	case ProviderOpenRouter:
		var v struct {
			Data struct {
				LimitRemaining *float64 `json:"limit_remaining"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &v); err != nil {
			return KeyStatus{}, fmt.Errorf("ai: openrouter returned an unreadable reply: %w", err)
		}
		out.CreditRemaining = v.Data.LimitRemaining
	default:
		var v struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &v); err != nil {
			return KeyStatus{}, fmt.Errorf("ai: %s returned an unreadable reply: %w", p, err)
		}
		for _, m := range v.Data {
			out.Models = append(out.Models, m.ID)
		}
	}
	return out, nil
}

// Complete asks the provider for one single-turn completion and returns the
// assistant's text.
func (c *Client) Complete(ctx context.Context, p Provider, key, model, system, user string, maxTokens int) (string, error) {
	s, ok := specs[p]
	if !ok {
		return "", errUnsupported(p)
	}
	if model == "" {
		model = s.DefaultModel
	}

	payload, err := json.Marshal(chatBody(p, model, system, user, maxTokens))
	if err != nil {
		return "", err
	}
	// The last gate before the bytes leave the machine.
	if err := Clean(string(payload)); err != nil {
		return "", err
	}

	body, err := c.do(ctx, p, http.MethodPost, s.ChatPath, key, payload)
	if err != nil {
		return "", err
	}
	return parseCompletion(p, body)
}

// parseCompletion pulls the assistant's text out of a provider reply.
//
// Anthropic returns an array of content blocks, which is not always
// text-first — a thinking-capable model emits other block types ahead of it —
// so the block is searched for rather than indexed.
func parseCompletion(p Provider, body []byte) (string, error) {
	if p == ProviderAnthropic {
		var v struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(body, &v); err != nil {
			return "", fmt.Errorf("ai: anthropic returned an unreadable reply: %w", err)
		}
		for _, b := range v.Content {
			if b.Type == "text" && strings.TrimSpace(b.Text) != "" {
				return b.Text, nil
			}
		}
		return "", errors.New("ai: anthropic returned no text")
	}

	var v struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return "", fmt.Errorf("ai: %s returned an unreadable reply: %w", p, err)
	}
	if len(v.Choices) == 0 || strings.TrimSpace(v.Choices[0].Message.Content) == "" {
		return "", fmt.Errorf("ai: %s returned no text", p)
	}
	return v.Choices[0].Message.Content, nil
}

// do performs one request and maps the outcome onto the error classes above.
func (c *Client) do(ctx context.Context, p Provider, method, path, key string, payload []byte) ([]byte, error) {
	var rdr io.Reader
	if payload != nil {
		rdr = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base(p)+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	authorize(p, req, key)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderDown, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("%w: the reply could not be read", ErrProviderDown)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, statusError(resp.StatusCode, providerMessage(body))
	}

	// OpenRouter can answer 200 with an error object in the body when the
	// failure happened after the model began producing output. A 200 is
	// therefore not on its own proof of success.
	if msg, bad := embeddedError(body); bad {
		return nil, fmt.Errorf("ai: %s: %s", p, msg)
	}
	return body, nil
}

// statusError maps an HTTP status onto one of the error classes.
func statusError(code int, msg string) error {
	var base error
	switch {
	case code == http.StatusUnauthorized:
		base = ErrBadKey
	case code == http.StatusPaymentRequired:
		base = ErrNoCredit
	case code == http.StatusForbidden:
		base = ErrForbidden
	case code == http.StatusTooManyRequests:
		base = ErrRateLimited
	case code >= 500:
		base = ErrProviderDown
	default:
		base = fmt.Errorf("ai: the provider answered %d", code)
	}
	if msg == "" {
		return base
	}
	return fmt.Errorf("%w: %s", base, msg)
}

// providerMessage digs the human-readable message out of an error body. The
// three providers nest it differently; an unrecognised shape yields "".
func providerMessage(body []byte) string {
	var v struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &v); err == nil {
		if v.Error.Message != "" {
			return v.Error.Message
		}
		if v.Error.Type != "" {
			return v.Error.Type
		}
	}
	return ""
}

// embeddedError reports an error object carried inside a 200 response.
func embeddedError(body []byte) (string, bool) {
	var v struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &v); err != nil || v.Error == nil {
		return "", false
	}
	if v.Error.Message == "" {
		return "the provider reported an error", true
	}
	return v.Error.Message, true
}
