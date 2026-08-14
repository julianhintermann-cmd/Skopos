package api

import (
	"net/http"
	"strings"

	"github.com/julianhintermann-cmd/skopos/internal/config"
)

// ConfigReport describes the configuration the process is actually running on.
//
// It exists because the most consequential configuration mistake is invisible
// from inside the dashboard: a mistyped mount path means Skopos never read the
// file, falls back to defaults, and every screen looks entirely normal. The
// operator sees settings that are not theirs and no indication of why. Path and
// Found together make that one glance instead of a shell.
//
// Nothing here is a secret. Whether a notifier is configured is reported;
// what it is configured with is not.
type ConfigReport struct {
	// Path is where Skopos looked, always present — it is the fact that makes
	// a bad mount actionable rather than merely puzzling.
	Path string `json:"path"`
	// Found is false when the file was not there and built-in defaults are in
	// force. Everything in the operator's file is then being ignored.
	Found bool `json:"found"`
	// Inert names the keys in the operator's own file that Skopos accepts and
	// does not act on. Absent when there are none.
	Inert []string `json:"inert_keys,omitempty"`
	// InertReasons explains each of them, so the answer to "why does this do
	// nothing" travels with the finding.
	InertReasons map[string]string `json:"inert_reasons,omitempty"`
	Notify       NotifyReport      `json:"notify"`
}

// NotifyReport says whether each delivery channel is set up, and where it
// points. The ntfy token lives in the environment and never appears here; a
// URL and a topic are addresses, not credentials.
type NotifyReport struct {
	Ntfy    ChannelReport `json:"ntfy"`
	Webhook ChannelReport `json:"webhook"`
}

type ChannelReport struct {
	Configured bool   `json:"configured"`
	URL        string `json:"url,omitempty"`
	Topic      string `json:"topic,omitempty"`
}

// handleConfig reports where the configuration came from and what in it is
// inert. Read scope: it carries no secret, and an operator who can see the
// dashboard can already see every effective setting.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.deps.Config
	rep := ConfigReport{
		Path:  s.deps.ConfigInfo.Path,
		Found: !s.deps.ConfigInfo.Missing,
		Inert: s.deps.ConfigInfo.Inert,
	}
	if len(rep.Inert) > 0 {
		all := config.InertKeys()
		rep.InertReasons = make(map[string]string, len(rep.Inert))
		for _, k := range rep.Inert {
			if why, ok := all[k]; ok {
				rep.InertReasons[k] = why
			}
		}
	}
	if cfg != nil {
		ntfy := cfg.Notify.Ntfy
		rep.Notify.Ntfy = ChannelReport{
			// A topic with no server reaches nothing, and a server with no
			// topic has nowhere to publish. Either alone is a half-configured
			// notifier that would otherwise report itself as ready.
			Configured: strings.TrimSpace(ntfy.URL) != "" && strings.TrimSpace(ntfy.Topic) != "",
			URL:        ntfy.URL,
			Topic:      ntfy.Topic,
		}
		hook := cfg.Notify.Webhook
		rep.Notify.Webhook = ChannelReport{
			Configured: strings.TrimSpace(hook.URL) != "",
			URL:        hook.URL,
		}
	}
	writeJSON(w, http.StatusOK, rep)
}
