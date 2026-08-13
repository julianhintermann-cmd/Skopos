package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/notify"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

// Action tokens let a push notification carry working buttons — "Block",
// "Mute" — without carrying an API credential. Each token authorises exactly
// one operation on exactly one target and expires; leaking a notification
// therefore leaks the ability to block one address for a while, not access to
// the API. The signing key is the one already in the store for sessions.
const (
	actionTTL      = 7 * 24 * time.Hour
	actionBlock    = "block"
	actionMute     = "mute"
	actionBlockTTL = 24 * time.Hour
)

// mintAction returns a signed, single-purpose token.
func (s *Server) mintAction(kind, target, detector string, now time.Time) string {
	payload := strings.Join([]string{
		kind, target, detector, strconv.FormatInt(now.Add(actionTTL).Unix(), 10),
	}, "|")
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + s.signAction(payload)
}

func (s *Server) signAction(payload string) string {
	mac := hmac.New(sha256.New, s.signer.key)
	mac.Write([]byte("action:" + payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// parseAction verifies a token and returns its authorised operation.
func (s *Server) parseAction(token string, now time.Time) (kind, target, detector string, ok bool) {
	raw, sig, found := strings.Cut(token, ".")
	if !found {
		return "", "", "", false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return "", "", "", false
	}
	payload := string(decoded)
	if !hmac.Equal([]byte(sig), []byte(s.signAction(payload))) {
		return "", "", "", false
	}
	parts := strings.Split(payload, "|")
	if len(parts) != 4 {
		return "", "", "", false
	}
	exp, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || now.After(time.Unix(exp, 0)) {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// ActionLinks are the notification buttons for one alert.
type ActionLinks struct {
	Block string
	Mute  string
}

// actionLinks builds the URLs for an alert's buttons, or zero values when no
// external URL is configured (a button pointing at localhost would only
// frustrate).
func (s *Server) actionLinks(a model.Alert) ActionLinks {
	base := strings.TrimRight(s.deps.Config.Server.ExternalURL, "/")
	if base == "" || !a.Source.IsValid() {
		return ActionLinks{}
	}
	now := s.clock()
	return ActionLinks{
		Block: base + "/api/actions/" + s.mintAction(actionBlock, a.Source.String(), a.Detector, now),
		Mute:  base + "/api/actions/" + s.mintAction(actionMute, a.Source.String(), a.Detector, now),
	}
}

// handleAction performs the single operation a token authorises. It is
// deliberately reachable without a session: the token is the credential, it
// is scoped to one target and one verb, and it expires. Repeating it is
// harmless — blocking an address twice is blocking it once.
func (s *Server) handleAction(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	kind, target, detector, ok := s.parseAction(r.PathValue("token"), s.clock())
	if !ok {
		writeError(w, http.StatusForbidden, "this action link is invalid or has expired")
		return
	}
	addr, err := netip.ParseAddr(target)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid target")
		return
	}
	prefix := netip.PrefixFrom(addr, addr.BitLen())

	switch kind {
	case actionBlock:
		if err := s.deps.Firewall.ManualBlock(ctx, prefix, "notification", "blocked from a notification", actionBlockTTL); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.deps.Store.Audit(ctx, model.AuditEntry{
			Actor: "notification", Action: "block", Target: prefix.String(),
			Detail: "from a notification button",
		})
		enforcing := s.deps.Firewall.Enforcing()
		msg := fmt.Sprintf("Blocked %s for %s.", addr, actionBlockTTL)
		if !enforcing {
			msg += " Enforcement is off, so this is recorded but not applied yet."
		}
		writeActionPage(w, "Blocked", msg)

	case actionMute:
		rule := store.MuteRule{Detector: detector, Prefix: prefix.String(), Reason: "muted from a notification"}
		if _, err := s.deps.Store.AddMuteRule(ctx, rule); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.reloadMutes()
		_ = s.deps.Store.Audit(ctx, model.AuditEntry{
			Actor: "notification", Action: "mute_add", Target: prefix.String(), Detail: detector,
		})
		writeActionPage(w, "Muted",
			fmt.Sprintf("No more %s alerts for %s. Blocking is unchanged.", detector, addr))

	default:
		writeError(w, http.StatusBadRequest, "unknown action")
	}
}

// writeActionPage answers with a tiny self-contained page: the button was
// tapped on a phone, and a JSON blob would be a poor reply.
func writeActionPage(w http.ResponseWriter, title, detail string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `<!doctype html>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Skopos — %[1]s</title>
<style>
 body{margin:0;display:grid;place-items:center;min-height:100vh;
      font:16px/1.5 system-ui,sans-serif;background:#0f1214;color:#e6e9ea}
 main{max-width:28rem;padding:2rem;text-align:center}
 h1{font-size:1.35rem;margin:0 0 .5rem;color:#57c08a}
 p{margin:0;color:#9aa4a8}
</style>
<main><h1>%[1]s</h1><p>%[2]s</p></main>`, title, detail)
}

// AlertActions builds the notification buttons for an alert. The dispatcher
// calls it; keeping the minting here means the signing key never leaves the
// API layer.
func (s *Server) AlertActions(a model.Alert) []notify.Action {
	links := s.actionLinks(a)
	if links.Block == "" {
		return nil
	}
	return []notify.Action{
		{Label: "Block 24h", URL: links.Block},
		{Label: "Mute", URL: links.Mute},
	}
}
