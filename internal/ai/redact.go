package ai

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Everything that leaves this machine passes through this file.
//
// Skopos' README says captured traffic never leaves the NAS. The AI
// integration is the single exception to that sentence, which makes the code
// deciding what may leave the most consequential code in the feature — more so
// than the provider abstraction or the sealing, both of which are ordinary
// engineering. So the decision lives in one place, operates on typed structs
// rather than on an interpolated prompt string, and is guarded by Clean below,
// which re-reads the finished payload and refuses to send it if a banned shape
// survived.
//
// The reason for the care is not the operator. It is everyone else: a home
// network carries the browsing of a household, and the partner, the children
// and the guests did not agree to any of this. Device labels are typed by hand
// and are usually people's names. MAC addresses are globally unique and stable
// for the life of the hardware. Neither adds anything an explanation needs, so
// neither is ever sent.

const (
	// MaxPayloadBytes caps one prompt. A ceiling enforced in code, mirroring
	// the cloudflare client's maxBody: without it, "summarise this device"
	// quietly becomes "upload the flow table".
	MaxPayloadBytes = 32 << 10

	// MaxDestinations bounds how many hostnames one device explanation may
	// carry. Ten is enough to characterise a device and far short of a
	// browsing history.
	MaxDestinations = 10
)

// macRE matches a MAC address in either usual separator. Used by Clean as a
// last line of defence, not as the primary mechanism — the primary mechanism is
// that no field in the request structs below ever holds one.
//
// The two separators are spelled out as an alternation rather than captured and
// back-referenced because Go's RE2 has no backreferences. The cost is that
// aa:bb-cc:dd-ee:ff would not match; nothing produces that, and Clean is the
// backstop rather than the gate.
var macRE = regexp.MustCompile(`(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b|\b[0-9a-f]{2}(?:-[0-9a-f]{2}){5}\b`)

// keyRE matches the documented API-key prefixes of the three providers, so a
// key can never be echoed into a prompt.
var keyRE = regexp.MustCompile(`\b(sk-ant-|sk-or-|sk-)[A-Za-z0-9_\-]{16,}`)

// fullIPv4RE matches a dotted quad whose final octet is a number. Addresses are
// always reduced to a shape by Addr below, so a complete one in a finished
// payload means something bypassed the redactor.
var fullIPv4RE = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// Addr reduces an address to its shape: enough to say "a device on your LAN"
// or "an address in this /48", not enough to identify the host.
//
// This applies to external addresses too, not only to the household's own. The
// task is explaining what a port scan is, and the final octet contributes
// nothing to that — while a public address, once sent, geolocates a subscriber
// and is one join away from an identity.
func Addr(a netip.Addr) string {
	a = a.Unmap()
	if !a.IsValid() {
		return "an address"
	}
	if a.Is4() {
		b := a.As4()
		return fmt.Sprintf("%d.%d.%d.x", b[0], b[1], b[2])
	}
	p, err := a.Prefix(48)
	if err != nil {
		return "an IPv6 address"
	}
	return p.String()
}

// Pseudonym names a device without naming its owner. The caller supplies a
// stable index; "device-7" carries every bit of analytical signal that "Anna's
// iPhone" does, and none of the identification.
func Pseudonym(i int) string { return fmt.Sprintf("device-%d", i) }

// AlertFacts is the sanitised description of one alert — the safe set. Every
// field here is either a Skopos-internal category, a count, or a shape.
type AlertFacts struct {
	Detector string `json:"detector"`
	Severity string `json:"severity"`
	// Source is a shape from Addr, never a full address.
	Source string `json:"source"`
	// Country is the ISO code GeoIP resolved, when it did.
	Country string `json:"country,omitempty"`
	Port    int    `json:"port,omitempty"`
	Count   int    `json:"count,omitempty"`
	// Detail is the detector's own sentence, scrubbed.
	Detail string `json:"detail,omitempty"`
}

// DeviceFacts is the sanitised description of one device. It carries the
// manufacturer — which is a property of the hardware — and never the label the
// operator typed or the hostname DHCP reported, both of which routinely name a
// person.
type DeviceFacts struct {
	Pseudonym string `json:"device"`
	Vendor    string `json:"vendor,omitempty"`
	// Destinations are hostnames observed on the wire. These are the sensitive
	// part of this struct and the reason device explanation is a separate,
	// explicitly-labelled action rather than something Skopos does on its own.
	Destinations []string `json:"destinations,omitempty"`
}

// ScrubAlert builds the sanitised facts for one alert.
func ScrubAlert(detector, severity, detail, country string, src netip.Addr, port, count int) AlertFacts {
	return AlertFacts{
		Detector: detector,
		Severity: severity,
		Source:   Addr(src),
		Country:  country,
		Port:     port,
		Count:    count,
		Detail:   Text(detail),
	}
}

// ScrubDevice builds the sanitised facts for one device. The label and hostname
// are not parameters, so a caller cannot pass them by mistake.
func ScrubDevice(index int, vendor string, destinations []string) DeviceFacts {
	if len(destinations) > MaxDestinations {
		destinations = destinations[:MaxDestinations]
	}
	out := make([]string, 0, len(destinations))
	for _, d := range destinations {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	return DeviceFacts{
		Pseudonym:    Pseudonym(index),
		Vendor:       Text(vendor),
		Destinations: out,
	}
}

// Text scrubs a free-text string that Skopos itself generated — a detector's
// detail line, a vendor name. Detector text is built from templates and should
// never contain a MAC or a key, so a hit here means a template changed; the
// value is replaced rather than the request refused, because a scrubbed
// explanation is more useful than none.
func Text(s string) string {
	s = macRE.ReplaceAllString(s, "[mac]")
	s = keyRE.ReplaceAllString(s, "[redacted]")
	s = fullIPv4RE.ReplaceAllStringFunc(s, func(m string) string {
		a, err := netip.ParseAddr(m)
		if err != nil {
			return m
		}
		return Addr(a)
	})
	return s
}

// Clean is the guard, run on the finished payload immediately before it is
// sent. It re-reads what the structs above produced and refuses the request if
// a banned shape survived.
//
// It is redundant by design. Every field is already sanitised at construction,
// so Clean should never fire — and if it ever does, the correct outcome is a
// failed request rather than a quiet leak, because by then the alternative is
// bytes on somebody else's disk.
func Clean(payload string) error {
	if len(payload) > MaxPayloadBytes {
		return fmt.Errorf("ai: payload is %d bytes, over the %d-byte ceiling",
			len(payload), MaxPayloadBytes)
	}
	if macRE.MatchString(payload) {
		return fmt.Errorf("ai: refusing to send — payload contains a MAC address")
	}
	if keyRE.MatchString(payload) {
		return fmt.Errorf("ai: refusing to send — payload contains something shaped like an API key")
	}
	if m := fullIPv4RE.FindString(payload); m != "" {
		return fmt.Errorf("ai: refusing to send — payload contains a full IP address (%s)", m)
	}
	return nil
}
