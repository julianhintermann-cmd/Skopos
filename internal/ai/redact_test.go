package ai

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// The redaction tests are the ones that matter most in this package. Skopos
// advertises that captured traffic never leaves the NAS; this is the one
// feature that breaks that sentence on purpose, so what it may send has to be
// pinned by tests rather than by the care of whoever edits a prompt next.
//
// The shape of these tests is deliberate: they assert on the *finished payload*
// rather than on the redaction helpers, because a helper that works perfectly
// while a caller bypasses it is the failure mode being guarded against.

func TestAddrKeepsShapeAndDropsTheHost(t *testing.T) {
	cases := []struct{ in, want string }{
		{"192.168.1.47", "192.168.1.x"},
		{"192.168.1.1", "192.168.1.x"},
		{"8.8.8.8", "8.8.8.x"},
		{"203.0.113.199", "203.0.113.x"},
		// v4-mapped v6 must reduce like the v4 address it is, not leak the
		// full form through the v6 branch.
		{"::ffff:192.168.1.47", "192.168.1.x"},
	}
	for _, c := range cases {
		if got := Addr(netip.MustParseAddr(c.in)); got != c.want {
			t.Errorf("Addr(%s) = %q, want %q", c.in, got, c.want)
		}
	}

	// IPv6 keeps the routing prefix and loses the interface identifier, which
	// on many networks is derived from the MAC.
	got := Addr(netip.MustParseAddr("2001:db8:1234:5678:9abc:def0:1234:5678"))
	if !strings.HasPrefix(got, "2001:db8:1234::/48") {
		t.Errorf("Addr(v6) = %q, want the /48", got)
	}
	if strings.Contains(got, "9abc") {
		t.Errorf("Addr(v6) = %q, leaked the interface identifier", got)
	}

	if got := Addr(netip.Addr{}); got != "an address" {
		t.Errorf("Addr(invalid) = %q", got)
	}
}

// The names people type are the ones that identify people. ScrubDevice does not
// take a label or a hostname as a parameter, so this test asserts on the type's
// behaviour: what a caller passes as vendor is all that can reach the wire.
func TestScrubDeviceCarriesNoIdentity(t *testing.T) {
	d := ScrubDevice(7, "Samsung Electronics", []string{
		"api.spotify.com", "  ", "samsungcloudsolution.com",
	})
	if d.Pseudonym != "device-7" {
		t.Errorf("pseudonym = %q, want device-7", d.Pseudonym)
	}
	if len(d.Destinations) != 2 {
		t.Errorf("destinations = %v, want the blank dropped", d.Destinations)
	}

	body, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"Anna", "iPhone", "Kids", "MacBook"} {
		if strings.Contains(string(body), banned) {
			t.Errorf("payload carries %q: %s", banned, body)
		}
	}
}

// A device with a long history must not turn one click into a browsing-history
// upload.
func TestScrubDeviceCapsDestinations(t *testing.T) {
	many := make([]string, 200)
	for i := range many {
		many[i] = "host.example"
	}
	if got := len(ScrubDevice(1, "", many).Destinations); got != MaxDestinations {
		t.Errorf("destinations = %d, want the cap of %d", got, MaxDestinations)
	}
}

// Detector detail lines are built from templates. If a template ever starts
// interpolating an address or a MAC, the scrubber catches it rather than the
// operator discovering it in a provider's logs.
func TestTextScrubsIdentifiers(t *testing.T) {
	cases := []struct{ in, wantAbsent, wantPresent string }{
		{"host aa:bb:cc:dd:ee:ff scanned", "aa:bb:cc:dd:ee:ff", "[mac]"},
		{"host AA-BB-CC-DD-EE-FF scanned", "AA-BB-CC-DD-EE-FF", "[mac]"},
		{"key sk-ant-api03-abcdefghijklmnopqrstuvwxyz leaked", "abcdefghijklmnop", "[redacted]"},
		{"key sk-or-v1-abcdefghijklmnopqrstuvwxyz leaked", "abcdefghijklmnop", "[redacted]"},
		{"23 ports from 192.168.1.47", "192.168.1.47", "192.168.1.x"},
	}
	for _, c := range cases {
		got := Text(c.in)
		if strings.Contains(got, c.wantAbsent) {
			t.Errorf("Text(%q) = %q, still carries %q", c.in, got, c.wantAbsent)
		}
		if !strings.Contains(got, c.wantPresent) {
			t.Errorf("Text(%q) = %q, want it to contain %q", c.in, got, c.wantPresent)
		}
	}
}

// Clean is the last gate. These are the payloads it exists to stop.
func TestCleanRefusesBannedShapes(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{"mac", `{"detail":"device aa:bb:cc:dd:ee:ff joined"}`},
		{"openai key", `{"detail":"sk-proj-abcdefghijklmnopqrstuvwx"}`},
		{"anthropic key", `{"detail":"sk-ant-api03-abcdefghijklmnopqrst"}`},
		{"full address", `{"source":"192.168.1.47"}`},
		{"oversize", `{"x":"` + strings.Repeat("a", MaxPayloadBytes) + `"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := Clean(c.payload); err == nil {
				t.Error("Clean accepted a payload it must refuse")
			}
		})
	}

	// And it must not fire on the payloads the redactor actually produces,
	// or the feature never works at all.
	ok := `{"detector":"portscan","source":"192.168.1.x","port":22,"count":23}`
	if err := Clean(ok); err != nil {
		t.Errorf("Clean rejected a properly redacted payload: %v", err)
	}
}

// The end-to-end shape: what ScrubAlert produces must survive Clean. If these
// two ever disagree, the feature is either leaking or permanently broken, and
// this test says which.
func TestScrubbedAlertPassesTheGate(t *testing.T) {
	a := ScrubAlert(
		"portscan", "critical",
		"23 ports on 4 targets from 203.0.113.199 (aa:bb:cc:dd:ee:ff)",
		"NL", netip.MustParseAddr("203.0.113.199"), 22, 23,
	)
	body, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := Clean(string(body)); err != nil {
		t.Fatalf("a scrubbed alert must pass the gate: %v\npayload: %s", err, body)
	}
	if strings.Contains(string(body), "203.0.113.199") {
		t.Errorf("payload carries the full source address: %s", body)
	}
	if strings.Contains(string(body), "aa:bb:cc:dd:ee:ff") {
		t.Errorf("payload carries a MAC: %s", body)
	}
	if !strings.Contains(string(body), "203.0.113.x") {
		t.Errorf("payload lost the address shape entirely: %s", body)
	}
}

// Same contract for an episode, plus the two things an episode adds: the span
// is a duration and never a timestamp, and repeated detail lines collapse. A
// blocklist episode is fifteen copies of one sentence, and paying a provider
// by the token to read the same sentence fifteen times is waste on top of
// exposure.
func TestScrubbedIncidentPassesTheGate(t *testing.T) {
	inc := ScrubIncident(
		[]string{"feeds"}, "critical", "CA",
		netip.MustParseAddr("203.0.113.199"), 15, 5*time.Hour+2*time.Minute,
		[]string{
			"matched a configured IP blocklist feed",
			"matched a configured IP blocklist feed",
			"seen from 203.0.113.199 (aa:bb:cc:dd:ee:ff)",
			"matched a configured IP blocklist feed",
			"a fourth distinct line that must be dropped by the cap",
		},
	)
	body, err := json.Marshal(inc)
	if err != nil {
		t.Fatal(err)
	}
	if err := Clean(string(body)); err != nil {
		t.Fatalf("a scrubbed episode must pass the gate: %v\npayload: %s", err, body)
	}
	if strings.Contains(string(body), "203.0.113.199") {
		t.Errorf("payload carries the full source address: %s", body)
	}
	if strings.Contains(string(body), "aa:bb:cc:dd:ee:ff") {
		t.Errorf("payload carries a MAC: %s", body)
	}
	if inc.SpanMinutes != 302 {
		t.Errorf("span = %d minutes, want 302", inc.SpanMinutes)
	}
	if len(inc.Samples) != MaxSamples {
		t.Fatalf("samples = %d, want %d: %q", len(inc.Samples), MaxSamples, inc.Samples)
	}
	seen := map[string]bool{}
	for _, s := range inc.Samples {
		if seen[s] {
			t.Errorf("duplicate sample survived: %q", s)
		}
		seen[s] = true
	}
}

// An episode with no alerts attached — every one pruned by retention — still
// has to produce a sendable payload rather than a nil-deref or an empty prompt.
func TestScrubIncidentWithoutSamples(t *testing.T) {
	inc := ScrubIncident(nil, "info", "", netip.Addr{}, 1, 0, nil)
	if inc.Samples != nil {
		t.Errorf("samples = %q, want none", inc.Samples)
	}
	if inc.SpanMinutes != 0 {
		t.Errorf("span = %d, want 0", inc.SpanMinutes)
	}
	if inc.Source != "an address" {
		t.Errorf("source = %q, want the invalid-address placeholder", inc.Source)
	}
	body, err := json.Marshal(inc)
	if err != nil {
		t.Fatal(err)
	}
	if err := Clean(string(body)); err != nil {
		t.Fatalf("an empty episode must still pass the gate: %v", err)
	}
}
