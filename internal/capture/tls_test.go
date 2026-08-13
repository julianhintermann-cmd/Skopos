package capture

import (
	"crypto/tls"
	"net"
	"regexp"
	"testing"
	"time"
)

// realClientHello produces genuine ClientHello bytes by letting Go's own TLS
// stack write a handshake into a pipe. Far better evidence than a hand-built
// fixture: if the parser survives a real stack's output, it will survive a
// browser's.
func realClientHello(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()
	client, server := net.Pipe()
	go func() {
		_ = tls.Client(client, cfg).Handshake()
		_ = client.Close()
	}()
	defer func() { _ = server.Close() }()

	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("reading ClientHello: %v", err)
	}
	return buf[:n]
}

func TestParseClientHelloRealHandshake(t *testing.T) {
	hello := realClientHello(t, &tls.Config{ServerName: "example.com", NextProtos: []string{"h2", "http/1.1"}}) //nolint:gosec // no connection is completed

	got, ok := parseClientHello(hello)
	if !ok {
		t.Fatal("a real ClientHello must parse")
	}
	if got.SNI != "example.com" {
		t.Errorf("SNI = %q, want example.com", got.SNI)
	}
	// JA4: t13d<2 digits><2 digits>h2_<12 hex>_<12 hex>
	re := regexp.MustCompile(`^t1[0-3]d\d{4}h2_[0-9a-f]{12}_[0-9a-f]{12}$`)
	if !re.MatchString(got.JA4) {
		t.Errorf("JA4 = %q, does not match the expected shape", got.JA4)
	}
}

func TestParseClientHelloWithoutSNI(t *testing.T) {
	// No ServerName: JA4 must mark the absence with "i" and still fingerprint.
	hello := realClientHello(t, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // no connection is completed
	got, ok := parseClientHello(hello)
	if !ok {
		t.Fatal("ClientHello without SNI must still parse")
	}
	if got.SNI != "" {
		t.Errorf("SNI = %q, want empty", got.SNI)
	}
	// Layout: 't' + two version digits + the SNI marker.
	if len(got.JA4) < 4 || got.JA4[3] != 'i' {
		t.Errorf("JA4 = %q, want the SNI-absent marker 'i' at index 3", got.JA4)
	}
}

func TestJA4StableAcrossCipherOrder(t *testing.T) {
	// The whole point of sorting: the same client keeps one fingerprint even
	// when it shuffles its cipher and extension order per connection.
	a := ja4(0x0304, true, []uint16{0x1301, 0x1302, 0x1303}, []uint16{0x000b, 0x000a, 0x0023}, []uint16{0x0403}, "h", "2")
	b := ja4(0x0304, true, []uint16{0x1303, 0x1301, 0x1302}, []uint16{0x0023, 0x000b, 0x000a}, []uint16{0x0403}, "h", "2")
	if a != b {
		t.Errorf("fingerprint changed with order:\n%s\n%s", a, b)
	}
	// A different cipher list must change it.
	c := ja4(0x0304, true, []uint16{0x1301}, []uint16{0x000b, 0x000a, 0x0023}, []uint16{0x0403}, "h", "2")
	if a == c {
		t.Error("different cipher lists must produce different fingerprints")
	}
}

func TestIsGREASE(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0xdada, 0xfafa} {
		if !isGREASE(v) {
			t.Errorf("%#04x should be GREASE", v)
		}
	}
	for _, v := range []uint16{0x1301, 0x0000, 0x002b, 0x0a1a} {
		if isGREASE(v) {
			t.Errorf("%#04x should not be GREASE", v)
		}
	}
}

func TestParseClientHelloRejectsJunk(t *testing.T) {
	hello := realClientHello(t, &tls.Config{ServerName: "example.com"}) //nolint:gosec // no connection is completed

	// Truncations (the split-across-segments case) and garbage must be
	// refused, never panic.
	for i := 0; i < len(hello); i++ {
		if _, ok := parseClientHello(hello[:i]); ok && i < len(hello)-1 {
			// A prefix may legitimately parse only if the handshake body is
			// complete, which it is not before the final byte.
			t.Fatalf("truncated hello at %d parsed as complete", i)
		}
	}
	for _, junk := range [][]byte{nil, {0x16}, {0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5}} {
		if _, ok := parseClientHello(junk); ok {
			t.Errorf("junk %v must not parse", junk)
		}
	}
}
