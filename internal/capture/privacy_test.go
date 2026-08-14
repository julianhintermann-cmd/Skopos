package capture

import (
	"crypto/tls"
	"testing"
	"time"
)

// The tests in this file exist because capture.dns and capture.sni were
// documented, defaulted to true and read by nothing: the parsers ran whatever
// the configuration said. Each one asserts both halves of a switch, so a gate
// that is quietly dropped again fails here rather than in a household's
// database.

// dnsResponseFrame builds an Ethernet frame carrying a DNS response for
// youtube.com from port 53.
func dnsResponseFrame() []byte {
	d := &dnsBuilder{}
	d.header(0x8180, 1, 1) // response, NOERROR
	d.question("youtube", "com")
	d.answerPtr(12, dnsTypeA, []byte{142, 250, 185, 78})
	return ethFrame(etherIPv4, ipv4(ipProtoUDP, append(udp(53, 40000), d.b...)))
}

// tlsClientHelloFrame builds an Ethernet frame carrying a real ClientHello to
// port 443.
func tlsClientHelloFrame(t *testing.T) []byte {
	t.Helper()
	hello := realClientHello(t, &tls.Config{ServerName: "example.com", NextProtos: []string{"h2"}}) //nolint:gosec // no connection is completed
	return ethFrame(etherIPv4, ipv4(ipProtoTCP, append(tcp(40000, 443, 0x18), hello...)))
}

// setPayloadParsing installs a setting for one test and restores the previous
// one, so the process-wide switch cannot leak between tests.
func setPayloadParsing(t *testing.T, p PayloadParsing) {
	t.Helper()
	prev := payloadParsing.Load()
	payloadParsing.Store(&p)
	t.Cleanup(func() { payloadParsing.Store(prev) })
}

func TestCaptureDNSSwitchGovernsNameParsing(t *testing.T) {
	frame := dnsResponseFrame()

	on, ok := parseFrame(frame, time.Unix(1, 0), PayloadParsing{DNS: true, SNI: true})
	if !ok {
		t.Fatal("expected parse ok with DNS on")
	}
	if len(on.Names) != 1 || on.Names[0].Name != "youtube.com" {
		t.Fatalf("with capture.dns on, names = %+v, want youtube.com", on.Names)
	}

	off, ok := parseFrame(frame, time.Unix(1, 0), PayloadParsing{DNS: false, SNI: true})
	if !ok {
		t.Fatal("a DNS packet must still count as a flow with capture.dns off")
	}
	if len(off.Names) != 0 {
		t.Errorf("capture.dns is off and the lookup was recorded anyway: %+v", off.Names)
	}
}

func TestCaptureDNSSwitchGovernsDNSOverTCP(t *testing.T) {
	d := &dnsBuilder{}
	d.header(0x8180, 1, 1)
	d.question("youtube", "com")
	d.answerPtr(12, dnsTypeA, []byte{142, 250, 185, 78})
	// DNS over TCP prefixes the message with its 2-byte length.
	msg := append([]byte{byte(len(d.b) >> 8), byte(len(d.b))}, d.b...)
	frame := ethFrame(etherIPv4, ipv4(ipProtoTCP, append(tcp(53, 40000, 0x18), msg...)))

	on, _ := parseFrame(frame, time.Unix(1, 0), PayloadParsing{DNS: true})
	if len(on.Names) != 1 || on.Names[0].Name != "youtube.com" {
		t.Fatalf("with capture.dns on, names = %+v, want youtube.com", on.Names)
	}

	off, ok := parseFrame(frame, time.Unix(1, 0), PayloadParsing{DNS: false})
	if !ok {
		t.Fatal("expected parse ok with DNS off")
	}
	if len(off.Names) != 0 {
		t.Errorf("capture.dns is off and DNS-over-TCP was read anyway: %+v", off.Names)
	}
}

func TestCaptureDNSSwitchGovernsMDNS(t *testing.T) {
	d := &dnsBuilder{}
	d.header(0x8400, 0, 1) // mDNS response, no question section
	d.name("printer", "local")
	d.b = append(d.b, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 120, 0, 4, 192, 168, 1, 50)
	frame := ethFrame(etherIPv4, ipv4(ipProtoUDP, append(udp(5353, 5353), d.b...)))

	on, _ := parseFrame(frame, time.Unix(1, 0), PayloadParsing{DNS: true})
	if len(on.Names) == 0 {
		t.Fatal("with capture.dns on, an mDNS announcement should yield a name")
	}

	off, _ := parseFrame(frame, time.Unix(1, 0), PayloadParsing{DNS: false})
	if len(off.Names) != 0 {
		t.Errorf("capture.dns is off and the mDNS name was read anyway: %+v", off.Names)
	}
}

func TestCaptureSNISwitchGovernsClientHelloParsing(t *testing.T) {
	frame := tlsClientHelloFrame(t)

	on, ok := parseFrame(frame, time.Unix(1, 0), PayloadParsing{SNI: true})
	if !ok {
		t.Fatal("expected parse ok with SNI on")
	}
	if on.DstName != "example.com" {
		t.Fatalf("with capture.sni on, DstName = %q, want example.com", on.DstName)
	}
	if on.JA4 == "" {
		t.Fatal("with capture.sni on, the JA4 fingerprint should be present")
	}

	off, ok := parseFrame(frame, time.Unix(1, 0), PayloadParsing{SNI: false})
	if !ok {
		t.Fatal("a TLS packet must still count as a flow with capture.sni off")
	}
	if off.DstName != "" || len(off.Names) != 0 {
		t.Errorf("capture.sni is off and the server name was recorded anyway: %q %+v",
			off.DstName, off.Names)
	}
	// The JA4 comes out of the same ClientHello, which is not read at all.
	if off.JA4 != "" {
		t.Errorf("capture.sni is off and the ClientHello was still fingerprinted: %q", off.JA4)
	}
}

func TestSwitchesOffStillCountTheTraffic(t *testing.T) {
	// Turning the parsers off is a privacy choice, not a blindfold: the flow
	// itself — who talked to whom, how much — must survive intact.
	off := PayloadParsing{}
	p, ok := parseFrame(tlsClientHelloFrame(t), time.Unix(1, 0), off)
	if !ok {
		t.Fatal("expected parse ok")
	}
	if p.SrcIP.String() != "192.168.1.10" || p.DstIP.String() != "9.9.9.9" {
		t.Errorf("addrs = %s → %s", p.SrcIP, p.DstIP)
	}
	if p.DstPort != 443 {
		t.Errorf("dst port = %d, want 443", p.DstPort)
	}
	if p.Size == 0 {
		t.Error("the packet's bytes must still be counted")
	}
}

func TestSetPayloadParsingReachesTheExportedParsers(t *testing.T) {
	// ParseFrame and ParseIPPacket are what the AF_PACKET source calls, so
	// the switch has to reach them and not merely the internal helpers.
	frame := dnsResponseFrame()
	packet := frame[14:] // the bare IP packet, as a tunnel delivers it

	setPayloadParsing(t, PayloadParsing{DNS: true, SNI: true})
	if p, _ := ParseFrame(frame, time.Unix(1, 0)); len(p.Names) != 1 {
		t.Fatalf("ParseFrame with DNS on: names = %+v, want 1", p.Names)
	}
	if p, _ := ParseIPPacket(packet, time.Unix(1, 0)); len(p.Names) != 1 {
		t.Fatalf("ParseIPPacket with DNS on: names = %+v, want 1", p.Names)
	}

	setPayloadParsing(t, PayloadParsing{DNS: false, SNI: false})
	if p, _ := ParseFrame(frame, time.Unix(1, 0)); len(p.Names) != 0 {
		t.Errorf("ParseFrame ignored capture.dns: %+v", p.Names)
	}
	if p, _ := ParseIPPacket(packet, time.Unix(1, 0)); len(p.Names) != 0 {
		t.Errorf("ParseIPPacket ignored capture.dns: %+v", p.Names)
	}
}

func TestPayloadParsingDefaultsToOnWhenUnset(t *testing.T) {
	// An unconfigured process must behave as the function names say, or the
	// unit tests and the demo source would quietly stop seeing names.
	setPayloadParsing(t, PayloadParsing{DNS: false, SNI: false})
	payloadParsing.Store(nil)
	if got := currentPayloadParsing(); !got.DNS || !got.SNI {
		t.Errorf("unset payload parsing = %+v, want both on", got)
	}
}
