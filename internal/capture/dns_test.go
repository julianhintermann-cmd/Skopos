package capture

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// dnsBuilder assembles wire-format DNS messages for the tests.
type dnsBuilder struct{ b []byte }

func (d *dnsBuilder) header(flags uint16, qd, an int) {
	d.b = append(d.b, 0x12, 0x34)
	d.b = binary.BigEndian.AppendUint16(d.b, flags)
	d.b = binary.BigEndian.AppendUint16(d.b, uint16(qd))
	d.b = binary.BigEndian.AppendUint16(d.b, uint16(an))
	d.b = binary.BigEndian.AppendUint16(d.b, 0)
	d.b = binary.BigEndian.AppendUint16(d.b, 0)
}

func (d *dnsBuilder) name(labels ...string) {
	for _, l := range labels {
		d.b = append(d.b, byte(len(l)))
		d.b = append(d.b, l...)
	}
	d.b = append(d.b, 0)
}

func (d *dnsBuilder) question(labels ...string) {
	d.name(labels...)
	d.b = binary.BigEndian.AppendUint16(d.b, 1) // A
	d.b = binary.BigEndian.AppendUint16(d.b, 1) // IN
}

// answerPtr writes an answer whose owner is a compression pointer to offset.
func (d *dnsBuilder) answerPtr(offset int, rrType uint16, rdata []byte) {
	d.b = binary.BigEndian.AppendUint16(d.b, uint16(0xc000|offset))
	d.b = binary.BigEndian.AppendUint16(d.b, rrType)
	d.b = binary.BigEndian.AppendUint16(d.b, 1)   // IN
	d.b = binary.BigEndian.AppendUint32(d.b, 300) // TTL
	d.b = binary.BigEndian.AppendUint16(d.b, uint16(len(rdata)))
	d.b = append(d.b, rdata...)
}

func TestParseDNSNamesAandAAAA(t *testing.T) {
	d := &dnsBuilder{}
	d.header(0x8180, 1, 2) // response, NOERROR
	d.question("youtube", "com")
	d.answerPtr(12, dnsTypeA, []byte{142, 250, 185, 78})
	v6 := netip.MustParseAddr("2a00:1450:4001:80f::200e").As16()
	d.answerPtr(12, dnsTypeAAAA, v6[:])

	got := parseDNSNames(d.b)
	if len(got) != 2 {
		t.Fatalf("records = %+v, want 2", got)
	}
	for _, r := range got {
		if r.Name != "youtube.com" {
			t.Errorf("name = %q, want youtube.com", r.Name)
		}
		if r.TTL != 300 {
			t.Errorf("ttl = %d, want 300", r.TTL)
		}
	}
	if got[0].Addr != netip.MustParseAddr("142.250.185.78") {
		t.Errorf("A record addr = %s", got[0].Addr)
	}
	if got[1].Addr != netip.MustParseAddr("2a00:1450:4001:80f::200e") {
		t.Errorf("AAAA record addr = %s", got[1].Addr)
	}
}

func TestParseDNSNamesUsesQuestionAcrossCNAME(t *testing.T) {
	// A real CDN answer: the question is the recognisable name, the A record
	// is owned by the CNAME target. The operator should see the former.
	d := &dnsBuilder{}
	d.header(0x8180, 1, 1)
	d.question("www", "example", "com")
	d.name("edge", "cdn", "net") // uncompressed owner, not a pointer
	d.b = binary.BigEndian.AppendUint16(d.b, dnsTypeA)
	d.b = binary.BigEndian.AppendUint16(d.b, 1)
	d.b = binary.BigEndian.AppendUint32(d.b, 60)
	d.b = binary.BigEndian.AppendUint16(d.b, 4)
	d.b = append(d.b, 203, 0, 113, 9)

	got := parseDNSNames(d.b)
	if len(got) != 1 || got[0].Name != "www.example.com" {
		t.Fatalf("records = %+v, want www.example.com", got)
	}
}

func TestParseDNSNamesMDNSWithoutQuestion(t *testing.T) {
	// mDNS announcements carry no question; the owner name is the hostname
	// we want for the device inventory. The class carries the cache-flush bit.
	d := &dnsBuilder{}
	d.header(0x8400, 0, 1)
	d.name("julian-nas", "local")
	d.b = binary.BigEndian.AppendUint16(d.b, dnsTypeA)
	d.b = binary.BigEndian.AppendUint16(d.b, 0x8001) // cache-flush | IN
	d.b = binary.BigEndian.AppendUint32(d.b, 120)
	d.b = binary.BigEndian.AppendUint16(d.b, 4)
	d.b = append(d.b, 192, 168, 1, 125)

	got := parseDNSNames(d.b)
	if len(got) != 1 || got[0].Name != "julian-nas.local" {
		t.Fatalf("records = %+v, want julian-nas.local", got)
	}
}

func TestParseDNSNamesRejectsJunk(t *testing.T) {
	d := &dnsBuilder{}
	d.header(0x8180, 1, 1)
	d.question("example", "com")
	d.answerPtr(12, dnsTypeA, []byte{1, 2, 3, 4})
	valid := d.b

	cases := map[string][]byte{
		"empty":            {},
		"short header":     {0x12, 0x34, 0x81},
		"query not answer": append([]byte{0x12, 0x34, 0x01, 0x00}, valid[4:]...),
		"nxdomain":         append([]byte{0x12, 0x34, 0x81, 0x83}, valid[4:]...),
	}
	for name, msg := range cases {
		if got := parseDNSNames(msg); len(got) != 0 {
			t.Errorf("%s: got %+v, want none", name, got)
		}
	}

	// Every truncation of a valid message must be handled without panicking.
	for i := 0; i < len(valid); i++ {
		parseDNSNames(valid[:i])
	}
}

func TestReadDNSNameRejectsPointerLoops(t *testing.T) {
	// A pointer to itself, and a forward pointer: both must be refused
	// rather than followed.
	self := []byte{0xc0, 0x0c}
	msg := make([]byte, 12)
	msg = append(msg, self...)
	if _, _, ok := readDNSName(msg, 12); ok {
		t.Error("self-referential pointer must not parse")
	}
	fwd := make([]byte, 12)
	fwd = append(fwd, 0xc0, 0x20)
	if _, _, ok := readDNSName(fwd, 12); ok {
		t.Error("forward pointer must not parse")
	}
}
