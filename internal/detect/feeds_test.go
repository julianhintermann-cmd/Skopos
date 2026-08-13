package detect

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// fakeFetcher serves canned bodies and honours ETags.
type fakeFetcher struct {
	bodies map[string]string
	etags  map[string]string
	calls  map[string]int
}

func (f *fakeFetcher) Fetch(_ context.Context, url, etag string) (FeedResult, error) {
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[url]++
	want := f.etags[url]
	if etag != "" && etag == want {
		return FeedResult{NotModified: true, ETag: etag}, nil
	}
	return FeedResult{Body: []byte(f.bodies[url]), ETag: want}, nil
}

func extPkt(src, dst string) flow.Packet {
	return flow.Packet{
		Time: time.Unix(1000, 0), SrcIP: netip.MustParseAddr(src), DstIP: netip.MustParseAddr(dst),
		Proto: model.ProtoTCP, DstPort: 443, Size: 100,
	}
}

func internalPred() func(netip.Addr) bool {
	return func(a netip.Addr) bool {
		return netip.MustParsePrefix("192.168.0.0/16").Contains(a)
	}
}

func TestFeedsMatchAndRaise(t *testing.T) {
	c := &collector{}
	fetch := &fakeFetcher{
		bodies: map[string]string{"https://x/list": "203.0.113.0/24\n# comment\n198.51.100.5\n"},
		etags:  map[string]string{"https://x/list": "v1"},
	}
	f := NewFeeds(FeedsConfig{
		Lists: []string{"https://x/list"}, Severity: model.SeverityCritical,
		IsInternal: internalPred(),
	}, c, fetch, func() time.Time { return time.Unix(1000, 0) })

	n, err := f.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if n == 0 || f.Count() == 0 {
		t.Fatalf("expected loaded prefixes, got n=%d count=%d", n, f.Count())
	}

	// An outbound flow to a blocklisted external address must fire.
	f.Observe(extPkt("192.168.1.10", "203.0.113.7"))
	if c.count() != 1 {
		t.Fatalf("expected 1 feed finding, got %d", c.count())
	}
	if c.findings[0].Source.String() != "203.0.113.7" {
		t.Errorf("finding source = %s, want the external peer 203.0.113.7", c.findings[0].Source)
	}

	// A flow to a non-listed address must not.
	f.Observe(extPkt("192.168.1.10", "9.9.9.9"))
	if c.count() != 1 {
		t.Errorf("non-listed address should not fire, count=%d", c.count())
	}
}

func TestFeedsETagAvoidsRefetchAndKeepsCoverage(t *testing.T) {
	c := &collector{}
	fetch := &fakeFetcher{
		bodies: map[string]string{
			"https://a/list": "203.0.113.0/24\n",
			"https://b/list": "198.51.100.0/24\n",
		},
		etags: map[string]string{"https://a/list": "a1", "https://b/list": "b1"},
	}
	f := NewFeeds(FeedsConfig{
		Lists:      []string{"https://a/list", "https://b/list"},
		Severity:   model.SeverityCritical,
		IsInternal: internalPred(),
	}, c, fetch, func() time.Time { return time.Unix(1000, 0) })

	if _, err := f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := f.Count()

	// Second refresh: both feeds now return 304. Coverage must be unchanged.
	if _, err := f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.Count() != first {
		t.Errorf("coverage changed after 304 refresh: %d → %d", first, f.Count())
	}
	// Both feeds must still match after the 304 round.
	f.Observe(extPkt("192.168.1.10", "203.0.113.1"))
	f.Observe(extPkt("192.168.1.10", "198.51.100.1"))
	if c.count() != 2 {
		t.Errorf("both feeds should still match after 304, got %d hits", c.count())
	}
}

func TestFeedsFailureKeepsPreviousCoverage(t *testing.T) {
	c := &collector{}
	fetch := &fakeFetcher{
		bodies: map[string]string{"firehol_level1": "203.0.113.0/24\n"},
		etags:  map[string]string{builtinFeeds["firehol_level1"]: "v1"},
	}
	// Map the built-in URL to the body key for the fake.
	fetch.bodies[builtinFeeds["firehol_level1"]] = "203.0.113.0/24\n"

	f := NewFeeds(FeedsConfig{
		Lists: []string{"firehol_level1"}, Severity: model.SeverityCritical,
		IsInternal: internalPred(),
	}, c, fetch, func() time.Time { return time.Unix(1000, 0) })

	if _, err := f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.Count() == 0 {
		t.Fatal("expected coverage after first refresh")
	}
	before := f.Count()

	// Now make fetch fail; coverage must survive.
	failing := NewFeeds(FeedsConfig{Lists: []string{"nonexistent_feed"}}, c, fetch, nil)
	if _, err := failing.Refresh(context.Background()); err == nil {
		t.Error("expected error naming the unknown feed")
	}
	if f.Count() != before {
		t.Errorf("coverage should be unchanged, %d → %d", before, f.Count())
	}
}

func TestNewDeviceReports(t *testing.T) {
	c := &collector{}
	d := NewNewDevice(NewDeviceConfig{Severity: model.SeverityInfo}, c)
	d.Report("aa:bb:cc:dd:ee:ff", "192.168.1.55")
	if c.count() != 1 {
		t.Fatalf("expected 1 finding, got %d", c.count())
	}
	f := c.findings[0]
	if f.Detector != "new_device" || f.Source.String() != "192.168.1.55" {
		t.Errorf("unexpected finding: %+v", f)
	}
}

// TestFeedsIgnoresBogonMatches reproduces the FireHOL-Level-1 noise: the list
// deliberately contains multicast, broadcast, CGNAT and RFC1918 space (border
// bogons). Inside a LAN those are mDNS, SSDP, DHCP and carrier-NAT traffic and
// must never raise a finding — while genuine public blocklisted peers still do.
func TestFeedsIgnoresBogonMatches(t *testing.T) {
	fetch := &fakeFetcher{bodies: map[string]string{
		"https://feed.example/list": "224.0.0.0/3\n100.64.0.0/10\n10.0.0.0/8\n45.153.34.0/24\n",
	}}
	var findings []Finding
	f := NewFeeds(FeedsConfig{
		Lists:      []string{"https://feed.example/list"},
		Severity:   model.SeverityCritical,
		IsInternal: internalPred(),
	}, SinkFunc(func(fi Finding) { findings = append(findings, fi) }), fetch, nil)
	if _, err := f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Everyday LAN chatter that FireHOL's bogon entries would match.
	f.Observe(extPkt("192.168.1.10", "239.255.255.250")) // SSDP multicast
	f.Observe(extPkt("192.168.1.10", "224.0.0.251"))     // mDNS
	f.Observe(extPkt("192.168.1.10", "255.255.255.255")) // DHCP broadcast
	f.Observe(extPkt("192.168.1.10", "100.67.0.225"))    // CGNAT peer
	if len(findings) != 0 {
		t.Fatalf("bogon traffic raised %d findings: %+v", len(findings), findings)
	}

	// A real blocklisted public address still fires.
	f.Observe(extPkt("45.153.34.47", "192.168.1.10"))
	if len(findings) != 1 || findings[0].Source != netip.MustParseAddr("45.153.34.47") {
		t.Fatalf("expected one finding for the public peer, got %+v", findings)
	}
}
