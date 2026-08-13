package capture

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
	"github.com/julianhintermann-cmd/skopos/internal/model"
)

type fakeDeviceStore struct {
	seen  map[string]bool
	addr  map[string]string // MAC -> last address written
	host  map[string]string // MAC -> last hostname written
	calls map[string]int    // MAC -> number of upserts
}

func (f *fakeDeviceStore) UpsertDevice(_ context.Context, mac, ip, hostname, _ string) (bool, error) {
	if f.seen == nil {
		f.seen = map[string]bool{}
		f.addr = map[string]string{}
		f.host = map[string]string{}
		f.calls = map[string]int{}
	}
	isNew := !f.seen[mac]
	f.seen[mac] = true
	f.addr[mac] = ip
	f.calls[mac]++
	if hostname != "" {
		f.host[mac] = hostname
	}
	return isNew, nil
}

func lanClassifier() *flow.Classifier {
	return flow.NewClassifier([]string{"192.168.0.0/16"})
}

func TestDeviceTrackerInventoriesInternalOnly(t *testing.T) {
	store := &fakeDeviceStore{}
	tr := NewDeviceTracker(lanClassifier(), store, nil, time.Second)

	// LAN device talking out: only the internal MAC/IP should be inventoried.
	tr.Observe(flow.Packet{
		SrcIP: netip.MustParseAddr("192.168.1.10"), DstIP: netip.MustParseAddr("9.9.9.9"),
		SrcMAC: "aa:aa:aa:aa:aa:aa", Proto: model.ProtoTCP,
	})
	// Purely external packet: nothing to inventory.
	tr.Observe(flow.Packet{
		SrcIP: netip.MustParseAddr("8.8.8.8"), DstIP: netip.MustParseAddr("9.9.9.9"),
		SrcMAC: "bb:bb:bb:bb:bb:bb", Proto: model.ProtoTCP,
	})

	if err := tr.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.seen["aa:aa:aa:aa:aa:aa"] != true {
		t.Error("internal device should have been inventoried")
	}
	if store.seen["bb:bb:bb:bb:bb:bb"] {
		t.Error("external MAC must not be inventoried")
	}
}

func TestDeviceTrackerFiresOnNewOnce(t *testing.T) {
	store := &fakeDeviceStore{}
	var newMACs []string
	tr := NewDeviceTracker(lanClassifier(), store, func(mac, _ string) {
		newMACs = append(newMACs, mac)
	}, time.Second)

	pkt := flow.Packet{
		SrcIP: netip.MustParseAddr("192.168.1.10"), DstIP: netip.MustParseAddr("9.9.9.9"),
		SrcMAC: "aa:aa:aa:aa:aa:aa", Proto: model.ProtoTCP,
	}
	tr.Observe(pkt)
	_ = tr.Flush(context.Background())
	tr.Observe(pkt)
	_ = tr.Flush(context.Background())

	if len(newMACs) != 1 {
		t.Errorf("onNew fired %d times, want exactly 1", len(newMACs))
	}
}

func TestDeviceTrackerDebouncesWrites(t *testing.T) {
	store := &fakeDeviceStore{}
	tr := NewDeviceTracker(lanClassifier(), store, nil, time.Second)

	// Many packets from the same device before a flush should collapse to one
	// pending sighting.
	for i := 0; i < 100; i++ {
		tr.Observe(flow.Packet{
			SrcIP: netip.MustParseAddr("192.168.1.10"), DstIP: netip.MustParseAddr("9.9.9.9"),
			SrcMAC: "aa:aa:aa:aa:aa:aa", Proto: model.ProtoTCP,
		})
	}
	tr.mu.Lock()
	pending := len(tr.pending)
	tr.mu.Unlock()
	if pending != 1 {
		t.Errorf("pending sightings = %d, want 1 (debounced)", pending)
	}
}

// A frame addressed to the broadcast or to a multicast group carries a
// link-layer address that belongs to no machine. Filing those as neighbours
// produced inventory rows like "192.168.1.255 (ff:ff:ff:ff:ff:ff)".
func TestDeviceTrackerSkipsGroupAddresses(t *testing.T) {
	store := &fakeDeviceStore{}
	tr := NewDeviceTracker(lanClassifier(), store, nil, time.Second)

	// A subnet broadcast: parse yields no MAC for a group address, so the
	// tracker has nothing to file even though the address is internal.
	tr.Observe(flow.Packet{
		SrcIP: netip.MustParseAddr("192.168.1.10"), DstIP: netip.MustParseAddr("192.168.1.255"),
		SrcMAC: "aa:aa:aa:aa:aa:aa", DstMAC: "", Proto: model.ProtoUDP,
	})
	// mDNS to a multicast group, with the sender's real MAC: the sender is a
	// device, the group address is not.
	tr.Observe(flow.Packet{
		SrcIP: netip.MustParseAddr("192.168.1.11"), DstIP: netip.MustParseAddr("224.0.0.251"),
		SrcMAC: "bb:bb:bb:bb:bb:bb", Proto: model.ProtoUDP,
	})

	if err := tr.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := store.addr["aa:aa:aa:aa:aa:aa"]; got != "192.168.1.10" {
		t.Errorf("sender should be inventoried by its own address, got %q", got)
	}
	if len(store.seen) != 2 {
		t.Errorf("inventoried %d entries, want 2 (the two senders only)", len(store.seen))
	}
	for mac, ip := range store.addr {
		if ip == "192.168.1.255" || ip == "224.0.0.251" {
			t.Errorf("%s: group address %s must not be inventoried", mac, ip)
		}
	}
}

// A dual-stack machine is one device with two addresses. Both are recorded,
// and neither overwrites the other.
func TestDeviceTrackerRecordsBothFamilies(t *testing.T) {
	store := &fakeDeviceStore{}
	c := flow.NewClassifier([]string{"192.168.0.0/16", "fd00::/8", "fe80::/10"})
	tr := NewDeviceTracker(c, store, nil, time.Second)

	tr.Observe(flow.Packet{
		SrcIP: netip.MustParseAddr("192.168.1.10"), DstIP: netip.MustParseAddr("9.9.9.9"),
		SrcMAC: "aa:aa:aa:aa:aa:aa", Proto: model.ProtoTCP,
	})
	tr.Observe(flow.Packet{
		SrcIP: netip.MustParseAddr("fd00::10"), DstIP: netip.MustParseAddr("fd00::1"),
		SrcMAC: "aa:aa:aa:aa:aa:aa", Proto: model.ProtoTCP,
	})
	if err := tr.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := store.calls["aa:aa:aa:aa:aa:aa"]; got != 2 {
		t.Fatalf("upserts for the device = %d, want 2 (one per family)", got)
	}
}

// Every interface has a fe80:: address and most LAN traffic uses it, but it
// identifies nothing. A routable address the device also holds wins.
func TestDeviceTrackerPrefersRoutableIPv6(t *testing.T) {
	store := &fakeDeviceStore{}
	c := flow.NewClassifier([]string{"fd00::/8", "fe80::/10"})
	tr := NewDeviceTracker(c, store, nil, time.Second)

	tr.Observe(flow.Packet{
		SrcIP: netip.MustParseAddr("fe80::1122:33ff:fe44:5566"), DstIP: netip.MustParseAddr("fe80::1"),
		SrcMAC: "aa:aa:aa:aa:aa:aa", Proto: model.ProtoUDP,
	})
	tr.Observe(flow.Packet{
		SrcIP: netip.MustParseAddr("fd00::10"), DstIP: netip.MustParseAddr("fd00::1"),
		SrcMAC: "aa:aa:aa:aa:aa:aa", Proto: model.ProtoTCP,
	})
	// And back to link-local: the routable address must survive.
	tr.Observe(flow.Packet{
		SrcIP: netip.MustParseAddr("fe80::1122:33ff:fe44:5566"), DstIP: netip.MustParseAddr("fe80::1"),
		SrcMAC: "aa:aa:aa:aa:aa:aa", Proto: model.ProtoUDP,
	})

	if err := tr.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := store.addr["aa:aa:aa:aa:aa:aa"]; got != "fd00::10" {
		t.Errorf("device address = %q, want the routable fd00::10", got)
	}
}

// The hostname comes from names Skopos already learned passively, so a device
// that announces itself over mDNS is not just a MAC address.
func TestDeviceTrackerUsesPassiveHostname(t *testing.T) {
	store := &fakeDeviceStore{}
	tr := NewDeviceTracker(lanClassifier(), store, nil, time.Second)
	tr.SetHostnameLookup(func(a netip.Addr) string {
		if a.String() == "192.168.1.10" {
			return "printer.local"
		}
		return ""
	})

	tr.Observe(flow.Packet{
		SrcIP: netip.MustParseAddr("192.168.1.10"), DstIP: netip.MustParseAddr("9.9.9.9"),
		SrcMAC: "aa:aa:aa:aa:aa:aa", Proto: model.ProtoTCP,
	})
	if err := tr.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := store.host["aa:aa:aa:aa:aa:aa"]; got != "printer.local" {
		t.Errorf("hostname = %q, want printer.local", got)
	}
}
