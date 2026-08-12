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
	seen map[string]bool
}

func (f *fakeDeviceStore) UpsertDevice(_ context.Context, mac, _, _, _ string) (bool, error) {
	if f.seen == nil {
		f.seen = map[string]bool{}
	}
	isNew := !f.seen[mac]
	f.seen[mac] = true
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
