package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestUpsertDeviceNewThenSeen(t *testing.T) {
	s, _ := testStore(t) // fixed clock
	ctx := context.Background()

	isNew, err := s.UpsertDevice(ctx, "aa:bb:cc:dd:ee:ff", "192.168.1.10", "nas", "")
	if err != nil {
		t.Fatal(err)
	}
	if !isNew {
		t.Error("first sighting must report isNew=true")
	}

	// Second upsert of the same MAC — even under the fixed clock — must NOT be
	// reported as new.
	isNew, err = s.UpsertDevice(ctx, "aa:bb:cc:dd:ee:ff", "192.168.1.11", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if isNew {
		t.Error("second sighting must report isNew=false")
	}

	devices, err := s.ListDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 {
		t.Fatalf("device count = %d, want 1", len(devices))
	}
	// The IP should have been updated to the newer non-empty value.
	if devices[0].IP.String() != "192.168.1.11" {
		t.Errorf("device IP = %s, want 192.168.1.11", devices[0].IP)
	}
	if devices[0].Hostname != "nas" {
		t.Errorf("hostname should be preserved as 'nas', got %q", devices[0].Hostname)
	}
}

func TestSetDeviceLabel(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	const mac = "aa:bb:cc:dd:ee:ff"
	if _, err := s.UpsertDevice(ctx, mac, "192.168.1.10", "nas", ""); err != nil {
		t.Fatal(err)
	}

	// Naming an unknown device is a not-found, not a silent no-op.
	if err := s.SetDeviceLabel(ctx, "00:00:00:00:00:00", "ghost"); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("labeling unknown device: err = %v, want ErrDeviceNotFound", err)
	}

	if err := s.SetDeviceLabel(ctx, mac, "Living-room TV"); err != nil {
		t.Fatal(err)
	}
	devices, err := s.ListDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if devices[0].Label != "Living-room TV" {
		t.Errorf("label = %q, want %q", devices[0].Label, "Living-room TV")
	}
	if got := devices[0].Name(); got != "Living-room TV" {
		t.Errorf("Name() = %q, want the label to win over hostname", got)
	}

	// Auto-discovery must never clobber an operator label: a later sighting
	// updates the hostname but leaves the label intact.
	if _, err := s.UpsertDevice(ctx, mac, "192.168.1.10", "nas2", "Ubiquiti"); err != nil {
		t.Fatal(err)
	}
	devices, _ = s.ListDevices(ctx)
	if devices[0].Label != "Living-room TV" {
		t.Errorf("label after re-sighting = %q, want it preserved", devices[0].Label)
	}

	// An empty label clears it, and Name() falls back to the hostname.
	if err := s.SetDeviceLabel(ctx, mac, ""); err != nil {
		t.Fatal(err)
	}
	devices, _ = s.ListDevices(ctx)
	if devices[0].Label != "" {
		t.Errorf("label = %q, want cleared", devices[0].Label)
	}
	if got := devices[0].Name(); got != "nas2" {
		t.Errorf("Name() = %q, want the hostname fallback", got)
	}
}

func TestPresenceWatchAndState(t *testing.T) {
	s, now := testStore(t)
	ctx := context.Background()

	const mac = "aa:bb:cc:dd:ee:22"
	if _, err := s.UpsertDevice(ctx, mac, "192.168.1.30", "phone", ""); err != nil {
		t.Fatal(err)
	}

	// Enabling on a just-seen device seeds present=true (no arrival ping later).
	if err := s.SetDeviceWatchPresence(ctx, mac, true, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	watched, err := s.WatchedDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(watched) != 1 || !watched[0].WatchPresence || !watched[0].Present {
		t.Fatalf("watched = %+v, want present seeded true", watched)
	}
	_ = now

	if err := s.SetDevicePresent(ctx, mac, false); err != nil {
		t.Fatal(err)
	}
	watched, _ = s.WatchedDevices(ctx)
	if watched[0].Present {
		t.Error("present should be false after SetDevicePresent(false)")
	}

	// Disabling clears both flags.
	if err := s.SetDeviceWatchPresence(ctx, mac, false, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	if w, _ := s.WatchedDevices(ctx); len(w) != 0 {
		t.Errorf("watched after disable = %d, want 0", len(w))
	}
	if err := s.SetDeviceWatchPresence(ctx, "00:00:00:00:00:99", true, time.Minute); err == nil {
		t.Error("unknown mac should error")
	}
}

// A dual-stack machine is one device with two addresses, and the IPv4 one is
// what an operator recognises. Before the split, whichever family sent the
// last packet overwrote the other.
func TestUpsertDeviceKeepsBothFamilies(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	const mac = "aa:bb:cc:dd:ee:ff"

	if _, err := s.UpsertDevice(ctx, mac, "192.168.1.10", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertDevice(ctx, mac, "fd00::10", "", ""); err != nil {
		t.Fatal(err)
	}

	devices, err := s.ListDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 {
		t.Fatalf("device count = %d, want 1", len(devices))
	}
	if got := devices[0].IP.String(); got != "192.168.1.10" {
		t.Errorf("IPv4 = %s, want 192.168.1.10", got)
	}
	if got := devices[0].IP6.String(); got != "fd00::10" {
		t.Errorf("IPv6 = %s, want fd00::10", got)
	}
	if got := devices[0].PrimaryAddr().String(); got != "192.168.1.10" {
		t.Errorf("primary address = %s, want the IPv4 one", got)
	}
}

// Every interface has a fe80:: address, so it is the one most LAN traffic
// carries — and it identifies nothing. It must not displace a routable one.
func TestUpsertDeviceLinkLocalDoesNotDisplaceRoutable(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	const mac = "aa:bb:cc:dd:ee:ff"

	if _, err := s.UpsertDevice(ctx, mac, "fd00::10", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertDevice(ctx, mac, "fe80::1122:33ff:fe44:5566", "", ""); err != nil {
		t.Fatal(err)
	}
	d, err := s.DeviceByMAC(ctx, mac)
	if err != nil {
		t.Fatal(err)
	}
	if got := d.IP6.String(); got != "fd00::10" {
		t.Errorf("IPv6 = %s, want the routable fd00::10 to survive", got)
	}

	// The other way round, a link-local is better than nothing.
	if _, err := s.UpsertDevice(ctx, "11:22:33:44:55:66", "fe80::1", "", ""); err != nil {
		t.Fatal(err)
	}
	other, err := s.DeviceByMAC(ctx, "11:22:33:44:55:66")
	if err != nil {
		t.Fatal(err)
	}
	if got := other.IP6.String(); got != "fe80::1" {
		t.Errorf("IPv6 = %s, want fe80::1 when it is all we have", got)
	}
}

// One address, one machine. Traffic that breaks the assumption — a tunnel with
// synthetic hardware addresses, a relay re-framing other hosts' packets — used
// to grow an inventory row and a "new device" alert per sighting.
func TestUpsertDeviceCapsMACsPerAddress(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	created := 0
	for i := 0; i < MaxMACsPerAddress+6; i++ {
		mac := fmt.Sprintf("02:00:00:00:00:%02x", i)
		isNew, err := s.UpsertDevice(ctx, mac, "10.0.1.2", "", "")
		if err != nil {
			t.Fatal(err)
		}
		if isNew {
			created++
		}
	}
	if created != MaxMACsPerAddress {
		t.Errorf("created %d entries for one address, want the cap of %d", created, MaxMACsPerAddress)
	}
	devices, err := s.ListDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != MaxMACsPerAddress {
		t.Errorf("inventory holds %d entries, want %d", len(devices), MaxMACsPerAddress)
	}

	// Devices already on record keep updating; only new entries are refused.
	isNew, err := s.UpsertDevice(ctx, "02:00:00:00:00:00", "10.0.1.2", "gateway", "")
	if err != nil {
		t.Fatal(err)
	}
	if isNew {
		t.Error("a known MAC must not report as new")
	}
	d, err := s.DeviceByMAC(ctx, "02:00:00:00:00:00")
	if err != nil {
		t.Fatal(err)
	}
	if d.Hostname != "gateway" {
		t.Errorf("hostname = %q, want the update to have landed", d.Hostname)
	}

	// A different address is unaffected by another's noise.
	if isNew, err := s.UpsertDevice(ctx, "02:00:00:00:00:99", "192.168.1.10", "", ""); err != nil {
		t.Fatal(err)
	} else if !isNew {
		t.Error("an unrelated address must still be inventoried")
	}
}

func TestForgetDevices(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	for _, mac := range []string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"} {
		if _, err := s.UpsertDevice(ctx, mac, "192.168.1.10", "", ""); err != nil {
			t.Fatal(err)
		}
	}

	removed, err := s.ForgetDevices(ctx, []string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "not:a:known:ma:c0:01"})
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}
	devices, err := s.ListDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].MAC != "aa:bb:cc:dd:ee:03" {
		t.Errorf("remaining inventory = %+v", devices)
	}

	// Forgetting nothing is not an error, and touches nothing.
	if n, err := s.ForgetDevices(ctx, nil); err != nil || n != 0 {
		t.Errorf("ForgetDevices(nil) = %d, %v", n, err)
	}
}
