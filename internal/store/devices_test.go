package store

import (
	"context"
	"errors"
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
