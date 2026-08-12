package store

import (
	"context"
	"testing"
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
