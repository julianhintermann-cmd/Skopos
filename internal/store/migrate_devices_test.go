package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// The device inventory that shipped before this migration filed anything with
// a link-layer address as a neighbour, and kept one address column for both
// families. This replays such a database — the rows are the shape a real NAS
// produced — and checks what the upgrade makes of it.
func TestMigrateCleansUpDeviceInventory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "skopos.db")

	// Bring a database up to the schema that came before, then fill it.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_migrations (
		version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_ms INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if m.version >= 8 {
			break
		}
		if err := applyOne(db, m); err != nil {
			t.Fatalf("applying %s: %v", m.name, err)
		}
	}

	rows := []struct {
		mac, ip, label, policy string
		watch                  int
	}{
		{"6c:1f:f7:92:77:71", "192.168.1.125", "Julian-NAS", "", 0}, // a real, named device
		{"c4:82:e1:9b:14:2d", "192.168.1.102", "", "", 0},           // a real device
		{"ff:ff:ff:ff:ff:ff", "192.168.1.255", "", "", 0},           // the subnet broadcast
		{"01:00:5e:00:00:fb", "224.0.0.251", "", "", 0},             // an mDNS group
		{"33:33:00:00:00:01", "ff02::1", "", "", 0},                 // an NDP group
		{"dc:f5:1b:71:a1:20", "fe80::def5:1bff:fe71:a120", "", "", 0},
		{"01:aa:bb:cc:dd:ee", "192.168.1.50", "Kept because named", "", 0},
		{"03:aa:bb:cc:dd:ee", "192.168.1.51", "", "quarantine", 0},
		{"05:aa:bb:cc:dd:ee", "192.168.1.52", "", "", 1},
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO devices (mac, ip, label, hostname, vendor, watch_presence, present, policy, first_seen_ms, last_seen_ms)
			VALUES (?,?,?,'','',?,0,?,0,0)`, r.mac, r.ip, r.label, r.watch, r.policy); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopening runs the pending migration.
	s, err := Open(Options{Path: path, Clock: func() time.Time { return time.Unix(0, 0) }})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	devices, err := s.ListDevices(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byMAC := map[string]int{}
	for _, d := range devices {
		byMAC[d.MAC]++
	}

	for _, gone := range []string{"ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:fb", "33:33:00:00:00:01"} {
		if byMAC[gone] != 0 {
			t.Errorf("%s is a group address and should have been dropped", gone)
		}
	}
	// An operator's own decisions outrank the heuristic, group address or not.
	for _, kept := range []string{
		"6c:1f:f7:92:77:71", "c4:82:e1:9b:14:2d", "dc:f5:1b:71:a1:20",
		"01:aa:bb:cc:dd:ee", "03:aa:bb:cc:dd:ee", "05:aa:bb:cc:dd:ee",
	} {
		if byMAC[kept] != 1 {
			t.Errorf("%s should have survived the migration", kept)
		}
	}

	// The IPv6-only row moved into the new column instead of sitting in the
	// IPv4 one, where the UI read it as the device's address.
	d, err := s.DeviceByMAC(context.Background(), "dc:f5:1b:71:a1:20")
	if err != nil {
		t.Fatal(err)
	}
	if d.IP.IsValid() {
		t.Errorf("IPv4 column = %s, want empty", d.IP)
	}
	if got := d.IP6.String(); got != "fe80::def5:1bff:fe71:a120" {
		t.Errorf("IPv6 column = %s", got)
	}
}
