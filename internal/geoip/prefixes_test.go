package geoip

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

func TestDemoProviderCountryPrefixes(t *testing.T) {
	d := NewDemoProvider()
	prefixes, counts, err := d.CountryPrefixes(context.Background(), []string{"RU", "CN"})
	if err != nil {
		t.Fatal(err)
	}
	if counts["RU"] != 1 || counts["CN"] != 1 {
		t.Errorf("counts = %v, want RU:1 CN:1", counts)
	}
	if len(prefixes) != 2 {
		t.Fatalf("prefixes = %v, want 2 entries", prefixes)
	}
	want := map[string]bool{"91.209.108.0/24": true, "139.199.0.0/16": true}
	for _, p := range prefixes {
		if !want[p.String()] {
			t.Errorf("unexpected prefix %s", p)
		}
	}

	// Unknown country: empty result, no error.
	prefixes, counts, err = d.CountryPrefixes(context.Background(), []string{"XX"})
	if err != nil || len(prefixes) != 0 || len(counts) != 0 {
		t.Errorf("unknown country: prefixes=%v counts=%v err=%v", prefixes, counts, err)
	}
}

func TestPrefixFromIPNet(t *testing.T) {
	cases := []struct {
		ip   net.IP
		bits int
		want string
		ok   bool
	}{
		// Plain IPv4 (what the iterator yields with SkipAliasedNetworks).
		{net.IPv4(203, 0, 113, 0).To4(), 24, "203.0.113.0/24", true},
		// Plain IPv6.
		{net.ParseIP("2a00::"), 16, "2a00::/16", true},
		// v4-mapped 16-byte form is normalised to plain IPv4.
		{net.ParseIP("::ffff:198.51.100.0"), 120, "198.51.100.0/24", true},
		// A whole address family is refused.
		{net.IPv4(0, 0, 0, 0).To4(), 0, "", false},
		// Wider than the v4-mapped range is refused.
		{net.ParseIP("::ffff:0.0.0.0"), 90, "", false},
	}
	for _, c := range cases {
		ipnet := &net.IPNet{IP: c.ip, Mask: net.CIDRMask(c.bits, len(c.ip)*8)}
		got, ok := prefixFromIPNet(ipnet)
		if ok != c.ok {
			t.Errorf("prefixFromIPNet(%s/%d) ok = %v, want %v", c.ip, c.bits, ok, c.ok)
			continue
		}
		if ok && got != netip.MustParsePrefix(c.want) {
			t.Errorf("prefixFromIPNet(%s/%d) = %s, want %s", c.ip, c.bits, got, c.want)
		}
	}
}

func TestBlocklistOnChangeFires(t *testing.T) {
	b, err := NewBlocklist(memKeyStore{})
	if err != nil {
		t.Fatal(err)
	}
	fired := 0
	b.SetOnChange(func() { fired++ })
	if err := b.Set([]string{"ru"}); err != nil {
		t.Fatal(err)
	}
	if fired != 1 {
		t.Errorf("onChange fired %d times, want 1", fired)
	}
	// A rejected set must not fire.
	if err := b.Set([]string{"nope"}); err == nil {
		t.Fatal("expected invalid code to be rejected")
	}
	if fired != 1 {
		t.Errorf("onChange fired %d times after rejected set, want still 1", fired)
	}
}

// memKeyStore is an in-memory KeyStore for tests.
type memKeyStore map[string]string

func (m memKeyStore) GetMeta(key string) (string, bool, error) {
	v, ok := m[key]
	return v, ok, nil
}

func (m memKeyStore) SetMeta(key, value string) error {
	m[key] = value
	return nil
}
