package netset

import (
	"net/netip"
	"testing"
)

func build(prefixes ...string) *Set {
	s := New()
	for _, p := range prefixes {
		s.Add(netip.MustParsePrefix(p))
	}
	s.Build()
	return s
}

func TestContainsV4(t *testing.T) {
	s := build("203.0.113.0/24", "198.51.100.7/32", "10.0.0.0/8")
	cases := map[string]bool{
		"203.0.113.5":   true,
		"203.0.113.255": true,
		"203.0.114.1":   false,
		"198.51.100.7":  true,
		"198.51.100.8":  false,
		"10.20.30.40":   true,
		"11.0.0.1":      false,
	}
	for addr, want := range cases {
		if got := s.Contains(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Contains(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestContainsV6(t *testing.T) {
	s := build("2001:db8::/32", "::1/128")
	if !s.Contains(netip.MustParseAddr("2001:db8:1234::1")) {
		t.Error("expected 2001:db8:1234::1 to be contained")
	}
	if s.Contains(netip.MustParseAddr("2001:dead::1")) {
		t.Error("2001:dead::1 should not be contained")
	}
	if !s.Contains(netip.MustParseAddr("::1")) {
		t.Error("::1 should be contained")
	}
}

func TestLen(t *testing.T) {
	s := build("203.0.113.0/24", "203.0.113.0/24", "10.0.0.0/8") // dup collapses
	if s.Len() != 2 {
		t.Errorf("Len = %d, want 2 (duplicate prefix should collapse)", s.Len())
	}
}

func TestEmptySet(t *testing.T) {
	s := New()
	s.Build()
	if s.Contains(netip.MustParseAddr("1.2.3.4")) {
		t.Error("empty set contains nothing")
	}
}
