// Package netset provides a fast membership test for large collections of IP
// prefixes. Blocklist feeds carry thousands of CIDRs and are checked on the
// packet path, so a linear scan is too slow; a set bucketed by prefix length
// answers Contains in one map lookup per distinct length instead.
package netset

import (
	"net/netip"
	"sort"
)

// Set is an immutable-after-Build collection of IP prefixes with fast lookup.
// The zero value is an empty, usable set.
type Set struct {
	v4        map[int]map[[4]byte]struct{}
	v6        map[int]map[[16]byte]struct{}
	v4Lengths []int
	v6Lengths []int
}

// New returns an empty Set.
func New() *Set {
	return &Set{
		v4: make(map[int]map[[4]byte]struct{}),
		v6: make(map[int]map[[16]byte]struct{}),
	}
}

// Add inserts a prefix. Call Build once after the last Add.
func (s *Set) Add(p netip.Prefix) {
	p = p.Masked()
	bits := p.Bits()
	addr := p.Addr()
	switch {
	case addr.Is4():
		m := s.v4[bits]
		if m == nil {
			m = make(map[[4]byte]struct{})
			s.v4[bits] = m
		}
		m[addr.As4()] = struct{}{}
	case addr.Is6():
		m := s.v6[bits]
		if m == nil {
			m = make(map[[16]byte]struct{})
			s.v6[bits] = m
		}
		m[addr.As16()] = struct{}{}
	}
}

// Build finalizes the set's internal length index. Safe to call multiple
// times; required before Contains reflects the latest Adds.
func (s *Set) Build() {
	s.v4Lengths = s.v4Lengths[:0]
	for l := range s.v4 {
		s.v4Lengths = append(s.v4Lengths, l)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(s.v4Lengths)))

	s.v6Lengths = s.v6Lengths[:0]
	for l := range s.v6 {
		s.v6Lengths = append(s.v6Lengths, l)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(s.v6Lengths)))
}

// Contains reports whether addr falls inside any prefix in the set. It probes
// the most specific prefix lengths first.
func (s *Set) Contains(addr netip.Addr) bool {
	if addr.Is4() || addr.Is4In6() {
		a := addr.Unmap()
		for _, bits := range s.v4Lengths {
			if prefix, err := a.Prefix(bits); err == nil {
				if _, ok := s.v4[bits][prefix.Addr().As4()]; ok {
					return true
				}
			}
		}
		return false
	}
	for _, bits := range s.v6Lengths {
		if prefix, err := addr.Prefix(bits); err == nil {
			if _, ok := s.v6[bits][prefix.Addr().As16()]; ok {
				return true
			}
		}
	}
	return false
}

// Len returns the number of prefixes in the set.
func (s *Set) Len() int {
	n := 0
	for _, m := range s.v4 {
		n += len(m)
	}
	for _, m := range s.v6 {
		n += len(m)
	}
	return n
}
