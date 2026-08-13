package geoip

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/oschwald/maxminddb-golang"
)

// PrefixEnumerator is the optional Provider extension behind preventive
// country blocking: it lists every network registered to a set of countries,
// so the firewall can load them into the kernel and drop that traffic before
// any service sees it — instead of only blocking sources after they appear.
type PrefixEnumerator interface {
	// CountryPrefixes returns all prefixes of the given ISO 3166-1 alpha-2
	// codes, plus a per-country count for the UI.
	CountryPrefixes(ctx context.Context, codes []string) ([]netip.Prefix, map[string]int, error)
}

// CountryPrefixes implements PrefixEnumerator by walking the whole database
// once. The DB-IP country file holds on the order of a million networks; the
// walk takes about a second and runs only at startup, on a list change and
// after a database refresh.
func (m *Manager) CountryPrefixes(ctx context.Context, codes []string) ([]netip.Prefix, map[string]int, error) {
	want := make(map[string]bool, len(codes))
	for _, c := range codes {
		want[c] = true
	}
	counts := make(map[string]int, len(codes))
	if len(want) == 0 {
		return nil, counts, nil
	}

	// Hold the read lock for the entire walk: load() swaps and closes the
	// reader under the write lock, and closing unmaps the file a running
	// iteration is still reading.
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.reader == nil {
		return nil, nil, fmt.Errorf("geoip: database not loaded")
	}

	var out []netip.Prefix
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	n := 0
	// SkipAliasedNetworks: the IPv4 space appears once (returned as plain
	// IPv4), not repeated under the 6to4/Teredo aliases.
	for it := m.reader.Networks(maxminddb.SkipAliasedNetworks); it.Next(); {
		if n++; n%8192 == 0 && ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		ipnet, err := it.Network(&rec)
		if err != nil || !want[rec.Country.ISOCode] {
			continue
		}
		p, ok := prefixFromIPNet(ipnet)
		if !ok {
			continue
		}
		out = append(out, p)
		counts[rec.Country.ISOCode]++
	}
	return out, counts, nil
}

// prefixFromIPNet converts the net.IPNet the mmdb iterator yields into a
// netip.Prefix, normalising any 4-in-6 form to plain IPv4 so the firewall
// puts it in the right address-family set.
func prefixFromIPNet(n *net.IPNet) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, bits := n.Mask.Size()
	if bits == 0 {
		return netip.Prefix{}, false // non-canonical mask
	}
	if addr.Is4In6() {
		if ones < 96 {
			return netip.Prefix{}, false // wider than the v4-mapped range
		}
		addr = addr.Unmap()
		ones -= 96
	}
	if ones == 0 {
		return netip.Prefix{}, false // refuse to block an entire family
	}
	return netip.PrefixFrom(addr, ones).Masked(), true
}
