package firewall

import "net/netip"

// Kernel object names and the address arithmetic behind the interval sets.
// They live apart from the netlink code so that the coalescer — and its tests,
// which are the ones that catch an expiry being silently extended or cut
// short — build and run on every platform, not just where nftables exists.

const (
	tableName = "skopos"
	chainIn   = "input"
	chainFwd  = "forward"
	chainOut  = "output"

	setDrop4   = "drop4"
	setDrop6   = "drop6"
	setReject4 = "reject4"
	setReject6 = "reject6"

	// Preventive country blocking: whole countries' prefixes, dropped on the
	// way in only (after a ct accept for established flows, so the NAS can
	// still deliberately reach those countries).
	setCountry4   = "country_drop4"
	setCountry6   = "country_drop6"
	setProtected4 = "protected4"
	setProtected6 = "protected6"

	// Per-device policy: the LAN ranges to compare against, plus the two
	// device sets.
	setLAN4        = "lan4"
	setLAN6        = "lan6"
	setDevLANOnly4 = "dev_lanonly4"
	setDevLANOnly6 = "dev_lanonly6"
	setDevQuar4    = "dev_quarantine4"
	setDevQuar6    = "dev_quarantine6"
)

// allSets is every set EnsureBase creates, so a verification pass can check
// that all of them are still present rather than trusting that the table's
// existence implies its contents.
var allSets = []string{
	setDrop4, setDrop6, setReject4, setReject6,
	setCountry4, setCountry6, setProtected4, setProtected6,
	setLAN4, setLAN6, setDevLANOnly4, setDevLANOnly6, setDevQuar4, setDevQuar6,
}

// setFor picks the set name for a rule by family and action.
func setFor(r Rule) (string, bool) {
	v6 := r.Prefix.Addr().Is6()
	switch r.Action {
	case Reject:
		if v6 {
			return setReject6, true
		}
		return setReject4, true
	default: // Drop
		if v6 {
			return setDrop6, true
		}
		return setDrop4, true
	}
}

// intervalBounds returns the inclusive start and exclusive end addresses of a
// prefix, as required by nftables interval sets.
// Both are one byte wider than the address itself. The exclusive end of a
// range that reaches the top of the family — 255.255.255.0/24, 240.0.0.0/4,
// ffff::/16 — is one past the maximum address, which does not fit in an
// address and which netip reports as an invalid Addr. Carrying it in an extra
// leading byte keeps every bound orderable, so the coalescer can sort and
// compare them without special cases. setKey strips that byte on the way to
// the kernel, where the same value is written as a wrap to zero.
func intervalBounds(p netip.Prefix) (start, end []byte) {
	p = p.Masked()
	start = append([]byte{0}, ipBytes(p.Addr())...)
	end = append([]byte{0}, ipBytes(lastAddr(p))...)
	for i := len(end) - 1; i >= 0; i-- {
		if end[i]++; end[i] != 0 {
			break
		}
	}
	return start, end
}

// setKey renders a bound as the kernel key: the address bytes without the
// ordering byte. A range ending one past the family maximum becomes the
// all-zero key, which is how nftables spells "up to the end".
func setKey(bound []byte) []byte { return bound[1:] }

func ipBytes(a netip.Addr) []byte {
	if a.Is4() {
		b := a.As4()
		return b[:]
	}
	b := a.As16()
	return b[:]
}

// lastAddr returns the last address contained in the prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	addr := p.Masked().Addr()
	bs := ipBytes(addr)
	bits := p.Bits()
	total := len(bs) * 8
	for i := bits; i < total; i++ {
		bs[i/8] |= 1 << (7 - uint(i%8))
	}
	out, _ := netip.AddrFromSlice(bs)
	return out
}
