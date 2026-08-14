package app

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/julianhintermann-cmd/skopos/internal/config"
)

// dbPath returns the SQLite database path on hot storage.
func dbPath(cfg *config.Config) string {
	return filepath.Join(cfg.Storage.Hot, "skopos.db")
}

// resolveInterfaces expands the configured interface list, replacing the
// special value "auto" with the best-guess primary interface.
func resolveInterfaces(configured []string) []string {
	var out []string
	for _, name := range configured {
		if name == "auto" {
			if primary := primaryInterface(); primary != "" {
				out = append(out, primary)
			}
			continue
		}
		out = append(out, name)
	}
	return out
}

// primaryInterface picks the first non-loopback, up interface that has a
// global unicast address — a reasonable default when the user hasn't named
// one. The default-route interface (resolveGateway) would be more precise but
// is platform-specific; this heuristic works everywhere.
func primaryInterface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				// A NAS is normally on a private LAN, so global-unicast
				// (which includes RFC 1918) is exactly what we want.
				if addr, ok := netip.AddrFromSlice(ipn.IP); ok && addr.IsGlobalUnicast() {
					return ifi.Name
				}
			}
		}
	}
	return ""
}

// localIPv6Prefixes returns the on-link global IPv6 prefixes this machine
// holds.
//
// "Internal" is decided against network.private_ranges, whose defaults cover
// RFC1918, ULA and link-local — everything except the case most home networks
// actually run. An ISP that delegates a prefix gives every device a real
// global address, and Skopos then read its own LAN as the internet: the
// blocklist detector picked the wrong end of the flow, the country detector
// could not see an attack on a device's own address, port-scan and rate
// thresholds applied the strict external numbers to ordinary local traffic,
// and the behavioural baseline never learned anything for a device that
// speaks IPv6 by preference. Nothing in the shipped configuration told the
// operator to add their prefix, and most could not name it if asked, so it is
// discovered instead.
func localIPv6Prefixes() []netip.Prefix {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	seen := map[string]bool{}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipn.IP)
			if !ok || !addr.Is6() || addr.Is4In6() {
				continue
			}
			// Only genuinely global addresses: link-local and ULA are already
			// covered by the shipped defaults.
			if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
				continue
			}
			ones, _ := ipn.Mask.Size()
			if ones <= 0 || ones > 64 {
				// A /128 says nothing about the neighbours; take the /64 the
				// address sits in, which is what SLAAC hands out.
				ones = 64
			}
			p := netip.PrefixFrom(addr, ones).Masked()
			if !seen[p.String()] {
				seen[p.String()] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// resolveGateways returns every default-route gateway, both families.
//
// The IPv6 one matters more than it looks: on a dual-stack home LAN the v6
// default router is almost always the link-local address the router announced
// itself with, which no operator would think to add to the allowlist — most
// router admin pages never show it. Without it, "the gateway can never be
// blocked" was an IPv4-only promise.
func resolveGateways() []netip.Addr {
	var out []netip.Addr
	if gw := resolveGateway(); gw.IsValid() {
		out = append(out, gw)
	}
	if gw := resolveGateway6(); gw.IsValid() {
		out = append(out, gw)
	}
	return out
}

// resolveGateway6 returns the IPv6 default-route gateway from
// /proc/net/ipv6_route. Each line is hex without separators: destination
// network (32 chars), prefix length, source network, source prefix length,
// next hop (32 chars), metric, refcount, use, flags, device. The default
// route is the entry whose destination and prefix length are both zero.
func resolveGateway6() netip.Addr {
	data, err := os.ReadFile("/proc/net/ipv6_route")
	if err != nil {
		return netip.Addr{}
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		if fields[1] != "00" || strings.Trim(fields[0], "0") != "" {
			continue // not ::/0
		}
		// Skip unreachable/blackhole defaults: RTF_REJECT (0x0200) in the
		// flags column. Protecting a reject route's "next hop" would protect
		// nothing and could shadow the real gateway.
		if len(fields) >= 9 {
			if flags, err := strconv.ParseUint(fields[8], 16, 64); err == nil && flags&0x0200 != 0 {
				continue
			}
		}
		raw, err := hex.DecodeString(fields[4])
		if err != nil || len(raw) != 16 {
			continue
		}
		addr, ok := netip.AddrFromSlice(raw)
		if !ok || addr.IsUnspecified() {
			continue
		}
		return addr
	}
	return netip.Addr{}
}

// resolveGateway returns the IPv4 default-route gateway by reading
// /proc/net/route (Linux). It is best-effort: on other platforms, or when the
// route table can't be read, it returns the zero Addr and the policy layer
// simply relies on the configured allowlist instead.
func resolveGateway() netip.Addr {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return netip.Addr{}
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		// Default route: destination 00000000, flags with RTF_GATEWAY (0x2).
		if fields[1] != "00000000" {
			continue
		}
		flags, _ := strconv.ParseInt(fields[3], 16, 64)
		if flags&0x2 == 0 {
			continue
		}
		gwLE, err := strconv.ParseUint(fields[2], 16, 32)
		if err != nil {
			continue
		}
		// The gateway is stored little-endian in /proc/net/route.
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(gwLE))
		return netip.AddrFrom4(b)
	}
	return netip.Addr{}
}
