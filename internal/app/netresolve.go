package app

import (
	"bufio"
	"bytes"
	"encoding/binary"
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
