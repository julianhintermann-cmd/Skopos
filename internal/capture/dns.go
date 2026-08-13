package capture

import (
	"encoding/binary"
	"net/netip"
	"strings"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
)

// DNS/mDNS ports whose payloads carry name mappings worth learning.
const (
	portDNS  = 53
	portMDNS = 5353
)

// Record types and limits.
const (
	dnsTypeA     = 1
	dnsTypeAAAA  = 28
	dnsClassIN   = 1
	dnsMaxNames  = 32  // answers harvested per message
	dnsMaxJumps  = 8   // compression-pointer budget
	dnsMaxLabels = 128 // labels per name
)

// parseDNSNames extracts address→name mappings from a DNS or mDNS response.
// Every read is bounds-checked and every loop bounded: this parses attacker-
// supplied bytes off the wire, so a malformed message must yield nothing
// rather than misbehave.
//
// Names are attributed to the question name, not the record owner: a lookup
// of youtube.com that follows a CNAME chain should show up as youtube.com,
// which is what the operator recognises, rather than the CDN node's internal
// label. mDNS responses often carry no question at all — those fall back to
// the owning record's name, which is exactly the device hostname we want.
func parseDNSNames(msg []byte) []flow.NameRecord {
	if len(msg) < 12 {
		return nil
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 == 0 {
		return nil // not a response
	}
	if flags&0x000f != 0 {
		return nil // rcode != NOERROR: nothing authoritative to learn
	}
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	if anCount == 0 {
		return nil
	}

	off := 12
	var question string
	for i := 0; i < qdCount; i++ {
		name, next, ok := readDNSName(msg, off)
		if !ok || next+4 > len(msg) {
			return nil
		}
		if i == 0 {
			question = name
		}
		off = next + 4 // QTYPE + QCLASS
	}

	var out []flow.NameRecord
	for i := 0; i < anCount && len(out) < dnsMaxNames; i++ {
		owner, next, ok := readDNSName(msg, off)
		if !ok || next+10 > len(msg) {
			return out
		}
		rrType := binary.BigEndian.Uint16(msg[next : next+2])
		rrClass := binary.BigEndian.Uint16(msg[next+2:next+4]) & 0x7fff // mDNS uses the top bit as cache-flush
		ttl := binary.BigEndian.Uint32(msg[next+4 : next+8])
		rdLen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		rd := next + 10
		if rd+rdLen > len(msg) {
			return out
		}

		if rrClass == dnsClassIN {
			var addr netip.Addr
			switch {
			case rrType == dnsTypeA && rdLen == 4:
				addr, _ = netip.AddrFromSlice(msg[rd : rd+4])
			case rrType == dnsTypeAAAA && rdLen == 16:
				addr, _ = netip.AddrFromSlice(msg[rd : rd+16])
			}
			if addr.IsValid() {
				name := question
				if name == "" {
					name = owner
				}
				if name != "" {
					out = append(out, flow.NameRecord{Addr: addr.Unmap(), Name: name, TTL: ttl})
				}
			}
		}
		off = rd + rdLen
	}
	return out
}

// readDNSName decodes a (possibly compressed) name, returning the name and
// the offset just past the name in the *record* stream — for a compressed
// name that is the position after the 2-byte pointer, not inside the target.
func readDNSName(msg []byte, off int) (name string, next int, ok bool) {
	var sb strings.Builder
	jumps := 0
	next = -1

	for labels := 0; labels < dnsMaxLabels; labels++ {
		if off < 0 || off >= len(msg) {
			return "", 0, false
		}
		length := int(msg[off])

		switch {
		case length == 0: // root label ends the name
			if next < 0 {
				next = off + 1
			}
			return strings.TrimSuffix(sb.String(), "."), next, true

		case length&0xc0 == 0xc0: // compression pointer
			if off+2 > len(msg) {
				return "", 0, false
			}
			target := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3fff)
			if next < 0 {
				next = off + 2
			}
			if jumps++; jumps > dnsMaxJumps || target >= off {
				return "", 0, false // only backward jumps, bounded — no loops
			}
			off = target

		case length&0xc0 != 0:
			return "", 0, false // reserved label type

		default:
			if off+1+length > len(msg) {
				return "", 0, false
			}
			label := msg[off+1 : off+1+length]
			if !validLabel(label) {
				return "", 0, false
			}
			sb.Write(label)
			sb.WriteByte('.')
			off += 1 + length
		}
	}
	return "", 0, false
}

// validLabel keeps names printable: anything else is either a broken parse or
// an attempt to smuggle control characters into the dashboard.
func validLabel(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}
