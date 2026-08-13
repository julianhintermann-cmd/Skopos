package capture

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// TLS record and handshake constants.
const (
	tlsRecordHandshake = 0x16
	tlsHandshakeHello  = 0x01

	extServerName        = 0x0000
	extALPN              = 0x0010
	extSignatureAlgs     = 0x000d
	extSupportedVersions = 0x002b
)

// clientHello is what one ClientHello tells us: the server name the client
// asked for, and a JA4 fingerprint identifying the client software.
type clientHello struct {
	SNI string
	JA4 string
}

// parseClientHello extracts the SNI and JA4 fingerprint from a TLS
// ClientHello. Best effort by design: a hello split across TCP segments is
// skipped rather than reassembled — Skopos keeps no TCP state, and the next
// connection will show the same name anyway. Every read is bounds-checked;
// this is attacker-controlled input.
func parseClientHello(b []byte) (clientHello, bool) {
	// TLS record header: type(1) version(2) length(2).
	if len(b) < 5 || b[0] != tlsRecordHandshake {
		return clientHello{}, false
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	body := b[5:]
	if recLen < len(body) {
		body = body[:recLen] // trailing bytes of the next record
	}
	// Handshake header: type(1) length(3).
	if len(body) < 4 || body[0] != tlsHandshakeHello {
		return clientHello{}, false
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	hs := body[4:]
	if hsLen > len(hs) {
		return clientHello{}, false // truncated across segments
	}
	hs = hs[:hsLen]

	r := reader{b: hs}
	legacyVersion, ok := r.uint16()
	if !ok || !r.skip(32) { // client random
		return clientHello{}, false
	}
	sessID, ok := r.vector(1)
	if !ok {
		return clientHello{}, false
	}
	_ = sessID
	cipherBytes, ok := r.vector(2)
	if !ok || len(cipherBytes)%2 != 0 {
		return clientHello{}, false
	}
	if _, ok := r.vector(1); !ok { // compression methods
		return clientHello{}, false
	}

	var ciphers []uint16
	for i := 0; i+1 < len(cipherBytes); i += 2 {
		c := binary.BigEndian.Uint16(cipherBytes[i : i+2])
		if !isGREASE(c) {
			ciphers = append(ciphers, c)
		}
	}

	// Extensions are optional in the wire format, but every real client has
	// them; without any we still return a valid (SNI-less) fingerprint.
	var (
		exts     []uint16
		sigAlgs  []uint16
		sni      string
		alpnFrst string
		alpnLast string
		version  = legacyVersion
	)
	if extBlock, ok := r.vector(2); ok {
		er := reader{b: extBlock}
		for {
			extType, ok := er.uint16()
			if !ok {
				break
			}
			extData, ok := er.vector(2)
			if !ok {
				break
			}
			if isGREASE(extType) {
				continue
			}
			exts = append(exts, extType)

			switch extType {
			case extServerName:
				sni = parseSNI(extData)
			case extALPN:
				alpnFrst, alpnLast = parseALPN(extData)
			case extSignatureAlgs:
				sr := reader{b: extData}
				if list, ok := sr.vector(2); ok {
					for i := 0; i+1 < len(list); i += 2 {
						sigAlgs = append(sigAlgs, binary.BigEndian.Uint16(list[i:i+2]))
					}
				}
			case extSupportedVersions:
				vr := reader{b: extData}
				if list, ok := vr.vector(1); ok {
					for i := 0; i+1 < len(list); i += 2 {
						v := binary.BigEndian.Uint16(list[i : i+2])
						if !isGREASE(v) && v > version {
							version = v
						}
					}
				}
			}
		}
	}

	return clientHello{
		SNI: sni,
		JA4: ja4(version, sni != "", ciphers, exts, sigAlgs, alpnFrst, alpnLast),
	}, true
}

// ja4 builds the JA4 TLS client fingerprint: a readable prefix plus two
// truncated hashes over the sorted cipher and extension lists. Sorting is
// what makes it stable against clients that shuffle their order per
// connection, so the same software keeps the same fingerprint.
func ja4(version uint16, hasSNI bool, ciphers, exts, sigAlgs []uint16, alpnFirst, alpnLast string) string {
	d := "i"
	if hasSNI {
		d = "d"
	}
	if alpnFirst == "" {
		alpnFirst, alpnLast = "0", "0"
	}
	a := fmt.Sprintf("t%s%s%02d%02d%s%s", ja4Version(version), d,
		min(len(ciphers), 99), min(len(exts), 99), alpnFirst, alpnLast)

	b := ja4Hash(hexList(sortedCopy(ciphers)))

	// The extension hash excludes SNI and ALPN (they are already described by
	// the prefix) and appends the signature algorithms in their original
	// order.
	filtered := make([]uint16, 0, len(exts))
	for _, e := range exts {
		if e != extServerName && e != extALPN {
			filtered = append(filtered, e)
		}
	}
	c := hexList(sortedCopy(filtered))
	if len(sigAlgs) > 0 {
		c += "_" + hexList(sigAlgs)
	}
	return a + "_" + b + "_" + ja4Hash(c)
}

// ja4Hash is the first 12 hex characters of the SHA-256 of the list, or the
// all-zero placeholder JA4 uses for an empty list.
func ja4Hash(list string) string {
	if list == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(list))
	return hex.EncodeToString(sum[:])[:12]
}

func ja4Version(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	default:
		return "00"
	}
}

func sortedCopy(in []uint16) []uint16 {
	out := append([]uint16(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func hexList(in []uint16) string {
	parts := make([]string, len(in))
	for i, v := range in {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

// isGREASE reports whether a value is one of the reserved GREASE values
// clients inject to keep middleboxes honest. They are random per connection,
// so including them would make every fingerprint unique.
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v)
}

// parseSNI reads the first host_name entry of a server_name extension.
func parseSNI(b []byte) string {
	r := reader{b: b}
	list, ok := r.vector(2)
	if !ok {
		return ""
	}
	lr := reader{b: list}
	for {
		nameType, ok := lr.byteVal()
		if !ok {
			return ""
		}
		host, ok := lr.vector(2)
		if !ok {
			return ""
		}
		if nameType == 0 && validLabel(host) {
			return strings.ToLower(string(host))
		}
	}
}

// parseALPN returns the first and last character of the first protocol, which
// is what JA4 encodes (e.g. "h2" → "h","2").
func parseALPN(b []byte) (first, last string) {
	r := reader{b: b}
	list, ok := r.vector(2)
	if !ok {
		return "", ""
	}
	lr := reader{b: list}
	proto, ok := lr.vector(1)
	if !ok || len(proto) == 0 || !validLabel(proto) {
		return "", ""
	}
	return string(proto[0]), string(proto[len(proto)-1])
}

// reader is a bounds-checked cursor over a byte slice. Every method returns
// ok=false rather than panicking, so malformed input simply stops the parse.
type reader struct {
	b   []byte
	pos int
}

func (r *reader) byteVal() (byte, bool) {
	if r.pos+1 > len(r.b) {
		return 0, false
	}
	v := r.b[r.pos]
	r.pos++
	return v, true
}

func (r *reader) uint16() (uint16, bool) {
	if r.pos+2 > len(r.b) {
		return 0, false
	}
	v := binary.BigEndian.Uint16(r.b[r.pos : r.pos+2])
	r.pos += 2
	return v, true
}

func (r *reader) skip(n int) bool {
	if r.pos+n > len(r.b) {
		return false
	}
	r.pos += n
	return true
}

// vector reads a length-prefixed block whose length field is lenBytes wide.
func (r *reader) vector(lenBytes int) ([]byte, bool) {
	if r.pos+lenBytes > len(r.b) {
		return nil, false
	}
	n := 0
	for i := 0; i < lenBytes; i++ {
		n = n<<8 | int(r.b[r.pos+i])
	}
	start := r.pos + lenBytes
	if start+n > len(r.b) {
		return nil, false
	}
	r.pos = start + n
	return r.b[start : start+n], true
}
