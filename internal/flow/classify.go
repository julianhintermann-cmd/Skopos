package flow

import (
	"net/netip"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// Classifier decides whether an address is "internal" (inside the configured
// private ranges) and derives a flow's direction from its endpoints.
type Classifier struct {
	private []netip.Prefix
}

// NewClassifier builds a Classifier from CIDR strings. Invalid entries are
// skipped; validation happens in the config layer, so this stays total.
func NewClassifier(privateRanges []string) *Classifier {
	c := &Classifier{}
	for _, r := range privateRanges {
		if p, err := netip.ParsePrefix(r); err == nil {
			c.private = append(c.private, p)
		}
	}
	return c
}

// Internal reports whether addr falls inside any configured private range.
func (c *Classifier) Internal(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	// Compare in a single family; Contains handles v4/v6 mismatch by
	// returning false.
	for _, p := range c.private {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Direction classifies a flow from source and destination addresses.
func (c *Classifier) Direction(src, dst netip.Addr) model.Direction {
	si, di := c.Internal(src), c.Internal(dst)
	switch {
	case si && di:
		return model.DirLANtoLAN
	case si && !di:
		return model.DirLANtoWAN
	case !si && di:
		return model.DirWANtoLAN
	default:
		return model.DirWANtoWAN
	}
}

// Ranges returns the configured private ranges. The firewall needs them to
// express "this device may talk to the LAN but not the internet" as a kernel
// rule.
func (c *Classifier) Ranges() []netip.Prefix {
	return append([]netip.Prefix(nil), c.private...)
}
