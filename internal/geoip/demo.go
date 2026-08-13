package geoip

import (
	"context"
	"net/netip"
)

// DemoProvider is the country source for demo mode: a handful of static
// prefixes covering the demo traffic generator's addresses, so the dashboard
// shows a believable country mix without downloading anything.
type DemoProvider struct{ ranges []demoRange }

type demoRange struct {
	prefix  netip.Prefix
	country string
}

// NewDemoProvider builds the static demo mapping.
func NewDemoProvider() *DemoProvider {
	mk := func(p, cc string) demoRange {
		return demoRange{prefix: netip.MustParsePrefix(p), country: cc}
	}
	return &DemoProvider{ranges: []demoRange{
		mk("1.1.1.0/24", "US"),      // Cloudflare DNS
		mk("9.9.9.0/24", "CH"),      // Quad9 (Zürich)
		mk("142.250.0.0/15", "US"),  // Google
		mk("151.101.0.0/16", "US"),  // Fastly
		mk("104.16.0.0/13", "US"),   // Cloudflare
		mk("17.0.0.0/8", "US"),      // Apple
		mk("140.82.112.0/20", "US"), // GitHub
		mk("82.13.0.0/16", "GB"),
		mk("98.142.32.0/19", "US"),
		mk("91.209.108.0/24", "RU"),
		mk("2.57.0.0/16", "NL"),
		mk("65.241.0.0/16", "US"),
		mk("156.54.0.0/16", "IT"),
		mk("139.199.0.0/16", "CN"),
	}}
}

// Available implements Provider.
func (d *DemoProvider) Available() bool { return true }

// Lookup implements Provider.
func (d *DemoProvider) Lookup(addr netip.Addr) (string, bool) {
	for _, r := range d.ranges {
		if r.prefix.Contains(addr) {
			return r.country, true
		}
	}
	return "", false
}

// CountryPrefixes implements PrefixEnumerator over the static demo ranges, so
// preventive country blocking is demonstrable without the real database.
func (d *DemoProvider) CountryPrefixes(_ context.Context, codes []string) ([]netip.Prefix, map[string]int, error) {
	want := make(map[string]bool, len(codes))
	for _, c := range codes {
		want[c] = true
	}
	counts := make(map[string]int, len(codes))
	var out []netip.Prefix
	for _, r := range d.ranges {
		if want[r.country] {
			out = append(out, r.prefix)
			counts[r.country]++
		}
	}
	return out, counts, nil
}
