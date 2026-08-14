//go:build linux

package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// nftBackend enforces blocks through a dedicated inet table via netlink.
// Requires CAP_NET_ADMIN.
type nftBackend struct {
	mu    sync.Mutex
	table *nftables.Table
	sets  map[string]*nftables.Set
	// lan holds the configured private ranges, so per-device rules can ask
	// "is the other end outside our network?".
	lan []netip.Prefix
}

// NewNFTablesBackend creates the nftables backend. lanRanges are the private
// ranges per-device policies compare against. It does not touch the kernel
// until EnsureBase is called.
func NewNFTablesBackend(lanRanges []netip.Prefix) Backend {
	return &nftBackend{sets: make(map[string]*nftables.Set), lan: lanRanges}
}

func (b *nftBackend) Name() string { return "nftables" }

// Available reports whether nftables can be programmed: we can open a netlink
// connection and list tables. This is what degrades Skopos to monitor-only
// when CAP_NET_ADMIN or nf_tables is missing.
func (b *nftBackend) Available() bool {
	c, err := nftables.New()
	if err != nil {
		return false
	}
	if _, err := c.ListTables(); err != nil {
		return false
	}
	return true
}

// Verify reads the kernel back and reports whether the table, chains and sets
// Skopos programmed are still there.
//
// Available() cannot answer this: it proves only that netlink opens. Anything
// that wipes the ruleset out from under a running Skopos — `nft flush ruleset`
// from another tool, a container's network being rebuilt, a firewall package
// upgrade — left the service reporting that it was enforcing over an empty
// kernel, indefinitely, because nothing ever looked again.
func (b *nftBackend) Verify(context.Context) error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("opening netlink: %w", err)
	}
	tables, err := c.ListTables()
	if err != nil {
		return fmt.Errorf("listing tables: %w", err)
	}
	var table *nftables.Table
	for _, t := range tables {
		if t.Name == tableName && t.Family == nftables.TableFamilyINet {
			table = t
			break
		}
	}
	if table == nil {
		return fmt.Errorf("the %s table is gone from the kernel", tableName)
	}
	chains, err := c.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("listing chains: %w", err)
	}
	found := map[string]bool{}
	for _, ch := range chains {
		if ch.Table != nil && ch.Table.Name == tableName {
			found[ch.Name] = true
		}
	}
	for _, name := range []string{chainIn, chainFwd, chainOut} {
		if !found[name] {
			return fmt.Errorf("the %s chain is missing from the %s table", name, tableName)
		}
	}
	for _, name := range allSets {
		if _, err := c.GetSetByName(table, name); err != nil {
			return fmt.Errorf("the %s set is missing from the %s table: %w", name, tableName, err)
		}
	}
	return nil
}

// EnsureBase creates the table, sets and chains with their static match rules.
// It is idempotent: it deletes any prior skopos table first so a version
// upgrade with changed rules converges cleanly.
func (b *nftBackend) EnsureBase(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	c, err := nftables.New()
	if err != nil {
		return err
	}

	// Start from a clean slate: drop a previous skopos table if present.
	if tables, err := c.ListTables(); err == nil {
		for _, t := range tables {
			if t.Name == tableName && t.Family == nftables.TableFamilyINet {
				c.DelTable(t)
			}
		}
	}
	_ = c.Flush()

	table := c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: tableName})
	b.table = table
	b.sets = make(map[string]*nftables.Set)

	// Interval sets with per-element timeout: they hold CIDRs and expire
	// blocks in-kernel without Skopos intervening.
	for name, keyType := range map[string]nftables.SetDatatype{
		setDrop4: nftables.TypeIPAddr, setReject4: nftables.TypeIPAddr,
		setDrop6: nftables.TypeIP6Addr, setReject6: nftables.TypeIP6Addr,
	} {
		set := &nftables.Set{
			Table:      table,
			Name:       name,
			KeyType:    keyType,
			Interval:   true,
			HasTimeout: true,
		}
		if err := c.AddSet(set, nil); err != nil {
			return fmt.Errorf("adding set %s: %w", name, err)
		}
		b.sets[name] = set
	}

	// Country and LAN sets: intervals without timeout — replaced wholesale
	// when the list, the GeoIP database or the configuration changes.
	for name, keyType := range map[string]nftables.SetDatatype{
		setCountry4:   nftables.TypeIPAddr,
		setCountry6:   nftables.TypeIP6Addr,
		setLAN4:       nftables.TypeIPAddr,
		setLAN6:       nftables.TypeIP6Addr,
		setProtected4: nftables.TypeIPAddr,
		setProtected6: nftables.TypeIP6Addr,
	} {
		set := &nftables.Set{
			Table:    table,
			Name:     name,
			KeyType:  keyType,
			Interval: true,
		}
		if err := c.AddSet(set, nil); err != nil {
			return fmt.Errorf("adding set %s: %w", name, err)
		}
		b.sets[name] = set
	}

	// Device sets hold single addresses, so no interval flag is needed.
	for name, keyType := range map[string]nftables.SetDatatype{
		setDevLANOnly4: nftables.TypeIPAddr,
		setDevLANOnly6: nftables.TypeIP6Addr,
		setDevQuar4:    nftables.TypeIPAddr,
		setDevQuar6:    nftables.TypeIP6Addr,
	} {
		set := &nftables.Set{Table: table, Name: name, KeyType: keyType}
		if err := c.AddSet(set, nil); err != nil {
			return fmt.Errorf("adding set %s: %w", name, err)
		}
		b.sets[name] = set
	}

	// Chains hooked at input, forward and output. Blocks act in both
	// directions (D4): the NAS also stops talking to a blocked peer.
	input := c.AddChain(&nftables.Chain{
		Name: chainIn, Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter,
	})
	forward := c.AddChain(&nftables.Chain{
		Name: chainFwd, Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter,
	})
	output := c.AddChain(&nftables.Chain{
		Name: chainOut, Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter,
	})

	// Inbound and forwarded traffic is matched on source address; outbound on
	// destination address.
	addMatch(c, table, input, true)
	addMatch(c, table, forward, true)
	addMatch(c, table, forward, false)
	addMatch(c, table, output, false)

	// Per-device policy sits with the per-IP blocks, ahead of the conntrack
	// accept: a quarantined or LAN-confined device stays confined for
	// established connections too, which is the whole point of pulling its
	// plug from here.
	for _, chain := range []*nftables.Chain{input, forward, output} {
		for _, v6 := range []bool{false, true} {
			quar, lanOnly, lanSet := setDevQuar4, setDevLANOnly4, setLAN4
			if v6 {
				quar, lanOnly, lanSet = setDevQuar6, setDevLANOnly6, setLAN6
			}
			// Quarantine: absolute, either endpoint.
			c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: matchExprs(quar, v6, true, false)})
			c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: matchExprs(quar, v6, false, false)})
			// LAN-only: drop when this device is one end and the *other* end
			// is outside the configured private ranges.
			c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: lanOnlyExprs(lanOnly, lanSet, v6, true)})
			c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: lanOnlyExprs(lanOnly, lanSet, v6, false)})
		}
	}

	// Country blocking comes after the per-IP rules and behind a conntrack
	// accept: per-IP blocks are absolute in both directions, while country
	// prefixes only stop unsolicited inbound traffic — replies to connections
	// the LAN opened itself (updates, feeds, a CDN that happens to sit there)
	// keep flowing. Rule order within a chain is the order added here.
	// The never-block list sits between the conntrack accept and the country
	// drop, and matches the source only — the same field the country rule
	// matches. Placed any earlier it would short-circuit the per-device
	// policies; written as a destination match it would accept every inbound
	// packet to the LAN when the LAN is allowlisted, which would quietly
	// disable country blocking altogether. Here it does exactly one thing:
	// an address the operator marked never-block is not dropped for the
	// country it happens to sit in.
	for _, chain := range []*nftables.Chain{input, forward} {
		c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: ctEstablishedAccept()})
		c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: acceptExprs(setProtected4, false)})
		c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: acceptExprs(setProtected6, true)})
		c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: matchExprs(setCountry4, false, true, false)})
		c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: matchExprs(setCountry6, true, true, false)})
	}

	if err := c.Flush(); err != nil {
		return err
	}
	// The LAN ranges are static configuration; load them once here.
	return b.loadLANRanges()
}

// loadLANRanges fills the lan4/lan6 sets from the configured private ranges.
// Callers hold b.mu.
func (b *nftBackend) loadLANRanges() error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	elements := map[string][]nftables.SetElement{}
	for name, spans := range unionBySet(b.lan, setLAN4, setLAN6) {
		for _, s := range spans {
			elements[name] = append(elements[name], spanPair(s)...)
		}
	}
	for _, name := range []string{setLAN4, setLAN6} {
		c.FlushSet(b.sets[name])
		if els := elements[name]; len(els) > 0 {
			if err := c.SetAddElements(b.sets[name], els); err != nil {
				return fmt.Errorf("populating set %s: %w", name, err)
			}
		}
	}
	return c.Flush()
}

// ReconcileProtected replaces the never-block sets.
func (b *nftBackend) ReconcileProtected(_ context.Context, prefixes []netip.Prefix) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.table == nil {
		return fmt.Errorf("nftables: EnsureBase not called")
	}
	c, err := nftables.New()
	if err != nil {
		return err
	}
	// The allowlist and the auto-appended gateway /32 routinely overlap — an
	// allowlist of the LAN is exactly what the example config suggests — and an
	// overlap here used to abort Restore before it programmed a single block.
	elements := map[string][]nftables.SetElement{}
	for name, spans := range unionBySet(prefixes, setProtected4, setProtected6) {
		for _, s := range spans {
			elements[name] = append(elements[name], spanPair(s)...)
		}
	}
	for _, name := range []string{setProtected4, setProtected6} {
		c.FlushSet(b.sets[name])
		if els := elements[name]; len(els) > 0 {
			if err := c.SetAddElements(b.sets[name], els); err != nil {
				return fmt.Errorf("populating set %s: %w", name, err)
			}
		}
	}
	return c.Flush()
}

// lanOnlyExprs builds "ip [s|d]addr @devices ip [d|s]addr != @lan drop": the
// device is one endpoint, the peer is outside the private ranges.
func lanOnlyExprs(devSet, lanSet string, v6, deviceIsSrc bool) []expr.Any {
	devOff, devLen := addrField(v6, deviceIsSrc)
	peerOff, peerLen := addrField(v6, !deviceIsSrc)
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{nfproto(v6)}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: devOff, Len: devLen},
		&expr.Lookup{SourceRegister: 1, SetName: devSet},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: peerOff, Len: peerLen},
		&expr.Lookup{SourceRegister: 1, SetName: lanSet, Invert: true},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}

// addrField returns the payload offset and length of the source or
// destination address for the given family.
func addrField(v6, src bool) (offset, length uint32) {
	if v6 {
		if src {
			return 8, 16
		}
		return 24, 16
	}
	if src {
		return 12, 4
	}
	return 16, 4
}

// ReconcileDevices replaces the per-device policy sets.
func (b *nftBackend) ReconcileDevices(_ context.Context, rules []DeviceRule) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.table == nil {
		return fmt.Errorf("nftables: EnsureBase not called")
	}
	c, err := nftables.New()
	if err != nil {
		return err
	}

	elements := map[string][]nftables.SetElement{}
	for _, r := range rules {
		addr := r.Addr.Unmap()
		if !addr.IsValid() {
			continue
		}
		v6 := addr.Is6()
		var name string
		switch r.Policy {
		case DeviceQuarantine:
			name = setDevQuar4
			if v6 {
				name = setDevQuar6
			}
		case DeviceLANOnly:
			name = setDevLANOnly4
			if v6 {
				name = setDevLANOnly6
			}
		default:
			continue
		}
		elements[name] = append(elements[name], nftables.SetElement{Key: ipBytes(addr)})
	}

	for _, name := range []string{setDevQuar4, setDevQuar6, setDevLANOnly4, setDevLANOnly6} {
		c.FlushSet(b.sets[name])
		if els := elements[name]; len(els) > 0 {
			if err := c.SetAddElements(b.sets[name], els); err != nil {
				return fmt.Errorf("populating set %s: %w", name, err)
			}
		}
	}
	return c.Flush()
}

// ctEstablishedAccept builds "ct state established,related accept". Accept
// only ends this chain — other tables still see the packet — so it merely
// exempts established flows from the country rules that follow. On a kernel
// without conntrack the state reads as untracked and the exemption never
// matches, which fails closed: country blocking then affects both directions.
func ctEstablishedAccept() []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{
			SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
			Xor:  binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// addMatch appends rules to chain matching either the source (bySrc=true) or
// destination address against each set, applying drop or reject.
func addMatch(c *nftables.Conn, table *nftables.Table, chain *nftables.Chain, bySrc bool) {
	specs := []struct {
		set    string
		v6     bool
		reject bool
	}{
		{setDrop4, false, false},
		{setReject4, false, true},
		{setDrop6, true, false},
		{setReject6, true, true},
	}
	for _, s := range specs {
		c.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: matchExprs(s.set, s.v6, bySrc, s.reject),
		})
	}
}

// matchExprs builds "ip[6] [s|d]addr @set <verdict>".
func matchExprs(setName string, v6, bySrc, reject bool) []expr.Any {
	offset, length := addrField(v6, bySrc)

	exprs := []expr.Any{
		// Match L3 protocol family via meta nfproto.
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{nfproto(v6)}},
		&expr.Payload{
			DestRegister: 1, Base: expr.PayloadBaseNetworkHeader,
			Offset: offset, Len: length,
		},
		&expr.Lookup{SourceRegister: 1, SetName: setName},
	}
	if reject {
		exprs = append(exprs, &expr.Reject{})
	} else {
		exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictDrop})
	}
	return exprs
}

// acceptExprs matches a source address against a set and accepts it,
// short-circuiting the rules that follow in the same chain.
func acceptExprs(setName string, v6 bool) []expr.Any {
	offset, length := addrField(v6, true)
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{nfproto(v6)}},
		&expr.Payload{
			DestRegister: 1, Base: expr.PayloadBaseNetworkHeader,
			Offset: offset, Len: length,
		},
		&expr.Lookup{SourceRegister: 1, SetName: setName},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

func nfproto(v6 bool) byte {
	if v6 {
		return unix.NFPROTO_IPV6
	}
	return unix.NFPROTO_IPV4
}

// blockSets are the sets Reconcile owns: the per-IP blocks, by action and
// family. Naming them explicitly is load-bearing. This loop used to range over
// b.sets, which held every set in the table, so each reconcile flushed the
// country, LAN, never-block and per-device sets too and refilled none of them
// — they can only be refilled by the functions that own them. Since preventive
// country blocking shipped, any block or unblock silently emptied the country
// sets until their next refresh, while the dashboard went on reporting the
// prefix count it last loaded.
var blockSets = []string{setDrop4, setReject4, setDrop6, setReject6}

// Reconcile makes the per-IP block sets match desired exactly, in a single
// netlink batch so the kernel never sees a half-applied state. Element counts
// on a home network are small, making a flush-and-refill simpler and safer
// than element-by-element diffing.
func (b *nftBackend) Reconcile(_ context.Context, desired []Rule) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.table == nil {
		return fmt.Errorf("nftables: EnsureBase not called")
	}
	c, err := nftables.New()
	if err != nil {
		return err
	}

	now := time.Now()
	elements := map[string][]nftables.SetElement{}
	// Coalesced first: the kernel rejects overlapping intervals outright, and
	// one rejected batch wedges every later reconcile. See coalesce.go.
	for setName, spans := range coalesceRules(desired) {
		for _, s := range spans {
			els, ok := spanElements(s, now)
			if !ok {
				continue // already expired; the expiry loop will drop it
			}
			elements[setName] = append(elements[setName], els...)
		}
	}

	for _, name := range blockSets {
		set := b.sets[name]
		if set == nil {
			continue
		}
		c.FlushSet(set)
		if els := elements[name]; len(els) > 0 {
			if err := c.SetAddElements(set, els); err != nil {
				return fmt.Errorf("populating set %s: %w", name, err)
			}
		}
	}
	return c.Flush()
}

// countryChunk is how many prefixes go into one netlink message. Each prefix
// becomes two set elements (interval start + exclusive end) of a few dozen
// bytes; a netlink attribute caps at 64 KiB, so 400 prefixes leaves ample
// headroom. Flushing every few messages keeps single batches small enough for
// the socket buffer while a whole country streams in.
const (
	countryChunk      = 400
	countryFlushEvery = 8
)

// ReconcileCountry replaces the country sets with the given prefixes. The
// first batch carries the set flushes plus the first chunks, so the swap is
// near-atomic; a country's full list converges over a few batches.
func (b *nftBackend) ReconcileCountry(_ context.Context, prefixes []netip.Prefix) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.table == nil {
		return fmt.Errorf("nftables: EnsureBase not called")
	}
	c, err := nftables.New()
	if err != nil {
		return err
	}

	for _, name := range []string{setCountry4, setCountry6} {
		c.FlushSet(b.sets[name])
	}

	pending := map[string][]nftables.SetElement{}
	queued := 0
	queue := func() error {
		for name, els := range pending {
			if len(els) == 0 {
				continue
			}
			if err := c.SetAddElements(b.sets[name], els); err != nil {
				return fmt.Errorf("populating set %s: %w", name, err)
			}
			queued++
		}
		pending = map[string][]nftables.SetElement{}
		return nil
	}

	// GeoIP's own walk yields a disjoint trie, but a hand-edited prefix list or
	// a future source need not, and one overlap would take the whole batch
	// down. Merging is cheap here and removes the hazard for good.
	count := 0
	for name, spans := range unionBySet(prefixes, setCountry4, setCountry6) {
		for _, s := range spans {
			pending[name] = append(pending[name], spanPair(s)...)
			if count++; count%countryChunk != 0 {
				continue
			}
			if err := queue(); err != nil {
				return err
			}
			if queued >= countryFlushEvery {
				if err := c.Flush(); err != nil {
					return fmt.Errorf("flushing country batch: %w", err)
				}
				queued = 0
			}
		}
	}
	if err := queue(); err != nil {
		return err
	}
	return c.Flush()
}

// spanElements renders a coalesced range as the element pair an interval set
// wants: the inclusive start, carrying the timeout, and the exclusive end
// marker. It reports false when the range has already expired, so the caller
// leaves it out and lets the expiry loop retire the row.
func spanElements(s span, now time.Time) ([]nftables.SetElement, bool) {
	el := nftables.SetElement{Key: setKey(s.lo)}
	if s.expires != nil {
		ttl := s.expires.Sub(now)
		if ttl <= 0 {
			return nil, false
		}
		el.Timeout = ttl
	}
	return []nftables.SetElement{el, {Key: setKey(s.hi), IntervalEnd: true}}, true
}

// spanPair is spanElements for the sets that carry no expiry.
func spanPair(s span) []nftables.SetElement {
	return []nftables.SetElement{{Key: setKey(s.lo)}, {Key: setKey(s.hi), IntervalEnd: true}}
}

// unionBySet splits a prefix list by address family and merges each side into
// non-overlapping ranges, keyed by the set each family belongs in. A /0 is
// dropped: no set here is ever meant to swallow a whole address family.
func unionBySet(prefixes []netip.Prefix, name4, name6 string) map[string][]span {
	var v4, v6 []netip.Prefix
	for _, p := range prefixes {
		switch {
		case !p.IsValid() || p.Bits() == 0:
			continue
		case p.Addr().Is6():
			v6 = append(v6, p)
		default:
			v4 = append(v4, p)
		}
	}
	out := make(map[string][]span, 2)
	if s := unionPrefixes(v4); len(s) > 0 {
		out[name4] = s
	}
	if s := unionPrefixes(v6); len(s) > 0 {
		out[name6] = s
	}
	return out
}
