package firewall

import (
	"context"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// MemoryBackend is an in-memory Backend for tests and dry runs. It records the
// last reconciled rule set and how many times each method was called.
type MemoryBackend struct {
	mu             sync.Mutex
	available      bool
	baseEnsured    int
	reconcileCalls int
	current        []Rule
	country        []netip.Prefix
	countryCalls   int
	devices        []DeviceRule
	deviceCalls    int
	protected      []netip.Prefix
}

// NewMemoryBackend returns a memory backend. available controls whether it
// reports itself as able to enforce.
func NewMemoryBackend(available bool) *MemoryBackend {
	return &MemoryBackend{available: available}
}

// EnsureBase implements Backend.
func (m *MemoryBackend) EnsureBase(context.Context) error {
	m.mu.Lock()
	m.baseEnsured++
	m.mu.Unlock()
	return nil
}

// Reconcile implements Backend.
func (m *MemoryBackend) Reconcile(_ context.Context, desired []Rule) error {
	m.mu.Lock()
	m.reconcileCalls++
	m.current = sortRules(desired)
	m.mu.Unlock()
	return nil
}

// Available implements Backend.
func (m *MemoryBackend) Available() bool { return m.available }

// Verify implements Backend. The memory backend cannot lose its state to
// anything outside the process, so it is always consistent with itself.
func (m *MemoryBackend) Verify(context.Context) error { return nil }

// SetCounts implements Backend by reporting what it is holding, so the
// service's comparison logic is exercised by the unit tests too.
func (m *MemoryBackend) SetCounts(context.Context) (map[string]int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]int{}
	for _, r := range m.current {
		if name, ok := setFor(r); ok {
			out[name]++
		}
	}
	for _, p := range m.country {
		if p.Addr().Is6() {
			out[setCountry6]++
		} else {
			out[setCountry4]++
		}
	}
	for _, p := range m.protected {
		if p.Addr().Is6() {
			out[setProtected6]++
		} else {
			out[setProtected4]++
		}
	}
	for _, d := range m.devices {
		name := setDevQuar4
		switch {
		case d.Policy == DeviceLANOnly && d.Addr.Is6():
			name = setDevLANOnly6
		case d.Policy == DeviceLANOnly:
			name = setDevLANOnly4
		case d.Addr.Is6():
			name = setDevQuar6
		}
		out[name]++
	}
	return out, nil
}

// Dump implements Backend by reporting what the memory backend is holding, so
// the inspector's callers are exercised by the unit tests too.
//
// It says plainly that it has no chains rather than describing three healthy
// ones. A fake that answers like a working kernel would let the inspector's
// tests pass straight over the hole the inspector exists to find. The counts
// are one per stored rule: there is no interval encoding here to imitate, and
// imitating one would be theatre.
func (m *MemoryBackend) Dump(context.Context) (Snapshot, error) {
	snap := Snapshot{ReadAt: time.Now(), Table: true}
	for _, name := range []string{chainIn, chainFwd, chainOut} {
		snap.Chains = append(snap.Chains, ChainSnapshot{
			Name: name,
			Err:  "the memory backend keeps no chains",
		})
	}
	held := m.held()
	for _, name := range allSets {
		views := held[name]
		n := len(views)
		snap.Sets = append(snap.Sets, SetSnapshot{
			Name: name, Present: true, Elements: &n, Ranges: views,
		})
	}
	return snap, nil
}

// held renders everything the backend is holding, grouped by set, in one pass
// under the lock so the counts and the ranges cannot describe two different
// moments.
func (m *MemoryBackend) held() map[string][]RangeView {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := map[string][]RangeView{}
	add := func(name string, p netip.Prefix, expires *time.Time) {
		if v, ok := prefixView(p, expires); ok {
			out[name] = append(out[name], v)
		}
	}
	for _, r := range m.current {
		if name, ok := setFor(r); ok {
			add(name, r.Prefix, r.Expires)
		}
	}
	for _, p := range m.country {
		add(pick(p.Addr().Is6(), setCountry6, setCountry4), p, nil)
	}
	for _, p := range m.protected {
		add(pick(p.Addr().Is6(), setProtected6, setProtected4), p, nil)
	}
	for _, d := range m.devices {
		name := pick(d.Addr.Is6(), setDevQuar6, setDevQuar4)
		if d.Policy == DeviceLANOnly {
			name = pick(d.Addr.Is6(), setDevLANOnly6, setDevLANOnly4)
		}
		add(name, netip.PrefixFrom(d.Addr, d.Addr.BitLen()), nil)
	}
	return out
}

// Name implements Backend.
func (m *MemoryBackend) Name() string { return "memory" }

// Current returns the last reconciled rule set (sorted).
func (m *MemoryBackend) Current() []Rule {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Rule(nil), m.current...)
}

// ReconcileCalls returns how many times Reconcile was called.
func (m *MemoryBackend) ReconcileCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reconcileCalls
}

// ReconcileDevices implements Backend.
func (m *MemoryBackend) ReconcileDevices(_ context.Context, rules []DeviceRule) error {
	sorted := append([]DeviceRule(nil), rules...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Addr.String() < sorted[j].Addr.String() })
	m.mu.Lock()
	m.devices = sorted
	m.deviceCalls++
	m.mu.Unlock()
	return nil
}

// CurrentDevices returns the last reconciled device rules (sorted).
func (m *MemoryBackend) CurrentDevices() []DeviceRule {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]DeviceRule(nil), m.devices...)
}

// DeviceCalls returns how many times ReconcileDevices was called.
func (m *MemoryBackend) DeviceCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deviceCalls
}

// ReconcileCountry implements Backend.
func (m *MemoryBackend) ReconcileCountry(_ context.Context, prefixes []netip.Prefix) error {
	sorted := append([]netip.Prefix(nil), prefixes...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].String() < sorted[j].String() })
	m.mu.Lock()
	m.country = sorted
	m.countryCalls++
	m.mu.Unlock()
	return nil
}

// ReconcileProtected implements Backend.
func (m *MemoryBackend) ReconcileProtected(_ context.Context, prefixes []netip.Prefix) error {
	sorted := append([]netip.Prefix(nil), prefixes...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].String() < sorted[j].String() })
	m.mu.Lock()
	m.protected = sorted
	m.mu.Unlock()
	return nil
}

// CurrentProtected returns the last reconciled never-block prefixes (sorted).
func (m *MemoryBackend) CurrentProtected() []netip.Prefix {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]netip.Prefix(nil), m.protected...)
}

// CurrentCountry returns the last reconciled country prefixes (sorted).
func (m *MemoryBackend) CurrentCountry() []netip.Prefix {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]netip.Prefix(nil), m.country...)
}

// CountryCalls returns how many times ReconcileCountry was called.
func (m *MemoryBackend) CountryCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.countryCalls
}
