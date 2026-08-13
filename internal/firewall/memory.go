package firewall

import (
	"context"
	"net/netip"
	"sort"
	"sync"
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
