package app

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/julianhintermann-cmd/skopos/internal/firewall"
	"github.com/julianhintermann-cmd/skopos/internal/geoip"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

func TestCountryEnforcerCoverage(t *testing.T) {
	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "s.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	list, err := geoip.NewBlocklist(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := list.Set([]string{"RU"}); err != nil {
		t.Fatal(err)
	}
	backend := firewall.NewMemoryBackend(true)
	fw := firewall.NewService(firewall.Config{Enforce: true}, backend, st, nil)
	// Enforcing() now requires the base ruleset to genuinely exist, so the test
	// has to come up the way the app does rather than assume it.
	if err := fw.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	nop := func(string, ...any) {}

	ce := newCountryEnforcer(geoip.NewDemoProvider(), list, fw, func() bool { return true }, nop, nop)
	if !ce.refresh(context.Background()) {
		t.Fatal("refresh should succeed with the demo provider")
	}

	// The demo provider maps 91.209.108.0/24 to RU.
	if !ce.Covered(netip.MustParseAddr("91.209.108.7")) {
		t.Error("address inside a loaded RU prefix must be covered")
	}
	if ce.Covered(netip.MustParseAddr("8.8.8.8")) {
		t.Error("address outside the loaded prefixes must not be covered")
	}
	if got := backend.CurrentCountry(); len(got) != 1 {
		t.Errorf("kernel country prefixes = %v, want 1", got)
	}
	counts, loaded := ce.Stats()
	if !loaded || counts["RU"] != 1 {
		t.Errorf("Stats = %v loaded=%v, want RU:1 loaded", counts, loaded)
	}

	// In observe mode nothing is dropped, so coverage must read false even
	// after a successful load.
	ceObs := newCountryEnforcer(geoip.NewDemoProvider(), list, fw, func() bool { return false }, nop, nop)
	if !ceObs.refresh(context.Background()) {
		t.Fatal("observe refresh should still succeed")
	}
	if ceObs.Covered(netip.MustParseAddr("91.209.108.7")) {
		t.Error("observe mode must never report kernel coverage")
	}
}

// Coverage has to follow the kernel, not the boot-time decision. This was a
// bool captured at startup: disarm the firewall at noon and the live view kept
// flagging flows as dropped by country, and the policy engine kept silencing
// alerts on the grounds that the kernel was handling those sources — silence
// justified by a fact that had stopped being true, until the process
// restarted.
func TestCountryCoverageFollowsEnforcementAtRuntime(t *testing.T) {
	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "s.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	list, err := geoip.NewBlocklist(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := list.Set([]string{"RU"}); err != nil {
		t.Fatal(err)
	}
	fw := firewall.NewService(firewall.Config{Enforce: true}, firewall.NewMemoryBackend(true), st, nil)
	if err := fw.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	nop := func(string, ...any) {}

	enforcing := true
	ce := newCountryEnforcer(geoip.NewDemoProvider(), list, fw, func() bool { return enforcing }, nop, nop)
	if !ce.refresh(context.Background()) {
		t.Fatal("refresh should succeed with the demo provider")
	}

	// The demo provider maps 91.209.108.0/24 to RU, as the test above relies on.
	covered := netip.MustParseAddr("91.209.108.7")
	if !ce.Covered(covered) {
		t.Fatal("precondition: the loaded RU prefix should cover this address")
	}

	// Disarm. Nothing about the loaded prefixes changes — only whether the
	// kernel is dropping — and coverage must answer from that.
	enforcing = false
	if ce.Covered(covered) {
		t.Error("still reporting kernel coverage after enforcement was switched off")
	}

	// Arm again, without reloading anything.
	enforcing = true
	if !ce.Covered(covered) {
		t.Error("coverage did not come back when enforcement was switched on again")
	}
}
