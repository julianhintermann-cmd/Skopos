package firewall

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

// flushedBackend is a kernel someone emptied: Verify fails until the service
// rebuilds it. baseFails turns the rebuild itself into a failure, which is the
// case an operator most needs written down.
type flushedBackend struct {
	*MemoryBackend
	flushed   bool
	baseFails bool
}

func (f *flushedBackend) Verify(ctx context.Context) error {
	if f.flushed {
		return errors.New("the skopos table is not in the kernel")
	}
	return f.MemoryBackend.Verify(ctx)
}

func (f *flushedBackend) EnsureBase(ctx context.Context) error {
	if f.baseFails {
		return errors.New("netlink refused to create the table")
	}
	// A rebuild that gets this far has put the table back.
	f.flushed = false
	return f.MemoryBackend.EnsureBase(ctx)
}

// auditOf returns the audit entries whose action is one of the given ones.
func auditOf(t *testing.T, st *store.Store, actions ...string) []model.AuditEntry {
	t.Helper()
	entries, err := st.ListAudit(context.Background(), 200)
	if err != nil {
		t.Fatalf("reading the audit log: %v", err)
	}
	var out []model.AuditEntry
	for _, e := range entries {
		for _, a := range actions {
			if e.Action == a {
				out = append(out, e)
			}
		}
	}
	return out
}

// The defect: the whole ruleset could be torn down and rebuilt under the
// operator, leaving two log lines and nothing in the record they would
// actually look at. A self-heal that leaves no audit trace fails this test.
func TestSelfHealIsAudited(t *testing.T) {
	backend := &flushedBackend{MemoryBackend: NewMemoryBackend(true)}
	svc, st := newTestService(t, baseConfig(true), backend)
	ctx := context.Background()

	if err := svc.ManualBlock(ctx, netip.MustParsePrefix("203.0.113.7/32"), "admin", "test", 0); err != nil {
		t.Fatalf("the initial block should succeed: %v", err)
	}
	before := len(auditOf(t, st, ActionSelfHeal, ActionSelfHealFailed))

	backend.flushed = true
	if err := svc.Verify(ctx); err != nil {
		t.Fatalf("Verify should have repaired the kernel: %v", err)
	}

	healed := auditOf(t, st, ActionSelfHeal, ActionSelfHealFailed)
	if len(healed) != before+1 {
		t.Fatalf("a self-heal wrote %d audit entries, want exactly 1: %+v",
			len(healed)-before, healed)
	}
	e := healed[0]
	if e.Action != ActionSelfHeal {
		t.Errorf("action = %q, want %q", e.Action, ActionSelfHeal)
	}
	if e.Actor != ActorSystem || e.Target != TargetRuleset {
		t.Errorf("entry = %+v, want actor %q on target %q", e, ActorSystem, TargetRuleset)
	}
	// The entry has to carry what happened, not merely that something did:
	// what was found wrong, and what came back.
	if !strings.Contains(e.Detail, "the skopos table is not in the kernel") {
		t.Errorf("detail %q does not say what the kernel was found to be missing", e.Detail)
	}
	if !strings.Contains(e.Detail, "1 block rule,") {
		t.Errorf("detail %q does not say what was reapplied", e.Detail)
	}
}

// A repair that fails is the entry that matters most, and it is the one a
// rebuild-then-audit ordering would lose.
func TestFailedSelfHealIsAudited(t *testing.T) {
	backend := &flushedBackend{MemoryBackend: NewMemoryBackend(true)}
	svc, st := newTestService(t, baseConfig(true), backend)
	ctx := context.Background()

	backend.flushed = true
	backend.baseFails = true
	if err := svc.Verify(ctx); err == nil {
		t.Fatal("Verify should report a repair it could not make")
	}

	healed := auditOf(t, st, ActionSelfHeal, ActionSelfHealFailed)
	if len(healed) != 1 {
		t.Fatalf("a failed self-heal wrote %d audit entries, want exactly 1: %+v", len(healed), healed)
	}
	if healed[0].Action != ActionSelfHealFailed {
		t.Errorf("action = %q, want %q", healed[0].Action, ActionSelfHealFailed)
	}
	if !strings.Contains(healed[0].Detail, "netlink refused to create the table") {
		t.Errorf("detail %q does not say why the rebuild failed", healed[0].Detail)
	}
}

// A verification that passes changes nothing, so it must write nothing. An
// audit log that gains an entry every two minutes for work that did not happen
// is one nobody reads, and the entries that matter drown in it.
func TestHealthyVerifyWritesNoAuditEntry(t *testing.T) {
	backend := &flushedBackend{MemoryBackend: NewMemoryBackend(true)}
	svc, st := newTestService(t, baseConfig(true), backend)
	ctx := context.Background()

	if err := svc.Verify(ctx); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := auditOf(t, st, ActionSelfHeal, ActionSelfHealFailed); len(got) != 0 {
		t.Errorf("a passing verification wrote %d audit entries: %+v", len(got), got)
	}
}

// Allowlisting an address that is already blocked stops the kernel dropping it
// while the block list goes on showing it: rulesFor skips it on the next
// reconcile and nothing else changes. That release is the answer to "why is
// this address not being dropped although it is listed", and it used to be
// nowhere in the record.
func TestAllowlistReleaseIsAudited(t *testing.T) {
	svc, st := newTestService(t, baseConfig(true), NewMemoryBackend(true))
	ctx := context.Background()
	prefix := netip.MustParsePrefix("10.1.2.3/32")

	if err := svc.ManualBlock(ctx, prefix, "admin", "misbehaving", 0); err != nil {
		t.Fatalf("ManualBlock: %v", err)
	}
	if err := svc.SetProtected(ctx, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}); err != nil {
		t.Fatalf("SetProtected: %v", err)
	}

	released := auditOf(t, st, ActionBlockReleased)
	if len(released) != 1 {
		t.Fatalf("the release wrote %d audit entries, want 1: %+v", len(released), released)
	}
	if released[0].Target != prefix.String() {
		t.Errorf("target = %q, want %q", released[0].Target, prefix)
	}
	if !strings.Contains(released[0].Detail, "10.0.0.0/8") {
		t.Errorf("detail %q does not name the allowlist entry that covers it", released[0].Detail)
	}
	// The block is still listed — that is the confusion the entry explains —
	// but it is no longer in the kernel.
	active, _ := st.ActiveBlocks(ctx)
	if len(active) != 1 {
		t.Errorf("the block should still be recorded, got %d rows", len(active))
	}

	// Setting the same list again releases nothing: repeating the entry on
	// every settings save would record an event that did not happen.
	if err := svc.SetProtected(ctx, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}); err != nil {
		t.Fatalf("SetProtected: %v", err)
	}
	if got := auditOf(t, st, ActionBlockReleased); len(got) != 1 {
		t.Errorf("an unchanged allowlist wrote %d release entries, want 1", len(got))
	}
}

// Provenance reaches the stored block through the ordinary paths, and a block
// placed with an alert behind it can be followed back to it.
func TestBlockRecordsProvenance(t *testing.T) {
	svc, st := newTestService(t, baseConfig(true), NewMemoryBackend(true))
	ctx := context.Background()

	manual := netip.MustParsePrefix("203.0.113.7/32")
	if err := svc.ManualBlock(ctx, manual, "julian", "kept knocking", 0); err != nil {
		t.Fatalf("ManualBlock: %v", err)
	}
	fromAlert := netip.MustParsePrefix("203.0.113.8/32")
	if err := svc.BlockWithProvenance(ctx, fromAlert, model.OriginDetector, model.BlockProvenance{
		Actor: "detector", Evidence: "22 ports in 60s", AlertID: 41, IncidentID: 7,
	}, "portscan: port scan from 203.0.113.8", 0); err != nil {
		t.Fatalf("BlockWithProvenance: %v", err)
	}

	byPrefix := map[string]model.Block{}
	active, _ := st.ActiveBlocks(ctx)
	for _, b := range active {
		byPrefix[b.Prefix.String()] = b
	}

	m := byPrefix[manual.String()]
	if m.Provenance == nil {
		t.Fatalf("the manual block recorded no provenance: %+v", m)
	}
	if m.Provenance.Actor != "julian" {
		t.Errorf("actor = %q, want %q", m.Provenance.Actor, "julian")
	}
	if m.Provenance.AlertID != 0 || m.Provenance.IncidentID != 0 {
		t.Errorf("a block placed by hand must claim no alert: %+v", m.Provenance)
	}

	d := byPrefix[fromAlert.String()]
	if d.Provenance == nil {
		t.Fatalf("the detector block recorded no provenance: %+v", d)
	}
	if d.Provenance.AlertID != 41 || d.Provenance.IncidentID != 7 {
		t.Errorf("provenance = %+v, want alert 41 and incident 7", d.Provenance)
	}
	if d.Provenance.Evidence != "22 ports in 60s" {
		t.Errorf("evidence = %q", d.Provenance.Evidence)
	}

	// The audit log carries the link too: it is what an operator reads, and a
	// line ending at a reason sentence is the dead end being closed.
	var blockEntries []model.AuditEntry
	for _, e := range auditOf(t, st, "block") {
		if e.Target == fromAlert.String() {
			blockEntries = append(blockEntries, e)
		}
	}
	if len(blockEntries) != 1 {
		t.Fatalf("audit entries for %s = %d, want 1", fromAlert, len(blockEntries))
	}
	if !strings.Contains(blockEntries[0].Detail, "alert 41") {
		t.Errorf("audit detail %q does not point at the alert", blockEntries[0].Detail)
	}
}

// A block whose provenance nobody recorded must read as exactly that. Rows
// written before migration 0012 are the real case; this is the same row.
func TestBlockWithoutProvenanceReadsAsUnrecorded(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()

	if _, err := st.AddBlock(ctx, model.Block{
		Prefix: netip.MustParsePrefix("203.0.113.9/32"), Origin: model.OriginManual, Reason: "recorded in 0.3",
	}); err != nil {
		t.Fatalf("AddBlock: %v", err)
	}
	active, _ := st.ActiveBlocks(ctx)
	if len(active) != 1 {
		t.Fatalf("active blocks = %d, want 1", len(active))
	}
	if active[0].Provenance != nil {
		t.Errorf("a block recorded with no provenance came back claiming %+v", active[0].Provenance)
	}
}
