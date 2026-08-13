package settings

import (
	"encoding/json"
	"testing"
	"time"
)

type memStore map[string]string

func (m memStore) GetMeta(k string) (string, bool, error) { v, ok := m[k]; return v, ok, nil }
func (m memStore) SetMeta(k, v string) error              { m[k] = v; return nil }

func baseline() Runtime {
	return Runtime{
		Enforcement: "observe",
		BlockTTL:    24 * time.Hour,
		Allowlist:   []string{"192.168.1.0/24"},
		Cooldown:    30 * time.Minute,
		QuietHours:  QuietHours{Enabled: true, FromHour: 23, ToHour: 7, MinSeverity: "critical"},
		Portscan: Portscan{
			Enabled: true, Window: time.Minute,
			External: Thresholds{Ports: 15, Targets: 10},
			Internal: Thresholds{Ports: 40, Targets: 25},
		},
		Rate: Rate{Enabled: true, Window: 10 * time.Second, MaxNewConnections: 200, MaxPacketsPerSecond: 5000},
	}
}

func patch(t *testing.T, kv map[string]any) map[string]json.RawMessage {
	t.Helper()
	out := map[string]json.RawMessage{}
	for k, v := range kv {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		out[k] = raw
	}
	return out
}

func TestUpdateAppliesAndPersists(t *testing.T) {
	ks := memStore{}
	m, err := New(ks, baseline())
	if err != nil {
		t.Fatal(err)
	}
	var got []Runtime
	m.OnChange(func(r Runtime) { got = append(got, r) })

	if err := m.Update(patch(t, map[string]any{"enforcement": "enforce", "block_ttl": "48h"})); err != nil {
		t.Fatal(err)
	}
	cur := m.Current()
	if cur.Enforcement != "enforce" || cur.BlockTTL != 48*time.Hour {
		t.Fatalf("current = %+v", cur)
	}
	if len(got) != 1 || got[0].Enforcement != "enforce" {
		t.Errorf("subscribers = %+v, want one call with the new settings", got)
	}
	// Untouched fields keep the YAML value.
	if cur.Cooldown != 30*time.Minute || len(cur.Allowlist) != 1 {
		t.Errorf("unrelated fields changed: %+v", cur)
	}
	// A fresh manager over the same store sees the overrides.
	m2, err := New(ks, baseline())
	if err != nil {
		t.Fatal(err)
	}
	if m2.Current().Enforcement != "enforce" {
		t.Error("overrides did not survive a restart")
	}
	if o := m2.Overridden(); len(o) != 2 || o[0] != "block_ttl" || o[1] != "enforcement" {
		t.Errorf("overridden = %v", o)
	}
}

func TestUpdateIsAllOrNothing(t *testing.T) {
	ks := memStore{}
	m, _ := New(ks, baseline())
	fired := 0
	m.OnChange(func(Runtime) { fired++ })

	// One good field, one that fails validation: nothing may change.
	err := m.Update(patch(t, map[string]any{
		"enforcement":              "enforce",
		"rate.max_new_connections": 0,
	}))
	if err == nil {
		t.Fatal("expected validation to reject the patch")
	}
	if m.Current().Enforcement != "observe" {
		t.Error("a rejected patch must not apply its valid half")
	}
	if fired != 0 {
		t.Error("a rejected patch must not notify subscribers")
	}
	if _, ok := ks[overridesKey]; ok {
		t.Error("a rejected patch must not be persisted")
	}
}

func TestUpdateRejectsUnknownAndInvalid(t *testing.T) {
	m, _ := New(memStore{}, baseline())
	cases := map[string]map[string]any{
		"unknown key":        {"storage.hot": "/tmp"},
		"bad enforcement":    {"enforcement": "yolo"},
		"bad allowlist":      {"allowlist": []string{"not-an-ip"}},
		"zero window":        {"portscan.window": "0s"},
		"negative threshold": {"portscan.external": Thresholds{Ports: -1, Targets: 5}},
		"bad clock":          {"quiet_hours": QuietHours{Enabled: true, FromHour: 25}},
		"bad severity":       {"quiet_hours": QuietHours{MinSeverity: "loud"}},
	}
	for name, p := range cases {
		if err := m.Update(patch(t, p)); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestDurationAcceptsStringAndNanos(t *testing.T) {
	m, _ := New(memStore{}, baseline())
	if err := m.Update(patch(t, map[string]any{"cooldown": "5m"})); err != nil {
		t.Fatal(err)
	}
	if m.Current().Cooldown != 5*time.Minute {
		t.Errorf("string duration = %v", m.Current().Cooldown)
	}
	if err := m.Update(patch(t, map[string]any{"cooldown": int64(90 * time.Second)})); err != nil {
		t.Fatal(err)
	}
	if m.Current().Cooldown != 90*time.Second {
		t.Errorf("numeric duration = %v", m.Current().Cooldown)
	}
}

func TestResetReturnsToBaseline(t *testing.T) {
	ks := memStore{}
	m, _ := New(ks, baseline())
	if err := m.Update(patch(t, map[string]any{"enforcement": "enforce"})); err != nil {
		t.Fatal(err)
	}
	var last Runtime
	m.OnChange(func(r Runtime) { last = r })
	if err := m.Reset(); err != nil {
		t.Fatal(err)
	}
	if m.Current().Enforcement != "observe" || len(m.Overridden()) != 0 {
		t.Errorf("reset left state behind: %+v %v", m.Current(), m.Overridden())
	}
	if last.Enforcement != "observe" {
		t.Error("reset must notify subscribers with the baseline")
	}
}

func TestCorruptOverridesFallBackToYAML(t *testing.T) {
	ks := memStore{overridesKey: "{not json"}
	m, err := New(ks, baseline())
	if err != nil {
		t.Fatalf("corrupt overrides must not fail startup: %v", err)
	}
	if m.Current().Enforcement != "observe" {
		t.Error("expected the YAML baseline")
	}
}
