package config

import (
	"strings"
	"testing"
	"time"
)

func TestDefaultsAreValid(t *testing.T) {
	cfg := Default()
	cfg.normalize()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config must validate, got: %v", err)
	}
}

func TestParseEmptyYieldsDefaults(t *testing.T) {
	cfg, err := Parse(nil)
	if err != nil {
		t.Fatalf("empty config must parse, got: %v", err)
	}
	if got := cfg.Server.Port; got != 8686 {
		t.Errorf("default port = %d, want 8686", got)
	}
	if cfg.Firewall.Enforcement != "observe" {
		t.Errorf("default enforcement = %q, want observe", cfg.Firewall.Enforcement)
	}
	if cfg.Server.Auth.Mode != "none" {
		t.Errorf("auth mode without hash = %q, want none", cfg.Server.Auth.Mode)
	}
}

func TestParseOverridesMergeWithDefaults(t *testing.T) {
	cfg, err := Parse([]byte(`
interfaces: [eth0, eth1]
server:
  port: 9000
detection:
  portscan:
    external: {ports: 5, targets: 6}
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Interfaces) != 2 || cfg.Interfaces[0] != "eth0" {
		t.Errorf("interfaces = %v", cfg.Interfaces)
	}
	if cfg.Server.Port != 9000 {
		t.Errorf("port = %d, want 9000", cfg.Server.Port)
	}
	// Untouched siblings keep their defaults.
	if cfg.Server.Bind != "0.0.0.0" {
		t.Errorf("bind lost its default: %q", cfg.Server.Bind)
	}
	if cfg.Detection.Portscan.External.Ports != 5 {
		t.Errorf("external.ports = %d, want 5", cfg.Detection.Portscan.External.Ports)
	}
	if cfg.Detection.Portscan.Internal.Ports != 30 {
		t.Errorf("internal.ports lost its default: %d", cfg.Detection.Portscan.Internal.Ports)
	}
	if cfg.Detection.Portscan.Window.Std() != 60*time.Second {
		t.Errorf("window lost its default: %v", cfg.Detection.Portscan.Window)
	}
}

func TestParseRejectsUnknownKeys(t *testing.T) {
	_, err := Parse([]byte("intrefaces: [eth0]\n"))
	if err == nil || !strings.Contains(err.Error(), "intrefaces") {
		t.Fatalf("want unknown-key error naming the key, got: %v", err)
	}
}

func TestEnvInterpolation(t *testing.T) {
	t.Setenv("SKOPOS_TEST_TOPIC", "alerts")
	cfg, err := Parse([]byte(`
notify:
  ntfy:
    url: https://ntfy.example.com
    topic: ${SKOPOS_TEST_TOPIC}
    token: ${SKOPOS_TEST_UNSET:-fallback}
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Notify.Ntfy.Topic != "alerts" {
		t.Errorf("topic = %q, want alerts", cfg.Notify.Ntfy.Topic)
	}
	if cfg.Notify.Ntfy.Token != "fallback" {
		t.Errorf("token = %q, want fallback", cfg.Notify.Ntfy.Token)
	}
}

func TestEnvInterpolationMissingFailsLoudly(t *testing.T) {
	_, err := Parse([]byte("notify:\n  ntfy:\n    url: ${SKOPOS_TEST_DEFINITELY_UNSET}\n"))
	if err == nil || !strings.Contains(err.Error(), "SKOPOS_TEST_DEFINITELY_UNSET") {
		t.Fatalf("want missing-env error naming the variable, got: %v", err)
	}
}

func TestArgonHashSurvivesInterpolation(t *testing.T) {
	hash := "$argon2id$v=19$m=65536,t=3,p=2$abc$def"
	cfg, err := Parse([]byte("server:\n  auth:\n    password_hash: \"" + hash + "\"\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Server.Auth.PasswordHash != hash {
		t.Errorf("hash mangled by interpolation: %q", cfg.Server.Auth.PasswordHash)
	}
	if cfg.Server.Auth.Mode != "single_admin" {
		t.Errorf("auth mode with hash = %q, want single_admin", cfg.Server.Auth.Mode)
	}
}

func TestValidationCollectsAllProblems(t *testing.T) {
	_, err := Parse([]byte(`
server: {port: 99999}
firewall: {enforcement: yolo}
logging: {level: chatty}
`))
	if err == nil {
		t.Fatal("want validation error")
	}
	for _, want := range []string{"server.port", "firewall.enforcement", "logging.level"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %s, got:\n%v", want, err)
		}
	}
}

func TestDurationParsing(t *testing.T) {
	cases := map[string]time.Duration{
		"90s": 90 * time.Second,
		"30m": 30 * time.Minute,
		"24h": 24 * time.Hour,
		"7d":  7 * 24 * time.Hour,
		"0":   0,
	}
	for in, want := range cases {
		got, err := ParseDuration(in)
		if err != nil {
			t.Errorf("ParseDuration(%q): %v", in, err)
			continue
		}
		if got.Std() != want {
			t.Errorf("ParseDuration(%q) = %v, want %v", in, got.Std(), want)
		}
	}
	if _, err := ParseDuration("7 days"); err == nil {
		t.Error("ParseDuration(\"7 days\") should fail")
	}
}

func TestSizeParsing(t *testing.T) {
	cases := map[string]int64{
		"5GiB":   5 << 30,
		"512MiB": 512 << 20,
		"2GB":    2e9,
		"1024":   1024,
	}
	for in, want := range cases {
		got, err := ParseSize(in)
		if err != nil {
			t.Errorf("ParseSize(%q): %v", in, err)
			continue
		}
		if got.Bytes() != want {
			t.Errorf("ParseSize(%q) = %d, want %d", in, got.Bytes(), want)
		}
	}
	if _, err := ParseSize("fünf GiB"); err == nil {
		t.Error("ParseSize(\"fünf GiB\") should fail")
	}
}

func TestClockTimeParsing(t *testing.T) {
	got, err := ParseClockTime("03:00")
	if err != nil || got.Hour != 3 || got.Minute != 0 {
		t.Errorf("ParseClockTime(03:00) = %v, %v", got, err)
	}
	if _, err := ParseClockTime("25:00"); err == nil {
		t.Error("ParseClockTime(25:00) should fail")
	}
}

func TestPrivacySwitchesCanBeTurnedOff(t *testing.T) {
	// The half of the privacy gate that lives here: both switches default to
	// true, so "false" has to survive being decoded over the default. If it
	// does not, the parser downstream never hears about the operator's choice.
	cfg, err := Parse([]byte("capture:\n  dns: false\n  sni: false\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Capture.DNS {
		t.Error("capture.dns: false was lost in the merge with the defaults")
	}
	if cfg.Capture.SNI {
		t.Error("capture.sni: false was lost in the merge with the defaults")
	}
	// Untouched siblings keep their defaults.
	if !cfg.Capture.Devices {
		t.Error("capture.devices lost its default")
	}
}

func TestLoggingFileCanBeTurnedOff(t *testing.T) {
	cfg, err := Parse([]byte("logging:\n  file: false\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Logging.File {
		t.Error("logging.file: false was lost in the merge with the defaults")
	}
}

func TestAlertRetentionDefaultAndOverride(t *testing.T) {
	if got := Default().Storage.Retention.Alerts.Std(); got != 365*24*time.Hour {
		t.Errorf("default alert retention = %v, want 365d", got)
	}
	cfg, err := Parse([]byte("storage:\n  retention:\n    alerts: 30d\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := cfg.Storage.Retention.Alerts.Std(); got != 30*24*time.Hour {
		t.Errorf("alert retention = %v, want 30d", got)
	}
	// "0" is the documented way to keep alerts forever and must validate.
	zero, err := Parse([]byte("storage:\n  retention:\n    alerts: 0\n"))
	if err != nil {
		t.Fatalf("alerts: 0 must be accepted: %v", err)
	}
	if zero.Storage.Retention.Alerts != 0 {
		t.Errorf("alerts: 0 = %v, want 0", zero.Storage.Retention.Alerts)
	}
}

func TestNegativeAlertRetentionIsRejected(t *testing.T) {
	_, err := Parse([]byte("storage:\n  retention:\n    alerts: -5h\n"))
	if err == nil || !strings.Contains(err.Error(), "storage.retention.alerts") {
		t.Fatalf("want an error naming storage.retention.alerts, got: %v", err)
	}
}
