package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/julianhintermann-cmd/skopos/internal/config"
)

// logging.file defaulted to true and wrote nothing, so these tests assert both
// halves of the switch: a file that exists and holds the log when it is on,
// and no file at all when it is off.

func loggingConfig(t *testing.T, file bool, maxSize config.Size, maxBackups int) *config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Storage.Cold = t.TempDir()
	cfg.Logging.File = file
	cfg.Logging.MaxSize = maxSize
	cfg.Logging.MaxBackups = maxBackups
	return cfg
}

func TestLoggingFileWritesStructuredLogs(t *testing.T) {
	cfg := loggingConfig(t, true, 1<<20, 3)

	log, closeLog := buildLogger(cfg)
	log.Info("capture started", "iface", "eth0")
	if err := closeLog(); err != nil {
		t.Fatalf("closing the log: %v", err)
	}

	path := filepath.Join(cfg.Storage.Cold, "logs", "skopos.log")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("logging.file is on but %s does not exist: %v", path, err)
	}
	var rec map[string]any
	line := strings.TrimSpace(strings.Split(string(raw), "\n")[0])
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatalf("log line is not JSON: %q", line)
	}
	if rec["msg"] != "capture started" || rec["iface"] != "eth0" {
		t.Errorf("log record = %v, want the message and its attributes", rec)
	}
}

func TestLoggingFileOffWritesNothing(t *testing.T) {
	cfg := loggingConfig(t, false, 1<<20, 3)

	log, closeLog := buildLogger(cfg)
	log.Info("capture started")
	_ = closeLog()

	if _, err := os.Stat(filepath.Join(cfg.Storage.Cold, "logs")); !os.IsNotExist(err) {
		t.Errorf("logging.file is off but the log directory was created anyway (err=%v)", err)
	}
}

func TestLoggingFileSurvivesUnreachableColdStorage(t *testing.T) {
	// Cold storage is a NAS share that may be unmounted. Skopos must keep
	// monitoring and say so, not fail to start.
	cfg := loggingConfig(t, true, 1<<20, 3)
	notADir := filepath.Join(cfg.Storage.Cold, "archive-is-a-file")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Storage.Cold = notADir

	log, closeLog := buildLogger(cfg)
	if log == nil {
		t.Fatal("buildLogger must always return a usable logger")
	}
	log.Info("still monitoring")
	if err := closeLog(); err != nil {
		t.Errorf("closing a logger that never opened a file: %v", err)
	}
}

func TestLogFileRotatesAndKeepsOnlyMaxBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skopos.log")
	const maxBackups = 2
	lf, err := openLogFile(path, 64, maxBackups)
	if err != nil {
		t.Fatalf("openLogFile: %v", err)
	}
	defer func() { _ = lf.Close() }()

	// Each write is half the cap, so every second one rotates. Five rotations
	// is well past the backup count.
	line := make([]byte, 32)
	for i := range line {
		line[i] = 'x'
	}
	for i := 0; i < 12; i++ {
		if _, err := lf.Write(line); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	for _, name := range []string{"skopos.log", "skopos.log.1", "skopos.log.2"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s should exist after rotation: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "skopos.log.3")); !os.IsNotExist(err) {
		t.Errorf("max_backups=%d but skopos.log.3 exists (err=%v)", maxBackups, err)
	}
	// The whole point of the cap: no file may exceed max_size.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > 64 {
			t.Errorf("%s is %d bytes, over the 64-byte max_size", e.Name(), info.Size())
		}
	}
}

func TestLogFileWithoutRotationKeepsGrowing(t *testing.T) {
	// max_size 0 is documented as "no rotation"; it must not rotate on every
	// write instead.
	dir := t.TempDir()
	path := filepath.Join(dir, "skopos.log")
	lf, err := openLogFile(path, 0, 3)
	if err != nil {
		t.Fatalf("openLogFile: %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, err := lf.Write([]byte("0123456789")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := lf.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 100 {
		t.Errorf("log size = %d, want 100 (max_size 0 must not rotate)", info.Size())
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Errorf("max_size 0 rotated anyway (err=%v)", err)
	}
}

func TestLogFileReopenAppendsRatherThanTruncates(t *testing.T) {
	// A restart must not throw away the log it was about to be read for.
	dir := t.TempDir()
	path := filepath.Join(dir, "skopos.log")
	for i := 0; i < 2; i++ {
		lf, err := openLogFile(path, 1<<20, 3)
		if err != nil {
			t.Fatalf("openLogFile: %v", err)
		}
		if _, err := lf.Write([]byte("run\n")); err != nil {
			t.Fatal(err)
		}
		if err := lf.Close(); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "run\nrun\n" {
		t.Errorf("log = %q, want both runs", raw)
	}
}
