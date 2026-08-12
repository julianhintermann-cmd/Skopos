package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// repoFile resolves a path relative to the repository root regardless of the
// test's working directory.
func repoFile(t *testing.T, rel string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine caller path")
	}
	root := filepath.Join(filepath.Dir(thisFile), "..", "..")
	return filepath.Join(root, rel)
}

func TestExampleConfigParsesAndValidates(t *testing.T) {
	raw, err := os.ReadFile(repoFile(t, "deploy/config.example.yaml"))
	if err != nil {
		t.Fatalf("reading example: %v", err)
	}
	// The example references optional env vars via ${VAR:-} so it must parse
	// with none of them set.
	if _, err := Parse(raw); err != nil {
		t.Fatalf("deploy/config.example.yaml must parse and validate:\n%v", err)
	}
}

func TestExampleCoversEveryTopLevelKey(t *testing.T) {
	raw, err := os.ReadFile(repoFile(t, "deploy/config.example.yaml"))
	if err != nil {
		t.Fatalf("reading example: %v", err)
	}
	for _, key := range sortedTopLevelKeys() {
		// Every top-level config section should appear in the example so
		// users have a documented starting point for each one.
		if !containsKey(raw, key) {
			t.Errorf("deploy/config.example.yaml is missing top-level key %q", key)
		}
	}
}

func containsKey(raw []byte, key string) bool {
	// crude but sufficient: look for "\n<key>:" or start-of-file "<key>:"
	needle := "\n" + key + ":"
	return len(raw) > 0 && (string(raw[:min(len(raw), len(key)+1)]) == key+":" ||
		bytesContains(raw, needle))
}

func bytesContains(haystack []byte, needle string) bool {
	return len(needle) > 0 && indexOf(haystack, needle) >= 0
}

func indexOf(haystack []byte, needle string) int {
	n := []byte(needle)
	for i := 0; i+len(n) <= len(haystack); i++ {
		if string(haystack[i:i+len(n)]) == needle {
			return i
		}
	}
	return -1
}

func TestSchemaIsValidJSON(t *testing.T) {
	schema, err := Schema()
	if err != nil {
		t.Fatalf("Schema(): %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(schema, &m); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	if m["title"] != "Skopos configuration" {
		t.Errorf("schema title = %v", m["title"])
	}
}
