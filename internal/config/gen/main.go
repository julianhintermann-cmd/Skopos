//go:build ignore

// Command gen writes the generated configuration artifacts: the JSON schema
// (deploy/config.schema.json) and the Markdown reference (docs/configuration.md).
// Run via `go generate ./...` or `make generate`; it locates the repo root by
// walking up to the directory containing go.mod, so the working directory does
// not matter.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/julianhintermann-cmd/skopos/internal/config"
)

func main() {
	root, err := repoRoot()
	if err != nil {
		fail(err)
	}
	// Comment extraction in Schema()/Reference() resolves "./internal/config"
	// relative to the working directory, so anchor it at the repo root.
	if err := os.Chdir(root); err != nil {
		fail(err)
	}

	schema, err := config.Schema()
	if err != nil {
		fail(err)
	}
	writeFile(filepath.Join(root, "deploy", "config.schema.json"), schema)

	ref, err := config.Reference()
	if err != nil {
		fail(err)
	}
	writeFile(filepath.Join(root, "docs", "configuration.md"), ref)

	fmt.Println("wrote deploy/config.schema.json and docs/configuration.md")
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find go.mod above %s", dir)
		}
		dir = parent
	}
}

func writeFile(path string, data []byte) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fail(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "gen:", err)
	os.Exit(1)
}
