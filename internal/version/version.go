// Package version carries build-time version information, injected via
// -ldflags at release build time (see Makefile and release workflow).
package version

import "runtime"

var (
	// Version is the semantic version (e.g. "0.1.0") or "dev" for local builds.
	Version = "dev"
	// Commit is the short git commit hash the binary was built from.
	Commit = "unknown"
	// Date is the UTC build timestamp in RFC 3339 format.
	Date = "unknown"
)

// String returns a single-line human-readable version description.
func String() string {
	return "skopos " + Version + " (" + Commit + ", " + Date + ", " + runtime.Version() + ")"
}
