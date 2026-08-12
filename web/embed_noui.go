//go:build !embedui

package webui

import "io/fs"

// FS reports that no UI is embedded in this (backend-only) build. The API
// server then serves a small placeholder page instead of the dashboard.
func FS() (fs.FS, bool) { return nil, false }
