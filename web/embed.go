//go:build embedui

// Package webui embeds the built dashboard into the binary. The embedui build
// tag keeps this file out of backend-only builds, where web/dist may not
// exist; `make build` builds the web assets first and then compiles with the
// tag so a release binary serves the UI from a single file.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS returns the embedded dashboard filesystem rooted at the asset directory.
func FS() (fs.FS, bool) {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil, false
	}
	return sub, true
}
