package config

import (
	"bytes"
	"encoding/json"

	"github.com/invopop/jsonschema"
)

// Schema returns the JSON Schema (draft 2020-12) for the configuration
// file, derived from the Config struct and its field doc comments. It is
// published so editors with yaml-language-server can offer completion and
// validation, and it drives the generated configuration reference.
func Schema() ([]byte, error) {
	r := &jsonschema.Reflector{
		// Field doc comments become schema descriptions.
		DoNotReference: true,
		ExpandedStruct: true,
	}
	if err := r.AddGoComments("github.com/julianhintermann-cmd/skopos", "./internal/config"); err != nil {
		// Comment extraction is best-effort: without the source tree
		// (e.g. in a stripped binary) the schema is still structurally
		// correct, just without descriptions.
		_ = err
	}
	schema := r.Reflect(&Config{})
	schema.ID = "https://github.com/julianhintermann-cmd/skopos/config.schema.json"
	schema.Title = "Skopos configuration"

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(schema); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
