package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/invopop/jsonschema"
)

// Reference renders the configuration reference as Markdown, derived from
// the same schema that powers editor completion, so the documentation can
// never drift from the code. Defaults are taken from Default().
func Reference() ([]byte, error) {
	r := &jsonschema.Reflector{ExpandedStruct: true, DoNotReference: true}
	if err := r.AddGoComments("github.com/julianhintermann-cmd/skopos", "./internal/config"); err != nil {
		_ = err
	}
	schema := r.Reflect(&Config{})

	defaults, err := defaultsMap()
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	b.WriteString("# Configuration reference\n\n")
	b.WriteString("_This file is generated from the config struct by `go generate ./...`. Do not edit by hand._\n\n")
	b.WriteString("Skopos is configured by a single YAML file (default `/config/config.yaml`, ")
	b.WriteString("override with `SKOPOS_CONFIG` or `--config`). Every option has a working ")
	b.WriteString("default; an empty file is valid. String values support `${VAR}` and ")
	b.WriteString("`${VAR:-default}` environment interpolation.\n\n")
	b.WriteString("| Option | Type | Default | Description |\n")
	b.WriteString("| ------ | ---- | ------- | ----------- |\n")

	walkSchema(&b, schema, "", defaults)

	b.WriteString("\nSee [`deploy/config.example.yaml`](../deploy/config.example.yaml) for a fully-commented example.\n")
	return b.Bytes(), nil
}

func walkSchema(b *bytes.Buffer, schema *jsonschema.Schema, prefix string, defaults map[string]any) {
	if schema.Properties == nil {
		return
	}
	for pair := schema.Properties.Oldest(); pair != nil; pair = pair.Next() {
		key := pair.Key
		prop := pair.Value
		if prop == nil {
			continue
		}
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		if prop.Properties != nil && prop.Properties.Len() > 0 {
			// Nested object: emit a section row then recurse.
			fmt.Fprintf(b, "| **`%s`** | object | | %s |\n", path, oneLine(prop.Description))
			walkSchema(b, prop, path, childDefaults(defaults, key))
			continue
		}
		typ := prop.Type
		if typ == "" && prop.Items != nil {
			typ = "array"
		}
		if prop.Items != nil {
			typ = "list of " + prop.Items.Type
		}
		fmt.Fprintf(b, "| `%s` | %s | %s | %s |\n", path, typ, defaultCell(defaults, key), oneLine(prop.Description))
	}
}

func defaultsMap() (map[string]any, error) {
	raw, err := json.Marshal(Default())
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func childDefaults(defaults map[string]any, key string) map[string]any {
	if defaults == nil {
		return nil
	}
	if child, ok := defaults[key].(map[string]any); ok {
		return child
	}
	return nil
}

func defaultCell(defaults map[string]any, key string) string {
	if defaults == nil {
		return ""
	}
	v, ok := defaults[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		if t == "" {
			return ""
		}
		return "`" + t + "`"
	case bool:
		return fmt.Sprintf("`%v`", t)
	case float64:
		return fmt.Sprintf("`%g`", t)
	case []any:
		if len(t) == 0 {
			return ""
		}
		parts := make([]string, len(t))
		for i, e := range t {
			parts[i] = fmt.Sprintf("%v", e)
		}
		return "`[" + strings.Join(parts, ", ") + "]`"
	default:
		return ""
	}
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.Join(strings.Fields(s), " ")
}

// sortedTopLevelKeys is used by tests to assert coverage.
func sortedTopLevelKeys() []string {
	m, _ := defaultsMap()
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
