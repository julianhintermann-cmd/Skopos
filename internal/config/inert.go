package config

import (
	"sort"

	"gopkg.in/yaml.v3"
)

// inertKeys are configuration keys Skopos still accepts and does not act on.
//
// They are listed here rather than only described in doc comments so the
// running process can tell an operator which of the settings *in their file*
// do nothing. A key that is documented as inert is still a key someone wrote
// down expecting an effect, and the gap between those two is exactly what a
// configuration screen exists to close.
var inertKeys = map[string]string{
	"storage.spool_max_size":    "no spool buffer exists; nothing is spooled",
	"storage.archive_at":        "no export job exists; raw flows past their retention are deleted, not exported",
	"capture.rdns":              "reverse-DNS lookups are not implemented",
	"capture.flow_idle_timeout": "the aggregator flushes on its own interval and does not read this",
}

// InertKeys returns the inert keys, sorted, with the reason each does nothing.
func InertKeys() map[string]string {
	out := make(map[string]string, len(inertKeys))
	for k, v := range inertKeys {
		out[k] = v
	}
	return out
}

// InertKeysIn returns the inert keys actually present in the given YAML, in a
// stable order. Listing every inert key on every install would be noise; the
// ones an operator wrote themselves are the ones worth naming, because those
// are the ones they are waiting to see work.
func InertKeysIn(raw []byte) []string {
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil || doc == nil {
		return nil
	}
	var found []string
	for key := range inertKeys {
		if hasPath(doc, splitPath(key)) {
			found = append(found, key)
		}
	}
	sort.Strings(found)
	return found
}

func splitPath(dotted string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(dotted); i++ {
		if dotted[i] == '.' {
			parts = append(parts, dotted[start:i])
			start = i + 1
		}
	}
	return append(parts, dotted[start:])
}

func hasPath(node map[string]any, parts []string) bool {
	if len(parts) == 0 {
		return false
	}
	v, ok := node[parts[0]]
	if !ok {
		return false
	}
	if len(parts) == 1 {
		return true
	}
	child, ok := v.(map[string]any)
	if !ok {
		return false
	}
	return hasPath(child, parts[1:])
}
