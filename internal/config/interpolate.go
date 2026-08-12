package config

import (
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
)

// envRe matches ${VAR} and ${VAR:-default}. Anything else — including bare
// "$argon2id$…" hashes — passes through untouched.
var envRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}`)

// interpolateEnv walks a decoded config and expands ${VAR} / ${VAR:-default}
// references in every string-valued field against the process environment.
//
// Interpolation runs after YAML parsing and touches only real values, never
// comments or keys, so a commented-out ${VAR} example can never cause a
// startup failure. A reference without a default whose variable is unset is
// an error, so missing secrets fail loudly instead of running empty.
func interpolateEnv(v any) error {
	var missing []string
	walkStrings(reflect.ValueOf(v), func(s string) string {
		return envRe.ReplaceAllStringFunc(s, func(m string) string {
			groups := envRe.FindStringSubmatch(m)
			name := groups[1]
			hasDefault := strings.HasPrefix(groups[2], ":-")
			if val, ok := os.LookupEnv(name); ok {
				return val
			}
			if hasDefault {
				return groups[3]
			}
			missing = append(missing, name)
			return m
		})
	})
	if len(missing) > 0 {
		return fmt.Errorf("environment variable(s) referenced in config but not set: %s (use ${VAR:-default} for optional values)",
			strings.Join(dedupe(missing), ", "))
	}
	return nil
}

// walkStrings recursively applies fn to every settable string field reachable
// from v, descending into structs, pointers, slices, arrays and maps.
func walkStrings(v reflect.Value, fn func(string) string) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			walkStrings(v.Elem(), fn)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			if f.CanSet() {
				walkStrings(f, fn)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			walkStrings(v.Index(i), fn)
		}
	case reflect.Map:
		for _, key := range v.MapKeys() {
			// Map values are not addressable; rebuild and re-set them.
			elem := v.MapIndex(key)
			if elem.Kind() == reflect.String {
				nv := reflect.New(elem.Type()).Elem()
				nv.SetString(fn(elem.String()))
				v.SetMapIndex(key, nv)
			}
		}
	case reflect.String:
		if v.CanSet() {
			v.SetString(fn(v.String()))
		}
	}
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
