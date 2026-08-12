package config

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/invopop/jsonschema"
	"gopkg.in/yaml.v3"
)

// Duration is a time span. It accepts Go duration syntax ("90s", "30m",
// "24h") plus a "d" suffix for days ("7d"). "0" disables a duration-based
// feature where the field documents that.
type Duration time.Duration

var dayRe = regexp.MustCompile(`^(\d+(?:\.\d+)?)d$`)

// ParseDuration parses a duration string with optional day suffix.
func ParseDuration(s string) (Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if s == "0" {
		return 0, nil
	}
	if m := dayRe.FindStringSubmatch(s); m != nil {
		days, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return Duration(time.Duration(days * 24 * float64(time.Hour))), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q (use e.g. \"90s\", \"30m\", \"24h\", \"7d\")", s)
	}
	return Duration(d), nil
}

// Std returns the value as a standard time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

func (d Duration) String() string {
	v := time.Duration(d)
	if v == 0 {
		return "0"
	}
	if v%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", v/(24*time.Hour))
	}
	return v.String()
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("line %d: duration must be a string like \"24h\" or \"7d\"", node.Line)
	}
	v, err := ParseDuration(s)
	if err != nil {
		return fmt.Errorf("line %d: %w", node.Line, err)
	}
	*d = v
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseDuration(s)
	if err != nil {
		return err
	}
	*d = v
	return nil
}

// JSONSchema customizes the generated schema for Duration fields.
func (Duration) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:        "string",
		Pattern:     `^(0|\d+(\.\d+)?(ns|us|µs|ms|s|m|h|d))+$`,
		Description: "duration such as \"90s\", \"30m\", \"24h\" or \"7d\"",
	}
}

// Size is a byte count. It accepts binary units ("512MiB", "5GiB"),
// decimal units ("2GB") or a plain integer number of bytes.
type Size int64

var sizeRe = regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*([KMGT]i?B|B)?$`)

var sizeUnits = map[string]float64{
	"":   1,
	"B":  1,
	"KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12,
	"KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40,
}

// ParseSize parses a size string.
func ParseSize(s string) (Size, error) {
	s = strings.TrimSpace(s)
	m := sizeRe.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("invalid size %q (use e.g. \"512MiB\", \"5GiB\")", s)
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	unit, ok := sizeUnits[m[2]]
	if !ok {
		return 0, fmt.Errorf("invalid size unit %q", m[2])
	}
	return Size(n * unit), nil
}

// Bytes returns the size as int64 bytes.
func (s Size) Bytes() int64 { return int64(s) }

func (s Size) String() string {
	v := int64(s)
	switch {
	case v >= 1<<30 && v%(1<<30) == 0:
		return fmt.Sprintf("%dGiB", v>>30)
	case v >= 1<<20 && v%(1<<20) == 0:
		return fmt.Sprintf("%dMiB", v>>20)
	case v >= 1<<10 && v%(1<<10) == 0:
		return fmt.Sprintf("%dKiB", v>>10)
	default:
		return strconv.FormatInt(v, 10)
	}
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *Size) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return fmt.Errorf("line %d: size must be a string like \"5GiB\"", node.Line)
	}
	v, err := ParseSize(raw)
	if err != nil {
		return fmt.Errorf("line %d: %w", node.Line, err)
	}
	*s = v
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (s Size) MarshalYAML() (any, error) { return s.String(), nil }

// MarshalJSON implements json.Marshaler.
func (s Size) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// UnmarshalJSON implements json.Unmarshaler.
func (s *Size) UnmarshalJSON(b []byte) error {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	v, err := ParseSize(raw)
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// JSONSchema customizes the generated schema for Size fields.
func (Size) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:        "string",
		Pattern:     `^\d+(\.\d+)?\s*([KMGT]i?B|B)?$`,
		Description: "byte size such as \"512MiB\" or \"5GiB\"",
	}
}

// ClockTime is a local wall-clock time of day in "HH:MM" format.
type ClockTime struct {
	Hour   int
	Minute int
}

// ParseClockTime parses "HH:MM".
func ParseClockTime(s string) (ClockTime, error) {
	t, err := time.Parse("15:04", strings.TrimSpace(s))
	if err != nil {
		return ClockTime{}, fmt.Errorf("invalid time %q (use \"HH:MM\", e.g. \"03:00\")", s)
	}
	return ClockTime{Hour: t.Hour(), Minute: t.Minute()}, nil
}

func (c ClockTime) String() string { return fmt.Sprintf("%02d:%02d", c.Hour, c.Minute) }

// UnmarshalYAML implements yaml.Unmarshaler.
func (c *ClockTime) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return fmt.Errorf("line %d: time of day must be a string like \"03:00\"", node.Line)
	}
	v, err := ParseClockTime(raw)
	if err != nil {
		return fmt.Errorf("line %d: %w", node.Line, err)
	}
	*c = v
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (c ClockTime) MarshalYAML() (any, error) { return c.String(), nil }

// MarshalJSON implements json.Marshaler.
func (c ClockTime) MarshalJSON() ([]byte, error) { return json.Marshal(c.String()) }

// UnmarshalJSON implements json.Unmarshaler.
func (c *ClockTime) UnmarshalJSON(b []byte) error {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	v, err := ParseClockTime(raw)
	if err != nil {
		return err
	}
	*c = v
	return nil
}

// JSONSchema customizes the generated schema for ClockTime fields.
func (ClockTime) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:        "string",
		Pattern:     `^([01]\d|2[0-3]):[0-5]\d$`,
		Description: "local time of day in \"HH:MM\" format",
	}
}
