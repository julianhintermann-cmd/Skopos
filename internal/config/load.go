package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// DefaultPath is where the container image expects config.yaml; override
// with the SKOPOS_CONFIG environment variable or the --config flag.
const DefaultPath = "/config/config.yaml"

// LoadInfo describes where the effective configuration came from.
type LoadInfo struct {
	// Path is the file that was read (or would have been read).
	Path string
	// Missing is true when the file does not exist and pure defaults are
	// in effect.
	Missing bool
}

// ResolvePath returns the config path from, in order: the explicit flag
// value, the SKOPOS_CONFIG environment variable, or the built-in default.
func ResolvePath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv("SKOPOS_CONFIG"); env != "" {
		return env
	}
	return DefaultPath
}

// Load reads, interpolates, strictly parses and validates the configuration
// file at path. A missing file is not an error: Skopos then runs on
// defaults (LoadInfo.Missing reports it so callers can log the fact).
func Load(path string) (*Config, LoadInfo, error) {
	info := LoadInfo{Path: path}

	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		info.Missing = true
		cfg := Default()
		cfg.normalize()
		if err := cfg.Validate(); err != nil {
			return nil, info, err
		}
		return cfg, info, nil
	}
	if err != nil {
		return nil, info, fmt.Errorf("reading %s: %w", path, err)
	}

	cfg, err := Parse(raw)
	if err != nil {
		return nil, info, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, info, nil
}

// Parse strictly decodes a raw YAML document on top of the defaults, then
// interpolates ${ENV} references in string values and validates the result.
func Parse(raw []byte) (*Config, error) {
	cfg := Default()
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		if err.Error() == "EOF" {
			// Empty file: pure defaults.
		} else {
			var typeErr *yaml.TypeError
			if errors.As(err, &typeErr) {
				return nil, fmt.Errorf("invalid configuration:\n  %s", joinLines(typeErr.Errors))
			}
			return nil, fmt.Errorf("invalid YAML: %w", err)
		}
	}

	if err := interpolateEnv(cfg); err != nil {
		return nil, err
	}
	cfg.normalize()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// normalize fills computed defaults that depend on other fields.
func (c *Config) normalize() {
	// Auth mode default: single_admin as soon as a password hash is
	// configured, otherwise none (with a prominent warning at startup).
	if c.Server.Auth.Mode == "" {
		if c.Server.Auth.PasswordHash != "" {
			c.Server.Auth.Mode = "single_admin"
		} else {
			c.Server.Auth.Mode = "none"
		}
	}
}

func joinLines(lines []string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "\n  "
		}
		out += l
	}
	return out
}
