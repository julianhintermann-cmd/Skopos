package main

import (
	"flag"
	"fmt"

	"github.com/julianhintermann-cmd/skopos/internal/config"
)

func init() {
	register(&command{
		name:    "validate",
		summary: "load and validate the configuration, then exit",
		run:     runValidate,
	})
}

func runValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	path := fs.String("config", "", "path to config.yaml (default: $SKOPOS_CONFIG or "+config.DefaultPath+")")
	if err := fs.Parse(args); err != nil {
		return err
	}

	resolved := config.ResolvePath(*path)
	cfg, info, err := config.Load(resolved)
	if err != nil {
		return err
	}
	if info.Missing {
		fmt.Printf("no config file at %s — configuration is valid using built-in defaults\n", info.Path)
	} else {
		fmt.Printf("%s is valid\n", info.Path)
	}
	if cfg.Server.Auth.Mode == "none" {
		fmt.Println("note: authentication is disabled (server.auth.mode: none) — only expose Skopos on a trusted network")
	}
	if cfg.Firewall.Enforcement == "observe" {
		fmt.Println("note: firewall is in observe mode — blocks are logged but not applied")
	}
	return nil
}
