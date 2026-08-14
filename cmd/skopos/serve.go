package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/julianhintermann-cmd/skopos/internal/api"
	"github.com/julianhintermann-cmd/skopos/internal/app"
	"github.com/julianhintermann-cmd/skopos/internal/config"
	webui "github.com/julianhintermann-cmd/skopos/web"
)

func init() {
	register(&command{
		name:    "serve",
		summary: "run the monitor, firewall and dashboard (default command)",
		run:     runServe,
	})
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	path := fs.String("config", "", "path to config.yaml (default: $SKOPOS_CONFIG or "+config.DefaultPath+")")
	demo := fs.Bool("demo", false, "run with synthetic traffic and no privileges")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, info, err := config.Load(config.ResolvePath(*path))
	if err != nil {
		return err
	}
	if info.Missing {
		fmt.Fprintf(os.Stderr, "no config file at %s — starting with built-in defaults\n", info.Path)
	}
	// SKOPOS_DEMO=1 is an alternative to the flag, handy for `docker run`.
	demoMode := *demo || cfg.Demo || os.Getenv("SKOPOS_DEMO") == "1"

	// Wire the embedded dashboard, if this build has it.
	if f, ok := webui.FS(); ok {
		api.RegisterUI(f)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return app.New(cfg, app.Options{Demo: demoMode, ConfigInfo: info}).Run(ctx)
}
