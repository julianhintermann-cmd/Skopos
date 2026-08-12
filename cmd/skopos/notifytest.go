package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/julianhintermann-cmd/skopos/internal/config"
	"github.com/julianhintermann-cmd/skopos/internal/notify"
)

func init() {
	register(&command{
		name:    "notify-test",
		summary: "send a test notification to the configured channels",
		run:     runNotifyTest,
	})
}

func runNotifyTest(args []string) error {
	fs := flag.NewFlagSet("notify-test", flag.ContinueOnError)
	path := fs.String("config", "", "path to config.yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, _, err := config.Load(config.ResolvePath(*path))
	if err != nil {
		return err
	}
	dispatcher := notify.FromConfig(cfg)
	if !dispatcher.HasChannels() {
		return fmt.Errorf("no notification channels configured (set notify.ntfy.url or notify.webhook.url)")
	}
	if err := dispatcher.Test(context.Background()); err != nil {
		return fmt.Errorf("test notification failed: %w", err)
	}
	fmt.Println("test notification sent successfully")
	return nil
}
