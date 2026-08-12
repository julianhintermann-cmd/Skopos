package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/config"
)

func init() {
	register(&command{
		name:    "health",
		summary: "probe the local API health endpoint (for container HEALTHCHECK)",
		run:     runHealth,
	})
}

// runHealth queries the local /api/health endpoint and exits non-zero when the
// service is unhealthy. It needs no shell, so it works as the HEALTHCHECK in a
// distroless image.
func runHealth(args []string) error {
	fs := flag.NewFlagSet("health", flag.ContinueOnError)
	path := fs.String("config", "", "path to config.yaml (to discover the port)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, _, err := config.Load(config.ResolvePath(*path))
	if err != nil {
		return err
	}

	url := fmt.Sprintf("http://127.0.0.1:%d/api/health", cfg.Server.Port)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("health probe failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy: HTTP %d", resp.StatusCode)
	}
	var h struct {
		OK bool `json:"ok"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		return fmt.Errorf("bad health response: %w", err)
	}
	if !h.OK {
		return fmt.Errorf("unhealthy")
	}
	fmt.Println("ok")
	return nil
}
