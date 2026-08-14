package config

import "time"

// Default returns the configuration Skopos runs with when config.yaml is
// empty or absent. Every value here is documented in the generated
// configuration reference.
func Default() *Config {
	return &Config{
		Interfaces: []string{"auto"},
		Network: Network{
			PrivateRanges: []string{
				"10.0.0.0/8",
				"172.16.0.0/12",
				"192.168.0.0/16",
				"169.254.0.0/16",
				"fc00::/7",
				"fe80::/10",
			},
		},
		Storage: Storage{
			Hot:          "/data",
			Cold:         "/archive",
			HotMaxSize:   5 << 30, // 5 GiB
			SpoolMaxSize: 2 << 30, // 2 GiB
			Retention: Retention{
				RawFlows: Duration(7 * 24 * time.Hour),
				Rollup1m: Duration(90 * 24 * time.Hour),
				Rollup1h: Duration(730 * 24 * time.Hour),
				Rollup1d: 0, // forever
				Alerts:   Duration(365 * 24 * time.Hour),
			},
			ArchiveAt: ClockTime{Hour: 3, Minute: 0},
			Backup: Backup{
				Enabled: true,
				Keep:    14,
				At:      ClockTime{Hour: 3, Minute: 30},
			},
		},
		Capture: Capture{
			SampleThresholdPPS: 80000,
			DNS:                true,
			SNI:                true,
			RDNS:               true,
			Devices:            true,
			FlowFlush:          Duration(10 * time.Second),
			FlowIdleTimeout:    Duration(60 * time.Second),
		},
		Detection: Detection{
			Portscan: Portscan{
				Enabled:  true,
				Window:   Duration(60 * time.Second),
				External: ScanThresholds{Ports: 15, Targets: 20},
				Internal: ScanThresholds{Ports: 30, Targets: 40},
				Severity: "warning",
				Block:    false,
			},
			Rate: RateDetector{
				Enabled:             true,
				Window:              Duration(10 * time.Second),
				MaxNewConnections:   300,
				MaxPacketsPerSecond: 8000,
				Severity:            "warning",
				Block:               false,
			},
			Feeds: Feeds{
				Enabled:  false,
				Lists:    []string{"firehol_level1", "spamhaus_drop"},
				Refresh:  Duration(24 * time.Hour),
				Severity: "critical",
				Block:    false,
			},
			NewDevice: NewDevice{
				Enabled:  true,
				Severity: "info",
			},
			Cooldown: Duration(30 * time.Minute),
			QuietHours: QuietHours{
				Enabled:     false,
				From:        ClockTime{Hour: 23, Minute: 0},
				To:          ClockTime{Hour: 7, Minute: 0},
				MinSeverity: "critical",
			},
		},
		Firewall: Firewall{
			Enforcement:    "observe",
			Backend:        "nftables",
			BlockTTL:       Duration(24 * time.Hour),
			ActionExternal: "drop",
			ActionInternal: "reject",
		},
		Notify: Notify{
			Ntfy: Ntfy{
				Topic: "skopos",
			},
			System: SystemNotify{Enabled: true},
		},
		Server: Server{
			Bind: "0.0.0.0",
			Port: 8686,
			Auth: Auth{
				Username:   "admin",
				SessionTTL: Duration(30 * 24 * time.Hour),
			},
		},
		Logging: Logging{
			Level:      "info",
			File:       true,
			MaxSize:    50 << 20, // 50 MiB
			MaxBackups: 10,
		},
		Metrics: Metrics{Enabled: false},
		Updates: Updates{Check: true},
	}
}
