package main

import (
	"fmt"

	"github.com/julianhintermann-cmd/skopos/internal/version"
)

func init() {
	register(&command{
		name:    "version",
		summary: "print version information",
		run: func([]string) error {
			fmt.Println(version.String())
			return nil
		},
	})
}
