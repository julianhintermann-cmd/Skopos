package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/julianhintermann-cmd/skopos/internal/api"
)

func init() {
	register(&command{
		name:    "hash-password",
		summary: "generate an Argon2id password hash for config.yaml",
		run:     runHashPassword,
	})
}

func runHashPassword(_ []string) error {
	var password string

	// Prefer a no-echo terminal prompt; fall back to reading a line from stdin
	// so the command also works in a pipe.
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Password: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		fmt.Fprint(os.Stderr, "Confirm:  ")
		c, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		if string(b) != string(c) {
			return fmt.Errorf("passwords do not match")
		}
		password = string(b)
	} else {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return err
		}
		password = strings.TrimRight(line, "\r\n")
	}

	if password == "" {
		return fmt.Errorf("password must not be empty")
	}
	hash, err := api.HashPassword(password)
	if err != nil {
		return err
	}
	fmt.Println(hash)
	return nil
}
