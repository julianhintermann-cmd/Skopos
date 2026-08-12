// Command skopos is the single entry point for the Skopos network monitor:
// the long-running server as well as the operational subcommands.
package main

import (
	"fmt"
	"os"
	"sort"
)

// command is one skopos subcommand. Commands register themselves in the
// commands map from their own file's init(), so each milestone can add its
// command next to its implementation.
type command struct {
	name    string
	summary string
	run     func(args []string) error
}

var commands = map[string]*command{}

func register(c *command) { commands[c.name] = c }

func main() {
	args := os.Args[1:]
	name := "serve"
	if len(args) > 0 {
		name = args[0]
		args = args[1:]
	}

	switch name {
	case "help", "-h", "--help":
		usage(os.Stdout)
		return
	}

	cmd, ok := commands[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "skopos: unknown command %q\n\n", name)
		usage(os.Stderr)
		os.Exit(2)
	}
	if err := cmd.run(args); err != nil {
		fmt.Fprintf(os.Stderr, "skopos %s: %v\n", cmd.name, err)
		os.Exit(1)
	}
}

func usage(w *os.File) {
	fmt.Fprintln(w, "Skopos — traffic monitor & firewall management")
	fmt.Fprintln(w, "\nUsage:\n  skopos [command] [flags]")
	fmt.Fprintln(w, "\nCommands:")
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(w, "  %-15s %s\n", n, commands[n].summary)
	}
	fmt.Fprintln(w, "\nRunning skopos without a command starts the server (\"serve\").")
}
