//go:build linux

package app

import (
	"context"
	"flag"
	"fmt"
	"io"
)

const help = `Veyl — encrypted files at their original authenticated hidden pathname

Usage:
  veyl help [command]
  veyl version
  veyl init [--dir PATH] [--tty] [--autostart] [--explicit-unlock]
  veyl init --legacy-workspace [--dir PATH] [--tty] [--autostart]
  veyl service enable [--config FILE]
  veyl service disable|start|stop|status
  veyl mount   [--config FILE]
  veyl status  [--config FILE]
  veyl lock    [--config FILE]
  veyl unlock  [--config FILE] [--tty]
  veyl unmount [--config FILE]

init selects the current or specified EXISTING EMPTY directory itself. Management
files live in private XDG locations. The basename becomes the hidden name.
Setup does not mount: leave the original parent, close old directory handles,
then run the printed service enable command. Re-enter the absolute original path
after locked readiness. Your existing shell cwd cannot be redirected.
Populated targets are refused; no migration. Never mount over HOME or root.

Automatic desktop startup is opt-in and supervised by systemd --user.
Each new process starts locked; no terminal needs to remain open.
Manual mount stays in the foreground. Direct known-path lookup prompts.
For shells which probe paths while typing, use init --explicit-unlock, then
veyl unlock before entering. Existing configs can set "explicit_unlock": true
while stopped. Filesystem callbacks cannot distinguish user intent.

Config discovery: --config FILE, ./veyl.json, then the registered service default.
Setup prints its external configuration path. Use it when enabling the service.
Existing version 1 configs and explicit legacy workspace setup remain supported.
Use unlock --tty when graphical pinentry is unavailable.
Security limit: same-UID processes and root can access the backing plaintext mount;
lock cannot retract plaintext already returned or erase all caches.
See docs/quick-start.md, docs/cli.md and docs/security.md.
`

type Result struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	State   string `json:"state,omitempty"`
}

func Run(ctx context.Context, args []string, out, errOut io.Writer) int {
	usage := func() int {
		fmt.Fprintln(errOut, "Unknown command or invalid options. Run veyl help for commands and examples.")
		return 2
	}
	if len(args) == 0 {
		return usage()
	}
	command := args[0]
	if command == "--help" || command == "-h" || command == "help" {
		if len(args) > 2 {
			return usage()
		}
		if len(args) == 2 && !known(args[1]) {
			return usage()
		}
		if len(args) == 2 && args[1] == "init" {
			fmt.Fprint(out, initHelp)
		} else if len(args) == 2 && args[1] == "service" {
			fmt.Fprint(out, serviceHelp)
		} else {
			fmt.Fprint(out, help)
		}
		return 0
	}
	if command == "version" {
		if len(args) != 1 {
			return usage()
		}
		printVersion(out)
		return 0
	}
	if command == "service" {
		return serviceCommand(ctx, args[1:], out, errOut)
	}
	if command == "init" {
		return initCommand(ctx, args[1:], out, errOut)
	}
	if !known(command) {
		return usage()
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	config := flags.String("config", "", "version 1 or 2 configuration file")
	tty := false
	if command == "unlock" {
		flags.BoolVar(&tty, "tty", false, "read password from this command's /dev/tty")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprint(out, help)
			return 0
		}
		return usage()
	}
	if flags.NArg() != 0 {
		return usage()
	}
	path, err := discoverConfig(*config)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	result := runCommand(ctx, cfg, command, tty, out)
	writer := out
	if result.Code != 0 {
		writer = errOut
	}
	fmt.Fprintln(writer, result.Message)
	return result.Code
}
func known(s string) bool {
	switch s {
	case "init", "service", "mount", "status", "lock", "unlock", "unmount":
		return true
	}
	return false
}
