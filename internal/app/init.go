//go:build linux

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/poizdev/veyl/internal/auth"
	"github.com/poizdev/veyl/internal/credential"
	"github.com/poizdev/veyl/internal/policy"
	"github.com/poizdev/veyl/internal/storage"
)

const initHelp = `Protect the selected empty directory at its original pathname.

Usage:
  veyl init [--dir PATH] [--tty] [--autostart] [--explicit-unlock]
  veyl init --legacy-workspace [--dir PATH] [--tty] [--autostart]

Without --dir, select the current working directory. The target must already
exist and be empty. Populated directories and existing workspaces are refused.
The basename is the protected virtual name. Setup creates no management files
inside it: configuration is under XDG_CONFIG_HOME, encrypted persistent stores
under XDG_DATA_HOME, and control resources under private XDG_RUNTIME_DIR.

Setup alone does not mount. Leave the original parent in every shell and close
old directory handles, then run the printed service enable command. Re-enter
using the absolute original pathname after confirmed locked startup. A running
shell cannot be redirected transparently. --autostart is accepted only when the
caller is already outside the original parent. No root service or lingering.
Activation guards the empty physical target with mode 0500; it stays empty and
read-only after stop/crash. Decrypted contents exist only through authenticated
Veyl access. The protected name is absent from all parent enumeration, even
while unlocked. Never mount over HOME or the system root.

Graphical pinentry confirms the new password twice; --tty uses /dev/tty.
Filesystem probes from fish or other applications can request authentication.
Use --explicit-unlock to suppress all filesystem-triggered prompts, and run
veyl unlock before entering. No filesystem request can prove user intent.

--legacy-workspace explicitly selects the old version 1 layout, creating
store/, mount/, runtime/ and veyl.json inside the workspace. All four names must
be absent. Unrelated workspace files are preserved. Existing v1 configs still
work unchanged. Never silently reinterpret an old workspace.

No imports, migration, automatic deletion, or publication. Partial setup is
retained for inspection. See docs/quick-start.md and docs/security.md.
`

func initLegacyCommand(ctx context.Context, args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dir := flags.String("dir", ".", "workspace directory (default: current working directory)")
	autostart := flags.Bool("autostart", false, "explicitly enable automatic desktop startup after setup")
	tty := flags.Bool("tty", false, "prompt on /dev/tty instead of graphical pinentry")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprint(out, initHelp)
			return 0
		}
		fmt.Fprintln(errOut, "Usage: veyl init [--dir PATH] [--tty] [--autostart]")
		return 2
	}
	if flags.NArg() != 0 || *dir == "" {
		fmt.Fprintln(errOut, "Usage: veyl init [--dir PATH] [--tty] [--autostart]")
		return 2
	}
	base, err := filepath.Abs(*dir)
	if err != nil || strings.ContainsAny(base, "\x00\r\n") {
		fmt.Fprintln(errOut, "Choose a workspace directory with a valid path.")
		return 2
	}
	if len(filepath.Join(base, "runtime", "control.sock")) > 107 {
		fmt.Fprintln(errOut, "Destination path is too long for a Linux control socket. Choose a shorter path.")
		return 2
	}
	identity, err := inspectInitDestination(base)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	if ctx.Err() != nil {
		fmt.Fprintln(errOut, "Setup canceled; no files created.")
		return 4
	}
	for _, name := range []string{"gocryptfs", "fusermount3"} {
		if _, err := exec.LookPath(name); err != nil {
			fmt.Fprintln(errOut, "Install gocryptfs and fuse3 before running setup.")
			return 1
		}
	}
	prompt := credential.ReadTTY
	if !*tty {
		agent := credential.New("auto", filepath.Join(base, "mount"))
		prompt = func(ctx context.Context) ([]byte, error) {
			r, err := agent.Authenticate(ctx, auth.Request{Directory: base})
			return r.Proof, err
		}
	}
	password, result := setupPassword(ctx, prompt, out)
	if result.Code != 0 {
		fmt.Fprintln(errOut, result.Message)
		return result.Code
	}
	defer clear(password)
	if ctx.Err() != nil {
		fmt.Fprintln(errOut, "Setup canceled; no files created.")
		return 4
	}
	// Prompting can take time; recheck conflicts and the workspace identity
	// before creating anything. Exclusive creates remain the final protection.
	current, err := inspectInitDestination(base)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	if identity != nil {
		if current == nil || !os.SameFile(identity, current) {
			fmt.Fprintln(errOut, "Workspace changed during password entry. Nothing was created; retry setup.")
			return 2
		}
	} else {
		if current != nil {
			fmt.Fprintln(errOut, "Destination appeared during password entry. Nothing was overwritten; retry setup.")
			return 2
		}
		if err := os.Mkdir(base, 0700); err != nil {
			fmt.Fprintln(errOut, "Cannot create destination; it may already exist. Nothing was overwritten.")
			return 2
		}
	}
	partial := func() int {
		fmt.Fprintf(errOut, "Setup incomplete. Newly created Veyl paths were retained in %s; unrelated files were not modified or deleted. Inspect store/, mount/, runtime/ and veyl.json before retrying.\n", base)
		return 1
	}
	readOnly := false
	c := Config{ReadOnly: &readOnly, Version: 1, Store: filepath.Join(base, "store"), Mountpoint: filepath.Join(base, "mount"), RuntimeDir: filepath.Join(base, "runtime"), HiddenName: policy.GhostName, CredentialAgent: "auto"}
	for _, path := range []string{c.Store, c.Mountpoint, c.RuntimeDir} {
		if err := os.Mkdir(path, 0700); err != nil {
			return partial()
		}
	}
	if err := storage.Initialize(ctx, c.Store, password); err != nil {
		return partial()
	}
	clear(password) // Service setup must not extend credential lifetime.
	if ctx.Err() != nil {
		return partial()
	}
	path := filepath.Join(base, "veyl.json")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return partial()
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	err = enc.Encode(c)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return partial()
	}
	fmt.Fprintf(out, "Encrypted store created: %s\nConfiguration: %s\nHidden virtual path: %s (omitted even from ls -a).\nMount with: veyl mount --config %q\nThe store is empty. After mounting, authenticate and create files through the printed hidden path.\n", c.Store, path, filepath.Join(c.Mountpoint, c.HiddenName), path)
	if *autostart {
		result := enableService(ctx, path)
		writer := out
		if result.Code != 0 {
			writer = errOut
			fmt.Fprintln(writer, "Encrypted store and configuration are ready; automatic startup setup needs attention. They were preserved.")
		}
		fmt.Fprintln(writer, result.Message)
		return result.Code
	}
	fmt.Fprintf(out, "Optional desktop startup: veyl service enable --config %q\nThis is opt-in; no service was enabled.\n", path)
	return 0
}

func setupPassword(ctx context.Context, prompt func(context.Context) ([]byte, error), out io.Writer) ([]byte, Result) {
	fmt.Fprintln(out, "Choose a password for the new encrypted store.")
	first, err := prompt(ctx)
	if err != nil {
		clear(first)
		return nil, setupPromptError(err)
	}
	fmt.Fprintln(out, "Repeat the same password to confirm.")
	second, err := prompt(ctx)
	defer clear(second)
	if err != nil {
		clear(first)
		return nil, setupPromptError(err)
	}
	if len(first) == 0 || len(first) > 1024 || bytes.ContainsAny(first, "\x00\r\n") || !bytes.Equal(first, second) {
		clear(first)
		return nil, Result{Code: 4, Message: "Passwords are empty, unsupported, or do not match. Setup canceled; no files created."}
	}
	return first, Result{}
}

func setupPromptError(err error) Result {
	r := authResult(err)
	if r.Code == 4 {
		r.Message = "Password entry canceled or expired. Setup stopped; no files created."
	} else {
		r.Message = "Cannot collect password. Check graphical pinentry or retry veyl init [--dir PATH] --tty. No files created."
	}
	return r
}

// inspectInitDestination inspects only the workspace and Veyl's reserved names;
// it never enumerates unrelated workspace files or follows their symlinks.
func inspectInitDestination(base string) (os.FileInfo, error) {
	info, err := os.Lstat(base)
	if os.IsNotExist(err) {
		if storage.ValidateDirectory(filepath.Dir(base), false) != nil {
			return nil, fmt.Errorf("The parent directory must already exist, be owned by you, and have no symlinks or unsafe permissions.")
		}
		return nil, nil
	}
	if err != nil || storage.ValidateDirectory(base, false) != nil {
		return nil, fmt.Errorf("Workspace must be an existing directory owned and controlled by you, without symlinks or unsafe permissions.")
	}
	for _, name := range []string{"store", "mount", "runtime", "veyl.json"} {
		if _, err := os.Lstat(filepath.Join(base, name)); !os.IsNotExist(err) {
			return nil, fmt.Errorf("Cannot initialize: %s already exists or cannot be inspected. Veyl never overwrites managed paths; choose another workspace or inspect the conflict.", name)
		}
	}
	return info, nil
}
