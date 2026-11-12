//go:build linux

package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/poizdev/veyl/internal/storage"
)

func initCommand(ctx context.Context, args []string, out, errOut io.Writer) int {
	// The old layout remains available only by explicit request. Never infer it
	// from existing contents or silently adopt an old veyl.json.
	for i, arg := range args {
		if arg == "--legacy-workspace" {
			legacy := append([]string{}, args[:i]...)
			legacy = append(legacy, args[i+1:]...)
			return initLegacyCommand(ctx, legacy, out, errOut)
		}
	}
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dir := flags.String("dir", ".", "empty directory to protect")
	tty := flags.Bool("tty", false, "collect setup password on /dev/tty")
	autostart := flags.Bool("autostart", false, "activate after setup (leave the original parent first)")
	explicit := flags.Bool("explicit-unlock", false, "disable prompts from filesystem probes; use veyl unlock")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprint(out, initHelp)
			return 0
		}
		fmt.Fprint(errOut, initHelp)
		return 2
	}
	if flags.NArg() != 0 || *dir == "" {
		fmt.Fprint(errOut, initHelp)
		return 2
	}
	target, err := filepath.Abs(*dir)
	if err != nil || strings.ContainsAny(target, "\x00\r\n") || len(target) > 4095 {
		fmt.Fprintln(errOut, "Choose a valid absolute directory path.")
		return 2
	}
	location, err := inspectOriginal(target)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	name := filepath.Base(target)
	if !validName(name) || len(name) > 255 {
		fmt.Fprintln(errOut, errConfig)
		return 2
	}
	if ctx.Err() != nil {
		fmt.Fprintln(errOut, "Setup canceled; no files created.")
		return 4
	}
	// A shell inside the covered parent keeps its old cwd. Do not mount while
	// that shell can still write through its old directory description.
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(errOut, errConfig)
		return 2
	}
	if *autostart && beneath(filepath.Dir(target), cwd) {
		fmt.Fprintln(errOut, "Leave the original parent before activation. Run init without --autostart, then cd outside the parent and run the printed service enable command. Your shell cannot be redirected transparently.")
		return 2
	}
	paths, err := originalPaths()
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	for _, p := range []string{paths.config, paths.data, paths.runtime} {
		if beneath(filepath.Dir(target), p) || beneath(p, filepath.Dir(target)) {
			fmt.Fprintln(errOut, "XDG management locations must be separate from the original parent.")
			return 2
		}
	}
	if len(filepath.Join(paths.runtime, strings.Repeat("x", 32), "control.sock")) > 107 {
		fmt.Fprintln(errOut, "XDG runtime path is too long for the control socket.")
		return 2
	}
	registrationID := sha256.Sum256([]byte(target))
	config := filepath.Join(paths.config, hex.EncodeToString(registrationID[:])+".json")
	if _, err := os.Lstat(config); !os.IsNotExist(err) {
		fmt.Fprintln(errOut, "This directory already has a configuration registration, or it cannot be inspected. Nothing was adopted; inspect the existing configuration.")
		return 2
	}
	for _, binary := range []string{"gocryptfs", "fusermount3"} {
		if _, err := exec.LookPath(binary); err != nil {
			fmt.Fprintln(errOut, "Install gocryptfs and fuse3 before setup.")
			return 1
		}
	}
	prompt := credential.ReadTTY
	if !*tty {
		agent := credential.New("auto", filepath.Dir(target))
		prompt = func(ctx context.Context) ([]byte, error) {
			response, err := agent.Authenticate(ctx, auth.Request{Directory: target})
			return response.Proof, err
		}
	}
	password, result := setupPassword(ctx, prompt, out)
	if result.Code != 0 {
		fmt.Fprintln(errOut, result.Message)
		return result.Code
	}
	defer clear(password)
	current, err := inspectOriginal(target)
	if err != nil || *current != *location || ctx.Err() != nil {
		fmt.Fprintln(errOut, "Target changed or setup canceled; no files created.")
		return 2
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		fmt.Fprintln(errOut, "Cannot generate a private store identifier.")
		return 1
	}
	id := hex.EncodeToString(random[:])
	for _, p := range []string{paths.config, paths.data, paths.runtime} {
		if err := ensureServiceDirectory(p, true); err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
	}

	data := filepath.Join(paths.data, id)
	runtime := filepath.Join(paths.runtime, id)
	partial := func() int {
		fmt.Fprintf(errOut, "Setup incomplete. Retained configuration/data/runtime paths for inspection: %s, %s, %s. Original directory was not modified. No automatic deletion.\n", config, data, runtime)
		return 1
	}
	for _, p := range []string{data, runtime} {
		if err := os.Mkdir(p, 0700); err != nil {
			return partial()
		}
	}
	store := filepath.Join(data, "store")
	if err := os.Mkdir(store, 0700); err != nil {
		return partial()
	}
	if err := storage.Initialize(ctx, store, password); err != nil {
		return partial()
	}
	clear(password)
	current, err = inspectOriginal(target)
	if err != nil || *current != *location || ctx.Err() != nil {
		return partial()
	}
	readOnly := false
	c := Config{Version: 2, Original: location, ReadOnly: &readOnly, Store: store, RuntimeDir: runtime, Mountpoint: filepath.Dir(target), HiddenName: name, CredentialAgent: "auto", ExplicitUnlock: *explicit}
	f, err := os.OpenFile(config, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return partial()
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	err = enc.Encode(c)
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil || closed != nil {
		return partial()
	}
	fmt.Fprintf(out, "Encrypted store initialized for %s. Configuration: %s\nNo management files were placed in the original directory. Setup has not mounted anything.\nLeave the original parent and close old directory handles in all shells and applications.\nActivation makes the empty physical target mode 0500; it stays empty and read-only when Veyl is stopped.\nActivate with: veyl service enable --config %q\nAfter confirmed locked startup, re-enter %q using its absolute pathname. The protected name is omitted from parent listings even while unlocked.\n", target, config, config, target)
	if *autostart {
		result := enableService(ctx, config)
		fmt.Fprintln(out, result.Message)
		return result.Code
	}
	return 0
}

type originalDirectories struct{ config, data, runtime string }

func originalPaths() (originalDirectories, error) {
	config, err := os.UserConfigDir()
	if err != nil {
		return originalDirectories{}, errConfig
	}
	data := os.Getenv("XDG_DATA_HOME")
	if data == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return originalDirectories{}, errConfig
		}
		data = filepath.Join(home, ".local", "share")
	}
	runtime := os.Getenv("XDG_RUNTIME_DIR")
	for _, p := range []string{config, data, runtime} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, "\x00\r\n") {
			return originalDirectories{}, fmt.Errorf("Set safe absolute XDG config, data and runtime locations; XDG_RUNTIME_DIR is required.")
		}
	}
	if storage.ValidateDirectory(runtime, true) != nil || beneath(runtime, data) || beneath(data, runtime) || beneath(runtime, config) || beneath(config, runtime) {
		return originalDirectories{}, fmt.Errorf("XDG runtime must be private mode 0700 and separate from persistent config and data.")
	}
	return originalDirectories{filepath.Join(config, "veyl", "directories"), filepath.Join(data, "veyl"), filepath.Join(runtime, "veyl")}, nil
}
