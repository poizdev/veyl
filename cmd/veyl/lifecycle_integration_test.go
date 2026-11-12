//go:build integration && linux

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/poizdev/veyl/internal/storage"
)

const fixturePassword = "veyl-cli-test-password"

// A copied test executable acts as a deterministic pinentry subprocess. This
// exercises the production CLI/adapter/IPC/storage path, not a real GUI dialog.
func init() {
	if filepath.Base(os.Args[0]) != "veyl-test-pinentry" {
		return
	}
	base := filepath.Dir(os.Args[0])
	fmt.Println("OK synthetic test agent")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		command := scanner.Text()
		switch {
		case command == "GETPIN":
			f, _ := os.OpenFile(filepath.Join(base, "prompts"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if f != nil {
				_, _ = f.Write([]byte("x"))
				f.Close()
			}
			if _, err := os.Stat(filepath.Join(base, "wrong")); err == nil {
				fmt.Println("D incorrect")
			} else {
				fmt.Println("D " + fixturePassword)
			}
			fmt.Println("OK")
		case command == "BYE":
			fmt.Println("OK")
			os.Exit(0)
		default:
			fmt.Println("OK")
		}
	}
	os.Exit(0)
}

func TestCLIEncryptedLifecycle(t *testing.T)       { testCLIEncryptedLifecycle(t, false) }
func TestCLIWritableManagedLifecycle(t *testing.T) { testCLIEncryptedLifecycle(t, true) }

func TestCLIOriginalLifecycle(t *testing.T) { testCLIEncryptedLifecycle(t, true, true) }

func testCLIEncryptedLifecycle(t *testing.T, writableManaged bool, originalMode ...bool) {
	original := len(originalMode) != 0 && originalMode[0]
	hiddenName := ".vault"
	if original {
		hiddenName = "test"
	}
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skipf("real CLI lifecycle requires /dev/fuse: %v", err)
	}
	for _, name := range []string{"go", "gocryptfs", "fusermount3"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skip(name + " unavailable")
		}
	}
	project, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	prefix := ".veyl-cli-test-"
	if original {
		prefix = "veyl-cli-desktop-test-"
	} // Desktop monitors ignore dot paths before considering options.
	base, err := os.MkdirTemp(project, prefix)
	if err != nil {
		t.Fatal(err)
	}
	cipher, mount, runtime, seed := filepath.Join(base, "cipher"), filepath.Join(base, "mount"), filepath.Join(base, "runtime"), filepath.Join(base, "seed")
	for _, p := range []string{cipher, mount, runtime, seed} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	// Never recursively remove a plaintext view, even on a failed test.
	t.Cleanup(func() {
		mounted, err := storage.HasMountsUnder(base)
		if err != nil || mounted {
			t.Errorf("retaining synthetic fixture after incomplete cleanup: %s", base)
			return
		}
		if err := os.RemoveAll(cipher); err != nil {
			t.Error(err)
		}
		for _, p := range []string{filepath.Join(runtime, "views"), runtime, mount, seed} {
			if p == runtime {
				_ = os.Remove(filepath.Join(runtime, "instance.lock"))
			}
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				t.Error(err)
			}
		}
		for _, name := range []string{"veyl", "veyl-test-pinentry", "config.json", "wrong", "prompts", "process.log", "fusermount3"} {
			_ = os.Remove(filepath.Join(base, name))
		}
		if err := os.Remove(base); err != nil {
			t.Error(err)
		}
	})
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	passwordCommand := func(args ...string) *exec.Cmd {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = writer.Write([]byte(fixturePassword + "\n"))
		writer.Close()
		cmd := exec.Command("gocryptfs", args...)
		cmd.ExtraFiles = []*os.File{reader}
		cmd.Stdout = devnull
		cmd.Stderr = devnull
		t.Cleanup(func() { reader.Close() })
		return cmd
	}
	initCmd := passwordCommand("-init", "-q", "-scryptn", "10", "-passfile", "/proc/self/fd/3", "--", cipher)
	if err := initCmd.Run(); err != nil {
		t.Fatal("synthetic encrypted-store initialization failed", err)
	}
	seedCmd := passwordCommand("-fg", "-q", "-passfile", "/proc/self/fd/3", "--", cipher, seed)
	if err := seedCmd.Start(); err != nil {
		t.Fatal(err)
	}
	seedDone := make(chan error, 1)
	go func() { seedDone <- seedCmd.Wait() }()
	unmountSeed := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx, "fusermount3", "-u", "--", seed).Run()
	}
	t.Cleanup(unmountSeed)
	deadline := time.Now().Add(10 * time.Second)
	for {
		mounted, err := storage.HasMountsUnder(seed)
		if err != nil {
			t.Fatal(err)
		}
		if mounted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("seed mount not ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := os.Mkdir(filepath.Join(seed, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(seed, "nested", "payload"), []byte("real CLI synthetic payload"), 0600); err != nil {
		t.Fatal(err)
	}
	unmountSeed()
	select {
	case err := <-seedDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("seed process did not exit")
	}
	binary := filepath.Join(base, "veyl")
	build := exec.Command("go", "build", "-race", "-buildvcs=false", "-o", binary, "./cmd/veyl")
	build.Dir = project
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, output)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	helper, err := os.OpenFile(filepath.Join(base, "veyl-test-pinentry"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		source.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(helper, source)
	helper.Close()
	source.Close()
	if copyErr != nil {
		t.Fatal(copyErr)
	}
	config := filepath.Join(base, "config.json")
	fields := map[string]any{"version": 1, "store": cipher, "mountpoint": mount, "runtime_dir": runtime, "hidden_name": hiddenName, "credential_agent": filepath.Join(base, "veyl-test-pinentry")}
	if original {
		target := filepath.Join(mount, hiddenName)
		if err := os.Mkdir(target, 0700); err != nil {
			t.Fatal(err)
		}
		p, _ := os.Stat(mount)
		v, _ := os.Stat(target)
		ps := p.Sys().(*syscall.Stat_t)
		vs := v.Sys().(*syscall.Stat_t)
		fields["version"], fields["read_only"] = 2, false
		fields["original"] = map[string]uint64{"parent_device": uint64(ps.Dev), "parent_inode": ps.Ino, "target_device": uint64(vs.Dev), "target_inode": vs.Ino}
		t.Cleanup(func() {
			if mounted, err := storage.HasMountsUnder(base); err == nil && !mounted {
				_ = os.Remove(filepath.Join(mount, "sibling"))
				_ = os.Remove(target)
			}
		})
	} else if writableManaged {
		parent := filepath.Join(base, "siblings")
		if err := os.Mkdir(parent, 0700); err != nil {
			t.Fatal(err)
		}
		fields["parent"], fields["read_only"] = parent, false
		t.Cleanup(func() {
			if mounted, err := storage.HasMountsUnder(base); err != nil || mounted {
				return
			}
			if err := os.RemoveAll(parent); err != nil {
				t.Error(err)
			}
		})
	}
	cfg, _ := json.Marshal(fields)
	if err := os.WriteFile(config, cfg, 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(base, "process.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	process := exec.Command(binary, "mount", "--config", config)
	process.Dir = project
	process.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + base, "DISPLAY=:999"}
	process.Stdout = log
	process.Stderr = log
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	processDone := make(chan error, 1)
	go func() { processDone <- process.Wait() }()
	cli := func(op string) (int, string) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, op, "--config", config)
		output, err := cmd.CombinedOutput()
		code := 0
		if err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				code = exit.ExitCode()
			} else {
				code = 1
			}
		}
		return code, string(output)
	}
	var stopped bool
	t.Cleanup(func() {
		if !stopped {
			_, _ = cli("unmount")
			select {
			case <-processDone:
				stopped = true
			case <-time.After(5 * time.Second):
				t.Errorf("foreground owner retained; inspect synthetic fixture %s (PID %d)", base, process.Process.Pid)
			}
		}
	})
	deadline = time.Now().Add(10 * time.Second)
	for {
		code, text := cli("status")
		if code == 0 && strings.Contains(text, "mounted and locked") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("CLI not ready: %d %s", code, text)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if writableManaged {
		if err := os.WriteFile(filepath.Join(mount, "sibling"), []byte("public while locked"), 0640); err != nil {
			t.Fatal("managed sibling create", err)
		}
		if code, text := cli("status"); code != 0 || !strings.Contains(text, "mounted and locked") {
			t.Fatal("sibling access unlocked protected tree", code, text)
		}
	}
	// The explicit wrong-password check still verifies with real gocryptfs.
	if err := os.WriteFile(filepath.Join(base, "wrong"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if code, msg := cli("unlock"); code != 4 {
		t.Fatalf("wrong password exit code: %d (msg: %q)", code, msg)
	}
	os.Remove(filepath.Join(base, "wrong"))
	payload := filepath.Join(mount, hiddenName, "nested", "payload")
	before, _ := os.ReadFile(filepath.Join(base, "prompts"))
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data, err := os.ReadFile(payload)
			if err != nil || string(data) != "real CLI synthetic payload" {
				t.Errorf("automatic real read: %v", err)
			}
		}()
	}
	wg.Wait()
	after, _ := os.ReadFile(filepath.Join(base, "prompts"))
	if len(after) != len(before)+1 {
		t.Fatal("concurrent lookup spawned duplicate prompts")
	}
	listing, err := os.ReadDir(mount)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range listing {
		if entry.Name() == hiddenName {
			t.Fatal("hidden name enumerated")
		}
	}
	if code, text := cli("status"); code != 0 || !strings.Contains(text, "unlocked") {
		t.Fatalf("unlocked status: %d %s", code, text)
	}
	held, err := os.Open(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if writableManaged {
		if err := os.WriteFile(payload, []byte("edited through CLI mount"), 0600); err != nil {
			t.Fatal("protected write", err)
		}
	} else {
		if err := os.WriteFile(payload, []byte("no"), 0600); !errors.Is(err, syscall.EROFS) {
			t.Fatal("write not rejected", err)
		}
	}
	if code, text := cli("lock"); code != 0 {
		t.Fatalf("lock: %d %s", code, text)
	}
	if _, err := held.ReadAt(make([]byte, 32), 0); !errors.Is(err, syscall.EACCES) {
		t.Fatal("old handle remained readable", err)
	}
	if code, _ := cli("unlock"); code != 0 {
		t.Fatal("explicit GUI-path unlock failed")
	}
	if _, err := held.ReadAt(make([]byte, 32), 0); !errors.Is(err, syscall.EACCES) {
		t.Fatal("old handle revived", err)
	}
	held.Close()
	if writableManaged {
		if data, err := os.ReadFile(payload); err != nil || string(data) != "edited through CLI mount" {
			t.Fatal("CLI lock/unlock persistence", err)
		}
		if data, err := os.ReadFile(filepath.Join(mount, "sibling")); err != nil || string(data) != "public while locked" {
			t.Fatal("sibling persistence", err)
		}
	}
	if code, text := cli("unmount"); code != 0 {
		t.Fatalf("unmount: %d %s", code, text)
	}
	select {
	case err := <-processDone:
		stopped = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("foreground process did not stop")
	}
	if code, _ := cli("status"); code != 3 {
		t.Fatalf("stopped status: %d", code)
	}
	if _, err := os.Lstat(filepath.Join(runtime, "control.sock")); !os.IsNotExist(err) {
		t.Fatal("control socket leaked")
	}
	if original {
		// Crash an unlocked owner. Both FUSE mounts remain reported residues until
		// explicitly recovered; startup must not shadow it or report cleanup success.
		crashed := exec.Command(binary, "mount", "--config", config)
		crashed.Dir = project
		crashed.Env = process.Env
		crashed.Stdout = log
		crashed.Stderr = log
		if err := crashed.Start(); err != nil {
			t.Fatal(err)
		}
		deadline = time.Now().Add(10 * time.Second)
		for {
			code, text := cli("status")
			if code == 0 && strings.Contains(text, "mounted and locked") {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("crash fixture not ready", text)
			}
			time.Sleep(20 * time.Millisecond)
		}

		if code, text := cli("unlock"); code != 0 {
			t.Fatal("unlock crash fixture", code, text)
		}
		crashHandle, err := os.Open(payload)
		if err != nil {
			t.Fatal(err)
		}
		views, err := os.ReadDir(filepath.Join(runtime, "views"))
		if err != nil || len(views) != 1 {
			t.Fatal("expected exactly one owned synthetic view", views, err)
		}
		view := filepath.Join(runtime, "views", views[0].Name())
		identity, err := exec.Command("findmnt", "--noheadings", "--raw", "--output", "ID,FSTYPE,SOURCE", "--mountpoint", view).Output()
		if err != nil || !strings.Contains(string(identity), "fuse.gocryptfs "+cipher) {
			t.Fatal("unrecognized synthetic view", string(identity), err)
		}
		if err := crashed.Process.Kill(); err != nil {
			t.Fatal(err)
		}

		_ = crashed.Wait()
		if _, err := crashHandle.ReadAt(make([]byte, 32), 0); err == nil {
			t.Fatal("dead owner served plaintext")
		}
		crashHandle.Close()

		if code, text := cli("status"); code != 5 {
			t.Fatal("crash falsely reported clean", code, text)
		}

		again, err := exec.Command("findmnt", "--noheadings", "--raw", "--output", "ID,FSTYPE,SOURCE", "--mountpoint", view).Output()
		if err != nil || string(again) != string(identity) {
			t.Fatal("view identity changed; retaining residue", err)
		}
		if output, err := exec.Command("fusermount3", "-u", "--", view).CombinedOutput(); err != nil {
			t.Fatalf("recover backing view: %v %s", err, output)
		}
		if err := os.Remove(view); err != nil {
			t.Fatal("remove identified empty view", err)
		}
		if output, err := exec.Command("fusermount3", "-u", "--", mount).CombinedOutput(); err != nil {
			t.Fatalf("recover stale original mount: %v %s", err, output)
		}
		if code, text := cli("status"); code != 3 {
			t.Fatal("recovery status", code, text)
		}
		// Use a uniquely named transient user unit, never the user's veyl.service.
		unit := fmt.Sprintf("veyl-native-test-%d", os.Getpid())
		if output, err := exec.Command("systemctl", "--user", "is-system-running").CombinedOutput(); err != nil {
			t.Fatalf("native user manager unavailable: %v %s", err, output)
		}
		t.Cleanup(func() { _ = exec.Command("systemctl", "--user", "stop", unit).Run() })

		// This lifecycle check needs a visible drive to exercise GIO eject even on
		// desktops which honor x-gvfs-hide. Simulate an older helper for this unit
		// only; authenticated I/O and real native mount/unmount are unchanged.
		wrapper := `#!/bin/sh
if [ "$1" = "--version" ]; then
 printf 'fusermount3 version: 3.16.2\n'
 exit 0
fi
case "$*" in *x-gvfs-hide*) exit 2;; esac
exec /usr/bin/fusermount3 "$@"
`
		if err := os.WriteFile(filepath.Join(base, "fusermount3"), []byte(wrapper), 0700); err != nil {
			t.Fatal(err)
		}
		args := []string{"--user", "--collect", "--unit=" + unit, "--property=Type=notify", "--property=NotifyAccess=main", "--property=KillMode=mixed", "--property=SendSIGKILL=no", "--property=TimeoutStopSec=infinity", "--setenv=DISPLAY=:999", "--setenv=PATH=" + base + ":/usr/bin:/bin", binary, "mount", "--config", config}
		if output, err := exec.Command("systemd-run", args...).CombinedOutput(); err != nil {
			t.Fatalf("background readiness: %v %s", err, output)
		}
		if code, text := cli("status"); code != 0 || !strings.Contains(text, "mounted and locked") {
			t.Fatal("background not locked and ready", code, text)
		}
		if code, text := cli("unlock"); code != 0 {
			t.Fatal("unlock before desktop eject", code, text)
		}
		held, err := os.Open(payload)
		if err != nil {
			t.Fatal(err)
		}
		eject := func() ([]byte, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return exec.CommandContext(ctx, "gio", "mount", "--unmount", mount).CombinedOutput()
		}
		if output, err := eject(); err == nil || !(strings.Contains(strings.ToLower(string(output)), "busy") || strings.Contains(string(output), "preventing the unmount operation")) {
			held.Close()
			t.Fatalf("expected a busy GIO eject refusal, got: %s", output)
		}
		if code, text := cli("status"); code != 0 || !strings.Contains(text, "unlocked") {
			held.Close()
			t.Fatal("failed eject changed live owner", code, text)
		}
		held.Close()
		if output, err := eject(); err != nil {
			t.Fatalf("GIO eject: %v %s", err, output)
		}
		deadline = time.Now().Add(10 * time.Second)
		for {
			code, text := cli("status")
			if code == 3 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("external eject did not finish cleanup", code, text)
			}
			time.Sleep(20 * time.Millisecond)
		}
		if data, err := os.ReadDir(mount); err != nil || len(data) != 2 {
			t.Fatal("eject did not preserve physical target and public sibling", data, err)
		}
		if mounted, err := storage.HasMountsUnder(runtime); err != nil || mounted {
			t.Fatal("eject left decrypted backing mounted", err)
		}

		// Control cleanup precedes process exit; the race runtime can delay exit.
		// Wait for the user manager rather than treating a removed socket as exit.
		deadline = time.Now().Add(10 * time.Second)
		for {
			output, err := exec.Command("systemctl", "--user", "is-active", unit).CombinedOutput()
			state := strings.TrimSpace(string(output))
			if err != nil && (state == "inactive" || state == "unknown") {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("background unit did not stop after eject: %v %s", err, output)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	if mounted, err := storage.HasMountsUnder(base); err != nil || mounted {
		t.Fatal("fixture mount leaked")
	}
}
