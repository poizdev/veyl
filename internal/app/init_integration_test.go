//go:build integration && linux

package app

import (
	"bytes"
	"context"
	"github.com/poizdev/veyl/internal/storage"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This helper collects a deterministic synthetic password. Actual gocryptfs
// initialization is exercised; this is not a test of a physical GUI dialog.
func TestInitWorkspace(t *testing.T) {
	for _, binary := range []string{"gocryptfs", "fusermount3"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Skip(binary + " unavailable")
		}
	}
	helpers := filepath.Join(t.TempDir(), "helpers")
	if err := os.Mkdir(helpers, 0700); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
printf 'OK\n'
while IFS= read -r command; do
    case "$command" in
        GETPIN) printf 'D synthetic-workspace-password\nOK\n' ;;
        BYE) printf 'OK\n'; exit 0 ;;
        *) printf 'OK\n' ;;
    esac
done
`
	if err := os.WriteFile(filepath.Join(helpers, "pinentry-qt"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(helpers, "xdg"))
	t.Setenv("DISPLAY", ":999")
	t.Setenv("PATH", helpers+":"+os.Getenv("PATH"))
	for _, mode := range []string{"current", "existing", "new"} {
		t.Run(mode, func(t *testing.T) {
			workspace := t.TempDir()
			if mode == "new" {
				workspace = filepath.Join(workspace, "bundle")
			} else {
				if err := os.WriteFile(filepath.Join(workspace, "notes.txt"), []byte("keep this file"), 0640); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("missing-unrelated-file", filepath.Join(workspace, "unrelated-link")); err != nil {
					t.Fatal(err)
				}
			}
			var before os.FileInfo
			if mode != "new" {
				var err error
				before, err = os.Stat(workspace)
				if err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"init", "--legacy-workspace"}
			if mode == "current" {
				t.Chdir(workspace)
			} else {
				args = append(args, "--dir", workspace)
			}
			var out, errs bytes.Buffer
			if code := Run(context.Background(), args, &out, &errs); code != 0 {
				t.Fatalf("%d: %s", code, &errs)
			}
			path := filepath.Join(workspace, "veyl.json")
			c, err := LoadConfig(path)
			if err != nil || c.Store != filepath.Join(workspace, "store") || c.Mountpoint != filepath.Join(workspace, "mount") || c.RuntimeDir != filepath.Join(workspace, "runtime") || c.Version != 1 || !c.Writable() {
				t.Fatalf("configuration: %+v %v", c, err)
			}
			if err := c.validateMount(); err != nil {
				t.Fatal(err)
			}
			for _, dir := range []string{c.Store, c.Mountpoint, c.RuntimeDir} {
				info, err := os.Stat(dir)
				if err != nil || info.Mode().Perm() != 0700 {
					t.Fatalf("private directory: %s %v", dir, err)
				}
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("config permissions", err)
			}
			encrypted := filepath.Join(c.Store, "gocryptfs.conf")
			original, err := os.ReadFile(encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if mode != "new" {
				after, err := os.Stat(workspace)
				if err != nil || before.Mode() != after.Mode() {
					t.Fatal("workspace permissions changed", err)
				}
				data, err := os.ReadFile(filepath.Join(workspace, "notes.txt"))
				if err != nil || string(data) != "keep this file" {
					t.Fatal("unrelated file changed", err)
				}
				target, err := os.Readlink(filepath.Join(workspace, "unrelated-link"))
				if err != nil || target != "missing-unrelated-file" {
					t.Fatal("unrelated symlink changed", err)
				}
			}
			out.Reset()
			errs.Reset()
			if code := Run(context.Background(), args, &out, &errs); code != 2 || out.Len() != 0 {
				t.Fatalf("repeated init: %d %s", code, &errs)
			}
			after, err := os.ReadFile(encrypted)
			if err != nil || !bytes.Equal(original, after) {
				t.Fatal("existing store changed", err)
			}
		})
	}
	t.Run("partial failure", func(t *testing.T) {
		// Fail only the synthetic initializer; real gocryptfs was used above.
		if err := os.WriteFile(filepath.Join(helpers, "gocryptfs"), []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
			t.Fatal(err)
		}
		workspace := t.TempDir()
		sentinel := filepath.Join(workspace, "notes.txt")
		if err := os.WriteFile(sentinel, []byte("preserve unrelated data"), 0600); err != nil {
			t.Fatal(err)
		}
		var out, errs bytes.Buffer
		if code := Run(context.Background(), []string{"init", "--legacy-workspace", "--dir", workspace}, &out, &errs); code != 1 || !bytes.Contains(errs.Bytes(), []byte("retained")) {
			t.Fatalf("partial setup: %d %s", code, &errs)
		}
		if _, err := os.Lstat(filepath.Join(workspace, "veyl.json")); !os.IsNotExist(err) {
			t.Fatal("failed setup published config", err)
		}
		for _, name := range []string{"store", "mount", "runtime"} {
			if info, err := os.Stat(filepath.Join(workspace, name)); err != nil || !info.IsDir() {
				t.Fatal("partial path not retained", name, err)
			}
		}
		data, err := os.ReadFile(sentinel)
		if err != nil || string(data) != "preserve unrelated data" {
			t.Fatal("unrelated data changed", err)
		}
	})

	if _, err := os.Lstat(filepath.Join(helpers, "xdg")); !os.IsNotExist(err) {
		t.Fatal("initialization without --autostart modified user service configuration", err)
	}

}

func TestOriginalInitFromInsideEmptyDirectory(t *testing.T) {
	base, err := os.MkdirTemp("", "veyl-init-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if mounted, err := storage.HasMountsUnder(base); err != nil || mounted {
			t.Error("retaining mounted init fixture")
			return
		}
		if err := os.RemoveAll(base); err != nil {
			t.Error(err)
		}
	})
	for _, name := range []string{"config", "data", "run", "helpers", "parent"} {
		if err := os.Mkdir(filepath.Join(base, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(base, "parent", "test")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "parent", "neighbor"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "parent", "neighbor", "notes"), []byte("sibling"), 0600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
printf 'OK\n'
while IFS= read -r command; do
 case "$command" in
 GETPIN) printf 'D synthetic-original-password\nOK\n' ;;
 BYE) printf 'OK\n'; exit 0 ;;
 *) printf 'OK\n' ;;
 esac
done
`
	if err := os.WriteFile(filepath.Join(base, "helpers", "pinentry-qt"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	// Exercise compatibility with a helper that does not accept x-* options.
	// Actual mount/unmount operations still use the native system helper.
	oldHelper := `#!/bin/sh
if [ "$1" = "--version" ]; then
 printf 'fusermount3 version: 3.16.2\n'
 exit 0
fi
case "$*" in *x-gvfs-hide*) printf 'unsupported option\n' >&2; exit 2;; esac
exec /usr/bin/fusermount3 "$@"
`
	if err := os.WriteFile(filepath.Join(base, "helpers", "fusermount3"), []byte(oldHelper), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Join(base, "helpers")+":"+os.Getenv("PATH"))
	t.Setenv("DISPLAY", ":999")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(base, "data"))
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(base, "run"))
	t.Chdir(target)
	var out, errs bytes.Buffer
	if code := Run(context.Background(), []string{"init"}, &out, &errs); code != 0 {
		t.Fatalf("init: %d %s", code, &errs)
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 0 {
		t.Fatal("management files in target", entries, err)
	}
	configs, err := filepath.Glob(filepath.Join(base, "config", "veyl", "directories", "*.json"))
	if err != nil || len(configs) != 1 {
		t.Fatal(configs, err)
	}
	c, err := LoadConfig(configs[0])
	if err != nil || c.Version != 2 || c.Original == nil || c.HiddenName != "test" || c.Mountpoint != filepath.Dir(target) || !c.Writable() {
		t.Fatal(c, err)
	}
	if err := c.validateMount(); err != nil {
		t.Fatal(err)
	}
	if !beneath(filepath.Join(base, "data"), c.Store) || !beneath(filepath.Join(base, "run"), c.RuntimeDir) {
		t.Fatal("wrong XDG locations", c)
	}
	if mounted, err := storage.HasMountsUnder(filepath.Dir(target)); err != nil || mounted {
		t.Fatal("setup mounted over caller cwd", err)
	}
	out.Reset()
	errs.Reset()
	if code := Run(context.Background(), []string{"init"}, &out, &errs); code != 2 || out.Len() != 0 {
		t.Fatal("repeat setup accepted", code, &out, &errs)
	}
	// Activate the configuration produced above, with a retained pre-cutover
	// target handle. No path inside the real user's directories is involved.
	oldTarget, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer oldTarget.Close()
	t.Chdir(base)
	mountCtx, cancel := context.WithCancel(context.Background())
	done := make(chan Result, 1)
	go func() { done <- mountCommand(mountCtx, c, io.Discard) }()
	t.Cleanup(func() {
		cancel()
		select {
		case result := <-done:
			if result.Code != 0 {
				t.Error(result.Message)
			}
		case <-time.After(10 * time.Second):
			t.Error("retaining incomplete original fixture")
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		result := clientCommand(context.Background(), c, "status", false)
		if result.Code == 0 {
			if result.State != "locked" {
				t.Fatal(result)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("activation not ready", result)
		}
		time.Sleep(20 * time.Millisecond)
	}
	fd, err := syscall.Openat(int(oldTarget.Fd()), "unencrypted", syscall.O_WRONLY|syscall.O_CREAT, 0600)
	if err == nil {
		syscall.Close(fd)
		t.Fatal("old cwd could create unencrypted data")
	}
	if !os.IsPermission(err) {
		t.Fatal("unexpected old cwd result", err)
	}
	for _, args := range [][]string{{c.Mountpoint}, {"-a", c.Mountpoint}} {
		output, err := exec.Command("ls", args...).Output()
		if err != nil || strings.Contains(string(output), "test") {
			t.Fatal("protected name in listing", string(output), err)
		}
	}
	if err := os.WriteFile(filepath.Join(target, "hello.txt"), []byte("original path encrypted"), 0600); err != nil {
		t.Fatal("authenticated write at original path", err)
	}
	if result := clientCommand(context.Background(), c, "lock", false); result.Code != 0 {
		t.Fatal(result)
	}
	if result := clientCommand(context.Background(), c, "unmount", false); result.Code != 0 {
		t.Fatal(result)
	}
	if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
		t.Fatal("physical target contains plaintext", entries, err)
	}

}
