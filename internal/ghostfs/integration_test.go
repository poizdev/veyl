//go:build integration && linux

package ghostfs

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
)

func mountFilesystem(t *testing.T, root *Root) string {
	t.Helper()
	device, err := os.OpenFile("/dev/fuse", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("FUSE unavailable: %v", err)
	}
	device.Close()
	if _, err := exec.LookPath("fusermount3"); err != nil {
		if _, err := exec.LookPath("fusermount"); err != nil {
			t.Skip("FUSE mount helper unavailable")
		}
	}
	// Keep disposable mounts inside the project, never in a real backing tree.
	// A dot-prefixed name excludes live mounts from Go package discovery.
	project, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	mount, err := os.MkdirTemp(project, ".veyl-fuse-test-")
	if err != nil {
		t.Fatal(err)
	}
	server, err := fs.Mount(mount, root, Options())
	if err != nil {
		if removeErr := os.Remove(mount); removeErr != nil {
			t.Errorf("remove empty mountpoint: %v", removeErr)
		}
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) ||
			strings.Contains(err.Error(), "Operation not permitted") || strings.Contains(err.Error(), "Permission denied") {
			t.Skipf("FUSE mounting not permitted: %v", err)
		}
		t.Fatalf("mount: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Unmount(); err != nil {
			t.Errorf("unmount failed; leaving mountpoint %s for fusermount3 -u: %v", mount, err)
			return // Never recursively remove a mounted directory.
		}
		server.Wait()
		if err := os.Remove(mount); err != nil {
			t.Errorf("remove mountpoint: %v", err)
		}
	})

	return mount
}

func TestMountedFilesystem(t *testing.T) {
	mount := mountFilesystem(t, &Root{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "ls", "-a", "--", mount).Output()
	if err != nil {
		t.Fatalf("ls -a: %v", err)
	}
	for _, name := range strings.Fields(string(output)) {
		if name != "." && name != ".." && name != "visible.txt" {
			t.Fatalf("unexpected listing entry: %q", name)
		}
	}
	entries, err := os.ReadDir(mount)
	if err != nil || len(entries) != 1 || entries[0].Name() != "visible.txt" {
		t.Fatalf("ReadDir: %v, %v", entries, err)
	}
	visible := filepath.Join(mount, "visible.txt")
	data, err := os.ReadFile(visible)
	if err != nil || string(data) != VisibleContent {
		t.Fatalf("ReadFile: %q, %v", data, err)
	}
	for range 3 {
		for _, name := range []string{".troll", ".troll/child"} {
			if _, err := os.Stat(filepath.Join(mount, name)); !errors.Is(err, syscall.EACCES) {
				t.Fatalf("Stat(%q): %v", name, err)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(mount, "missing")); !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("unknown: %v", err)
	}
	for name, operation := range map[string]func() error{
		"write existing": func() error { return os.WriteFile(visible, []byte("changed"), 0600) },
		"create":         func() error { return os.WriteFile(filepath.Join(mount, "new"), []byte("new"), 0600) },
		"mkdir":          func() error { return os.Mkdir(filepath.Join(mount, "newdir"), 0700) },
		"remove":         func() error { return os.Remove(visible) },
		"rename":         func() error { return os.Rename(visible, filepath.Join(mount, "renamed")) },
		"chmod":          func() error { return os.Chmod(visible, 0600) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := operation(); !errors.Is(err, syscall.EROFS) {
				t.Fatalf("want EROFS, got %v", err)
			}
		})
	}
	data, err = os.ReadFile(visible)
	if err != nil || string(data) != VisibleContent {
		t.Fatalf("content changed: %q, %v", data, err)
	}
}

func TestMountedStateChanges(t *testing.T) {
	root := &Root{}
	mount := mountFilesystem(t, root)
	ghost := filepath.Join(mount, ".troll")
	hello := filepath.Join(ghost, "hello.txt")
	assertHidden := func() {
		t.Helper()
		entries, err := os.ReadDir(mount)
		if err != nil || len(entries) != 1 || entries[0].Name() != "visible.txt" {
			t.Fatalf("root listing: %v, %v", entries, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		output, err := exec.CommandContext(ctx, "ls", "-a", "--", mount).Output()
		if err != nil || strings.Contains(string(output), ".troll") {
			t.Fatalf("ls -a: %q, %v", output, err)
		}
	}
	assertHidden()
	if _, err := os.Stat(ghost); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("initial locked lookup: %v", err)
	}
	// This fixture controls policy in-process; it does not start the CLI/control socket.
	root.State.Unlock()
	assertHidden()
	entries, err := os.ReadDir(ghost)
	if err != nil || len(entries) != 1 || entries[0].Name() != "hello.txt" {
		t.Fatalf("ghost listing: %v, %v", entries, err)
	}
	data, err := os.ReadFile(hello)
	if err != nil || string(data) != HelloContent {
		t.Fatalf("hello read: %q, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(ghost, "unknown")); !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("unknown child: %v", err)
	}
	for name, operation := range map[string]func() error{
		"write":    func() error { return os.WriteFile(hello, []byte("changed"), 0600) },
		"create":   func() error { return os.WriteFile(filepath.Join(ghost, "new"), nil, 0600) },
		"mkdir":    func() error { return os.Mkdir(filepath.Join(ghost, "newdir"), 0700) },
		"remove":   func() error { return os.Remove(hello) },
		"rename":   func() error { return os.Rename(hello, filepath.Join(ghost, "renamed")) },
		"chmod":    func() error { return os.Chmod(hello, 0600) },
		"truncate": func() error { return os.Truncate(hello, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := operation(); !errors.Is(err, syscall.EROFS) {
				t.Fatalf("want EROFS, got %v", err)
			}
		})
	}
	held, err := os.Open(hello)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	dirHandle, err := os.Open(ghost)
	if err != nil {
		t.Fatal(err)
	}
	defer dirHandle.Close()
	// Keep a second descriptor entirely untouched until the next session. This
	// avoids mistaking an error cached while locked for session-bound rejection.
	untouchedDir, err := os.Open(ghost)
	if err != nil {
		t.Fatal(err)
	}
	defer untouchedDir.Close()
	buf := make([]byte, len(HelloContent))
	if n, err := held.ReadAt(buf, 0); err != nil || string(buf[:n]) != HelloContent {
		t.Fatalf("held read before lock: %q, %v", buf[:n], err)
	}
	root.State.Lock()
	assertHidden()
	for _, path := range []string{ghost, hello} {
		if _, err := os.Stat(path); !errors.Is(err, syscall.EACCES) {
			t.Fatalf("relocked Stat(%s): %v", path, err)
		}
	}
	// This descriptor has never been read, so there are no pre-lock directory
	// response buffers. Requests reaching our callback must be denied.
	if _, err := syscall.ReadDirent(int(dirHandle.Fd()), make([]byte, 4096)); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("first read through pre-lock directory handle: %v", err)
	}
	if _, err := held.ReadAt(buf, 0); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("read through pre-lock handle: %v", err)
	}
	if _, err := held.Stat(); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("getattr through pre-lock handle: %v", err)
	}
	fd, err := syscall.Openat(int(dirHandle.Fd()), "hello.txt", syscall.O_RDONLY, 0)
	if err == nil {
		syscall.Close(fd)
		t.Fatal("relocked openat succeeded")
	}
	if !errors.Is(err, syscall.EACCES) {
		t.Fatalf("relocked openat: %v", err)
	}
	if _, err := os.Stat(filepath.Join(mount, "unknown")); !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("root unknown: %v", err)
	}
	data, err = os.ReadFile(filepath.Join(mount, "visible.txt"))
	if err != nil || string(data) != VisibleContent {
		t.Fatalf("visible file: %q, %v", data, err)
	}
	root.State.Unlock()
	if _, err := syscall.ReadDirent(int(untouchedDir.Fd()), make([]byte, 4096)); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("untouched stale directory after unlock: %v", err)
	}
	if _, err := held.ReadAt(buf, 0); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("stale file handle after unlock: %v", err)
	}
	if _, err := held.Stat(); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("stale file getattr after unlock: %v", err)
	}
	if _, err := syscall.ReadDirent(int(dirHandle.Fd()), make([]byte, 4096)); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("stale directory after unlock: %v", err)
	}
	fd, err = syscall.Openat(int(dirHandle.Fd()), "hello.txt", syscall.O_RDONLY, 0)
	if err == nil {
		syscall.Close(fd)
		t.Fatal("stale directory openat succeeded")
	}
	if !errors.Is(err, syscall.EACCES) {
		t.Fatalf("stale directory openat: %v", err)
	}
	freshDir, err := os.Open(ghost)
	if err != nil {
		t.Fatal(err)
	}
	defer freshDir.Close()
	dirBuffer := make([]byte, 4096)
	if n, err := syscall.ReadDirent(int(freshDir.Fd()), dirBuffer); err != nil || !strings.Contains(string(dirBuffer[:n]), "hello.txt") {
		t.Fatalf("fresh directory: %q, %v", dirBuffer[:n], err)
	}
	data, err = os.ReadFile(hello)
	if err != nil || string(data) != HelloContent {
		t.Fatalf("hello after unlock: %q, %v", data, err)
	}
	// Fresh lookups must not rebind the descriptors from the earlier session.
	if _, err := held.ReadAt(buf, 0); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("stale file revived after fresh lookup: %v", err)
	}
	fd, err = syscall.Openat(int(untouchedDir.Fd()), "hello.txt", syscall.O_RDONLY, 0)
	if err == nil {
		syscall.Close(fd)
		t.Fatal("stale directory rebound after fresh lookup")
	}
	if !errors.Is(err, syscall.EACCES) {
		t.Fatalf("stale openat after fresh lookup: %v", err)
	}
	assertHidden()
}
