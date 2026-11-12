//go:build integration && linux

package storage

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/poizdev/veyl/internal/auth"
	"github.com/poizdev/veyl/internal/ghostfs"
	"github.com/poizdev/veyl/internal/policy"
)

// Explicit internal agent for a throwaway fixture; never installed by cmd/veyl.
type bridgeAgent struct {
	proof []byte
	wrong atomic.Bool
}

func (a *bridgeAgent) Authenticate(_ context.Context, r auth.Request) (auth.Response, error) {
	proof := a.proof
	if a.wrong.Load() {
		proof = []byte("wrong-synthetic-password")
	}
	return auth.Response{RequestID: r.ID, Approved: true, Proof: proof}, nil
}

func TestGocryptfsProtectedBridge(t *testing.T) {
	binary := realBinary(t)
	device, err := os.OpenFile("/dev/fuse", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("real protected bridge requires FUSE: %v", err)
	}
	device.Close()
	if _, err := exec.LookPath("fusermount3"); err != nil {
		t.Skip("fusermount3 unavailable")
	}
	store, run, password := temporaryStore(t, binary)
	root := &ghostfs.Root{}
	b, err := New(Config{Store: store, RuntimeDir: run, Binary: binary}, &root.State)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Errorf("retained synthetic backend cleanup: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// Seed encrypted contents via a standalone mount only in this test harness.
	seed, err := b.Mount(ctx, ticket(t, &root.State), password)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(seed.Path, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(seed.Path, "nested", "payload"), []byte("encrypted bridge fixture"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("nested", filepath.Join(seed.Path, "link")); err != nil {
		t.Fatal(err)
	}
	if err := b.Unmount(ctx); err != nil {
		t.Fatal(err)
	}
	empty(t, run)
	agent := &bridgeAgent{proof: password}
	agent.wrong.Store(true)
	prepared := make(chan *Candidate, 8)
	var reject atomic.Bool
	root.Backing = b
	root.Auth = auth.NewTransactional(&root.State, agent, func(ctx context.Context, ticket policy.Challenge, response auth.Response) (auth.Transaction, error) {
		c, err := b.Prepare(ctx, ticket, response.Proof)
		if c == nil {
			return nil, err
		}
		if err == nil {
			prepared <- c
			if reject.Load() {
				root.State.Lock()
			}
		}
		return c, err
	}, 30*time.Second)
	project, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	mountpoint, err := os.MkdirTemp(project, ".veyl-bridge-test-")
	if err != nil {
		t.Fatal(err)
	}
	server, err := fs.Mount(mountpoint, root, ghostfs.Options())
	if err != nil {
		os.Remove(mountpoint)
		t.Fatalf("Veyl FUSE mount: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Unmount(); err != nil {
			t.Errorf("Veyl unmount incomplete; retaining synthetic mountpoint: %v", err)
			return
		}
		server.Wait()
		if err := os.Remove(mountpoint); err != nil {
			t.Error(err)
		}
	})
	ghost := filepath.Join(mountpoint, policy.GhostName)
	payload := filepath.Join(ghost, "nested", "payload")
	hidden := func() {
		t.Helper()
		listing, err := os.ReadDir(mountpoint)
		if err != nil || len(listing) != 1 || listing[0].Name() != policy.VisibleName {
			t.Fatal("root concealment failed")
		}
		output, err := exec.CommandContext(ctx, "ls", "-a", "--", mountpoint).Output()
		if err != nil || strings.Contains(string(output), policy.GhostName) {
			t.Fatal("ls -a exposed protected name")
		}
	}
	hidden()
	if _, err := os.ReadFile(payload); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("wrong password: %v", err)
	}
	if !root.State.IsLocked() || b.Retained() != nil {
		t.Fatal("wrong password published plaintext")
	}
	empty(t, run)
	agent.wrong.Store(false)
	reject.Store(true)
	if _, err := os.ReadFile(payload); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("rejected challenge: %v", err)
	}
	rejected := receive(t, prepared)
	receive(t, rejected.View().Done())
	if rejected.Owned() {
		t.Fatal("rejected mount cleanup incomplete")
	}
	if _, err := os.ReadFile(filepath.Join(rejected.View().Path, "nested", "payload")); !os.IsNotExist(err) {
		t.Fatalf("rejected mount remains readable: %v", err)
	}
	empty(t, run)
	reject.Store(false)
	data, err := os.ReadFile(payload)
	if err != nil || string(data) != "encrypted bridge fixture" {
		t.Fatalf("protected nested read: %v", err)
	}
	adopted := receive(t, prepared)
	hidden()
	if _, err := os.ReadDir(filepath.Join(ghost, "nested")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(ghost, "link", "payload")); err == nil {
		t.Fatal("symlink traversal succeeded")
	}
	info, err := os.Stat(payload)
	if err != nil || info.Mode().Perm() != 0440 || info.Size() != 24 {
		t.Fatal("backing metadata mismatch")
	}
	for name, mutate := range map[string]func() error{
		"write":    func() error { return os.WriteFile(payload, []byte("changed"), 0600) },
		"create":   func() error { return os.WriteFile(filepath.Join(ghost, "new"), nil, 0600) },
		"mkdir":    func() error { return os.Mkdir(filepath.Join(ghost, "newdir"), 0700) },
		"unlink":   func() error { return os.Remove(payload) },
		"rmdir":    func() error { return os.Remove(filepath.Join(ghost, "nested")) },
		"rename":   func() error { return os.Rename(payload, filepath.Join(ghost, "other")) },
		"chmod":    func() error { return os.Chmod(payload, 0600) },
		"truncate": func() error { return os.Truncate(payload, 0) },
		"symlink":  func() error { return os.Symlink("nested", filepath.Join(ghost, "newlink")) },
		"link":     func() error { return os.Link(payload, filepath.Join(ghost, "hardlink")) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := mutate(); !errors.Is(err, syscall.EROFS) {
				t.Fatalf("mutation: %v", err)
			}
		})
	}
	held, err := os.Open(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	dir, err := os.Open(filepath.Join(ghost, "nested"))
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	root.State.Lock()
	if err := adopted.Close(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	if _, err := held.ReadAt(buf, 0); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("locked handle: %v", err)
	}
	if _, err := syscall.ReadDirent(int(dir.Fd()), make([]byte, 4096)); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("locked directory: %v", err)
	}
	// Explicit harness reauthentication uses the same adopted-session path.
	if err := root.Auth.RequestAccess(ctx); err != nil {
		t.Fatal(err)
	}
	next := receive(t, prepared)
	if data, err := os.ReadFile(payload); err != nil || string(data) != "encrypted bridge fixture" {
		t.Fatalf("fresh session read: %v", err)
	}
	current, err := os.Open(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	if _, err := held.ReadAt(buf, 0); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("stale handle revived: %v", err)
	}
	if _, err := held.Stat(); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("stale metadata revived: %v", err)
	}
	agent.wrong.Store(true) // a post-crash direct lookup must not reauthenticate
	<-b.gate
	p := b.active.process
	b.unlock()
	if err := p.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	receive(t, next.View().Done())
	if !root.State.IsLocked() {
		t.Fatal("backend crash did not revoke")
	}
	if _, err := current.ReadAt(buf, 0); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("crashed session read: %v", err)
	}
	if next.Owned() {
		t.Fatal("backend crash retained incomplete cleanup")
	}
	empty(t, run)
}
