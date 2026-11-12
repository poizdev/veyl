//go:build integration && linux

package ghostfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/poizdev/veyl/internal/auth"
)

func TestMountedAuthenticationBroker(t *testing.T) {
	root := &Root{}
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int64
	root.Auth = auth.New(&root.State, mockAgent(func(ctx context.Context, req auth.Request) (auth.Response, error) {
		if calls.Add(1) == 1 {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return auth.Response{}, ctx.Err()
			}
		}
		return auth.Response{RequestID: req.ID, Approved: true, Proof: []byte("test-only")}, nil
	}), mockVerifier{}, 5*time.Second)
	mount := mountFilesystem(t, root)
	checkHidden := func() {
		t.Helper()
		entries, err := os.ReadDir(mount)
		if err != nil || len(entries) != 1 || entries[0].Name() != "visible.txt" {
			t.Fatalf("root listing: %v, %v", entries, err)
		}
	}
	checkHidden()
	if calls.Load() != 0 {
		t.Fatal("listing contacted agent")
	}
	ghost := filepath.Join(mount, ".troll")
	result := make(chan error, 1)
	go func() { _, err := os.Stat(ghost); result <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("lookup did not request authentication")
	}
	checkHidden() // A pending authentication must not affect enumeration.
	// In-process controller only. Lock must finish despite the waiting agent and
	// invalidate the approval even though the filesystem was already locked.
	locked := make(chan struct{})
	go func() { root.State.Lock(); close(locked) }()
	select {
	case <-locked:
	case <-time.After(5 * time.Second):
		t.Fatal("authentication held filesystem authorization locks")
	}
	close(release)
	select {
	case err := <-result:
		if !errors.Is(err, syscall.EACCES) {
			t.Fatalf("stale approval lookup: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stale lookup stalled")
	}
	hello := filepath.Join(ghost, "hello.txt")
	data, err := os.ReadFile(hello)
	if err != nil || string(data) != HelloContent {
		t.Fatalf("fresh authenticated access: %q, %v", data, err)
	}
	held, err := os.Open(hello)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	root.State.Lock()
	if _, err := os.ReadFile(hello); err != nil {
		t.Fatalf("new session authentication: %v", err)
	}
	if _, err := held.ReadAt(make([]byte, 32), 0); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("old handle revived: %v", err)
	}
	checkHidden()
}
