//go:build linux

package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/poizdev/veyl/internal/policy"
)

type fakeChild struct {
	done chan struct{}
	once sync.Once
	code int
	mu   sync.Mutex
}

func (p *fakeChild) Done() <-chan struct{}  { return p.done }
func (p *fakeChild) ExitCode() int          { <-p.done; p.mu.Lock(); defer p.mu.Unlock(); return p.code }
func (p *fakeChild) Signal(os.Signal) error { p.exit(0); return nil }
func (p *fakeChild) exit(code int) {
	p.once.Do(func() { p.mu.Lock(); p.code = code; p.mu.Unlock(); close(p.done) })
}

type fakeSystem struct {
	mu          sync.Mutex
	entries     []mountEntry
	starts      int
	mode        string
	started     chan struct{}
	child       *fakeChild
	failUnmount bool
	unmounts    int
}

func (f *fakeSystem) mounts() ([]mountEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]mountEntry(nil), f.entries...), nil
}
func (f *fakeSystem) start(_ string, args []string, password []byte) (child, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts++
	f.child = &fakeChild{done: make(chan struct{})}
	path, store := args[len(args)-1], args[len(args)-2]
	if string(password) != "synthetic-password" {
		f.child.exit(12)
	} else if f.mode != "pending" {
		f.entries = append(f.entries, mountEntry{ID: 101, Path: path, Type: "fuse.gocryptfs", Source: store})
	}
	if f.started != nil {
		close(f.started)
		f.started = nil
	}
	return f.child, nil
}
func (f *fakeSystem) unmount(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unmounts++
	if f.failUnmount {
		return errors.New("synthetic-password")
	}
	f.entries = nil
	return nil
}
func (f *fakeSystem) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.starts }
func fixture(t *testing.T) (Config, *policy.State, *fakeSystem) {
	t.Helper()
	base := t.TempDir()
	store, run := filepath.Join(base, "cipher"), filepath.Join(base, "runtime")
	for _, path := range []string{store, run} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(store, "gocryptfs.conf"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return Config{Store: store, RuntimeDir: run, Binary: binary, UnmountBinary: binary, StartTimeout: time.Second, StopTimeout: time.Second}, &policy.State{}, &fakeSystem{}
}
func testBackend(t *testing.T) (*Backend, *policy.State, *fakeSystem, Config) {
	t.Helper()
	cfg, state, f := fixture(t)
	b, err := New(cfg, state)
	if err != nil {
		t.Fatal(err)
	}
	b.ops = operations{start: f.start, mounts: f.mounts, unmount: f.unmount}
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Errorf("backend cleanup: %v", err)
		}
	})
	return b, state, f, cfg
}
func ticket(t *testing.T, s *policy.State) policy.Challenge {
	t.Helper()
	c, ok := s.Challenge()
	if !ok {
		t.Fatal("missing challenge")
	}
	return c
}
func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle stalled")
		var z T
		return z
	}
}
func empty(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary plaintext view remains: %v, %v", entries, err)
	}
}

func TestValidMountAndRepeatedUnmount(t *testing.T) {
	b, state, f, cfg := testBackend(t)
	v, err := b.Mount(context.Background(), ticket(t, state), []byte("synthetic-password"))
	if err != nil {
		t.Fatalf("valid mount: %v", err)
	}
	if !b.Mounted() || f.count() != 1 {
		t.Fatal("successful mount not tracked")
	}
	info, err := os.Stat(v.Path)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("runtime directory not private")
	}
	if err := b.Unmount(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := b.Unmount(context.Background()); err != nil {
		t.Fatal(err)
	}
	receive(t, v.Done())
	if b.Mounted() {
		t.Fatal("still mounted")
	}
	empty(t, cfg.RuntimeDir)
}
func TestInvalidPasswordLeavesNoView(t *testing.T) {
	b, state, _, cfg := testBackend(t)
	v, err := b.Mount(context.Background(), ticket(t, state), []byte("incorrect-password"))
	if v != nil || !errors.Is(err, ErrCredentials) {
		t.Fatalf("invalid password: %v, %v", v, err)
	}
	if b.Mounted() {
		t.Fatal("failed authentication mounted a view")
	}
	empty(t, cfg.RuntimeDir)
}
func TestConcurrentMountsDoNotReuseVerification(t *testing.T) {
	b, state, f, _ := testBackend(t)
	c := ticket(t, state)
	start := make(chan struct{})
	results := make(chan error, 8)
	for range 8 {
		go func() {
			<-start
			_, err := b.Mount(context.Background(), c, []byte("synthetic-password"))
			results <- err
		}()
	}
	close(start)
	success, busy := 0, 0
	for range 8 {
		err := receive(t, results)
		if err == nil {
			success++
		} else if errors.Is(err, ErrBusy) {
			busy++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || busy != 7 || f.count() != 1 {
		t.Fatalf("duplicate mount: success=%d busy=%d starts=%d", success, busy, f.count())
	}
	if _, err := b.Mount(context.Background(), c, []byte("wrong")); !errors.Is(err, ErrBusy) {
		t.Fatal("existing view accepted as password verification")
	}
}
func TestMountCancellationAndStaleTicket(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(map[bool]string{false: "canceled", true: "stale"}[stale], func(t *testing.T) {
			b, state, f, cfg := testBackend(t)
			c := ticket(t, state)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if stale {
				state.Lock()
			} else {
				cancel()
			}
			_, err := b.Mount(ctx, c, []byte("synthetic-password"))
			if err == nil || f.count() != 0 {
				t.Fatalf("invalid request started process: %v", err)
			}
			empty(t, cfg.RuntimeDir)
		})
	}
	b, state, f, cfg := testBackend(t)
	f.mode = "pending"
	entered := make(chan struct{})
	f.started = entered
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	c := ticket(t, state)
	go func() { _, err := b.Mount(ctx, c, []byte("synthetic-password")); result <- err }()
	receive(t, entered)
	cancel()
	if err := receive(t, result); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	empty(t, cfg.RuntimeDir)
}
func TestStaleDuringStartupAndShutdown(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		t.Run(map[bool]string{false: "stale", true: "shutdown"}[shutdown], func(t *testing.T) {
			b, state, f, cfg := testBackend(t)
			f.mode = "pending"
			entered := make(chan struct{})
			f.started = entered
			result := make(chan error, 1)
			c := ticket(t, state)
			go func() { _, err := b.Mount(context.Background(), c, []byte("synthetic-password")); result <- err }()
			receive(t, entered)
			if shutdown {
				if err := b.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				state.Lock()
			}
			if err := receive(t, result); err == nil {
				t.Fatal("invalid startup succeeded")
			}
			empty(t, cfg.RuntimeDir)
		})
	}
}
func TestCrashAndUnexpectedUnmount(t *testing.T) {
	for _, crash := range []bool{false, true} {
		t.Run(map[bool]string{false: "unmount", true: "crash"}[crash], func(t *testing.T) {
			b, state, f, cfg := testBackend(t)
			v, err := b.Mount(context.Background(), ticket(t, state), []byte("synthetic-password"))
			if err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			p := f.child
			if !crash {
				f.entries = nil
			}
			f.mu.Unlock()
			if crash {
				p.exit(2)
			}
			receive(t, v.Done())
			if v.Err() == nil || b.Mounted() {
				t.Fatal("unexpected lifecycle loss not detected")
			}
			empty(t, cfg.RuntimeDir)
		})
	}
}
func TestCleanupFailureRetainsOwnership(t *testing.T) {
	b, state, f, cfg := testBackend(t)
	v, err := b.Mount(context.Background(), ticket(t, state), []byte("synthetic-password"))
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.failUnmount = true
	f.mu.Unlock()
	if err := b.Unmount(context.Background()); !errors.Is(err, ErrCleanup) || strings.Contains(err.Error(), "synthetic-password") {
		t.Fatalf("unsafe cleanup: %v", err)
	}
	if _, err := os.Stat(v.Path); err != nil {
		t.Fatal("lost cleanup path")
	}
	f.mu.Lock()
	f.failUnmount = false
	f.mu.Unlock()
	if err := b.Unmount(context.Background()); err != nil {
		t.Fatal(err)
	}
	empty(t, cfg.RuntimeDir)
}
func TestUnsafePathsAndMissingBinary(t *testing.T) {
	for _, kind := range []string{"store missing", "runtime missing", "runtime public", "store symlink", "config symlink", "runtime symlink", "overlap", "relative", "missing binary", "existing mount"} {
		t.Run(kind, func(t *testing.T) {
			cfg, state, f := fixture(t)
			switch kind {
			case "store missing":
				cfg.Store += "-missing"
			case "runtime missing":
				cfg.RuntimeDir += "-missing"
			case "runtime public":
				if err := os.Chmod(cfg.RuntimeDir, 0755); err != nil {
					t.Fatal(err)
				}
			case "store symlink":
				p := cfg.Store + "-link"
				if err := os.Symlink(cfg.Store, p); err != nil {
					t.Fatal(err)
				}
				cfg.Store = p
			case "runtime symlink":
				p := cfg.RuntimeDir + "-link"
				if err := os.Symlink(cfg.RuntimeDir, p); err != nil {
					t.Fatal(err)
				}
				cfg.RuntimeDir = p
			case "config symlink":
				p := filepath.Join(cfg.Store, "gocryptfs.conf")
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(cfg.Store, "missing"), p); err != nil {
					t.Fatal(err)
				}
			case "overlap":
				cfg.RuntimeDir = cfg.Store
			case "relative":
				cfg.Store = "."
			case "missing binary":
				cfg.Binary = filepath.Join(cfg.RuntimeDir, "no-binary")
			}
			b, err := New(cfg, state)
			if kind == "existing mount" {
				if err != nil {
					t.Fatal(err)
				}
				f.entries = []mountEntry{{ID: 9, Path: cfg.Store, Type: "fuse.gocryptfs", Source: cfg.Store}}
				b.ops = operations{start: f.start, mounts: f.mounts, unmount: f.unmount}
				_, err = b.Mount(context.Background(), ticket(t, state), []byte("synthetic-password"))
				if f.count() != 0 {
					t.Fatal("mounted over existing mount")
				}
				if e := b.Close(); e != nil {
					t.Fatal(e)
				}
			}
			if err == nil {
				if b != nil {
					b.Close()
				}
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}
func TestSeparateBackendsCannotMountSameStore(t *testing.T) {
	b, state, _, cfg := testBackend(t)
	v, err := b.Mount(context.Background(), ticket(t, state), []byte("synthetic-password"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := New(cfg, state)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSystem{}
	other.ops = operations{start: f.start, mounts: f.mounts, unmount: f.unmount}
	defer other.Close()
	if _, err := other.Mount(context.Background(), ticket(t, state), []byte("synthetic-password")); !errors.Is(err, ErrBusy) {
		t.Fatalf("duplicate backend mount: %v", err)
	}
	if v.Path == "" || f.count() != 0 {
		t.Fatal("second process started")
	}
}
func TestClosedBackendAndSecretFormat(t *testing.T) {
	b, state, f, _ := testBackend(t)
	for _, password := range [][]byte{nil, []byte("a\nb"), []byte("a\rb"), []byte("a\x00b"), make([]byte, 4097)} {
		if _, err := b.Mount(context.Background(), ticket(t, state), password); !errors.Is(err, ErrCredentials) {
			t.Fatal("ambiguous credential accepted")
		}
	}
	if f.count() != 0 {
		t.Fatal("invalid credential initiated process")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Mount(context.Background(), ticket(t, state), []byte("synthetic-password")); !errors.Is(err, ErrClosed) {
		t.Fatal("closed backend mounted")
	}
}

func TestUnsafeAncestorsAndWritableConfig(t *testing.T) {
	for _, kind := range []string{"ancestor", "config"} {
		t.Run(kind, func(t *testing.T) {
			cfg, state, _ := fixture(t)
			if kind == "config" {
				if err := os.Chmod(filepath.Join(cfg.Store, "gocryptfs.conf"), 0666); err != nil {
					t.Fatal(err)
				}
			} else {
				parent := filepath.Join(filepath.Dir(cfg.RuntimeDir), "untrusted")
				if err := os.Mkdir(parent, 0700); err != nil {
					t.Fatal(err)
				}
				cfg.RuntimeDir = filepath.Join(parent, "runtime")
				if err := os.Mkdir(cfg.RuntimeDir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(parent, 0777); err != nil {
					t.Fatal(err)
				}
			}
			b, err := New(cfg, state)
			if err == nil {
				b.Close()
				t.Fatal("unsafe path accepted")
			}
		})
	}
}
func TestStackedMountsNeverUnmountForeignView(t *testing.T) {
	b, state, f, _ := testBackend(t)
	v, err := b.Mount(context.Background(), ticket(t, state), []byte("synthetic-password"))
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.entries = append(f.entries, mountEntry{ID: 202, Path: v.Path, Type: "tmpfs", Source: "foreign"})
	f.mu.Unlock()
	if b.Mounted() {
		t.Error("ambiguous stacked mount reported ready")
	}
	if err := b.Unmount(context.Background()); !errors.Is(err, ErrCleanup) {
		t.Errorf("foreign mount ownership accepted: %v", err)
	}
	f.mu.Lock()
	calls := f.unmounts
	f.entries = nil
	f.mu.Unlock()
	if calls != 0 {
		t.Fatal("unmounted a foreign stacked mount")
	}
	if err := b.Unmount(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestRuntimeParentDataPreserved(t *testing.T) {
	b, state, _, cfg := testBackend(t)
	sentinel := filepath.Join(cfg.RuntimeDir, "keep.txt")
	if err := os.WriteFile(sentinel, []byte("owned synthetic sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	v, err := b.Mount(context.Background(), ticket(t, state), []byte("synthetic-password"))
	if err != nil {
		t.Fatal(err)
	}
	if v.Path == cfg.RuntimeDir {
		t.Fatal("mounted over parent data")
	}
	if err := b.Unmount(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(sentinel)
	if err != nil || string(data) != "owned synthetic sentinel" {
		t.Fatal("parent data modified")
	}
}

func (p *fakeChild) Exited() <-chan struct{} { return p.done }

func TestShutdownObservedAtLaunchAndReadiness(t *testing.T) {
	for _, ready := range []bool{false, true} {
		t.Run(map[bool]string{false: "launch", true: "readiness"}[ready], func(t *testing.T) {
			b, state, f, cfg := testBackend(t)
			b.ops.mounts = func() ([]mountEntry, error) {
				entries, err := f.mounts()
				if !ready || len(entries) > 0 {
					b.shutdown()
				}
				return entries, err
			}
			v, err := b.Mount(context.Background(), ticket(t, state), []byte("synthetic-password"))
			if v != nil || !errors.Is(err, ErrClosed) {
				t.Errorf("shutdown publication: %v, %v", v, err)
			}
			if !ready && f.count() != 0 {
				t.Error("started process after shutdown")
			}
			empty(t, cfg.RuntimeDir)
		})
	}
}

func TestDescriptorCleanupFailureRetainsMount(t *testing.T) {
	b, state, _, cfg := testBackend(t)
	var fail atomic.Bool
	fail.Store(true)
	b.cfg.BeforeUnmount = func() error {
		if fail.Load() {
			return errors.New("synthetic sync failure")
		}
		return nil
	}
	view, err := b.Mount(context.Background(), ticket(t, state), []byte("synthetic-password"))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Unmount(context.Background()); !errors.Is(err, ErrCleanup) {
		t.Fatal("cleanup falsely succeeded", err)
	}
	if _, err := os.Stat(view.Path); err != nil {
		t.Fatal("lost retained view", err)
	}
	if !b.Mounted() {
		t.Fatal("lost retained ownership")
	}
	fail.Store(false)
	if err := b.Unmount(context.Background()); err != nil {
		t.Fatal("cleanup retry", err)
	}
	empty(t, cfg.RuntimeDir)
}

func TestManagedBackingRequestsGVfsHiding(t *testing.T) {
	b, state, f, _ := testBackend(t)
	b.cfg.HideFromDesktop = true
	b.ops.start = func(binary string, args []string, password []byte) (child, error) {
		found := false
		for i := 0; i+1 < len(args); i++ {
			if args[i] == "-ko" && args[i+1] == "x-gvfs-hide" {
				found = true
			}
		}
		if !found {
			t.Error("managed plaintext mount lacks GVfs visibility hint")
		}
		return f.start(binary, args, password)
	}
	if _, err := b.Mount(context.Background(), ticket(t, state), []byte("synthetic-password")); err != nil {
		t.Fatal(err)
	}
}
