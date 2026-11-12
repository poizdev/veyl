//go:build linux

package storage

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestPreparedCommitSurvivesAttempt(t *testing.T) {
	b, s, _, cfg := testBackend(t)
	attempt, cancel := context.WithCancel(context.Background())
	c, err := b.Prepare(attempt, ticket(t, s), []byte("synthetic-password"))
	if err != nil {
		t.Fatal(err)
	}
	if !s.IsLocked() {
		t.Fatal("prepare granted access")
	}
	if !c.Commit(func() bool { return attempt.Err() == nil }) {
		t.Fatal("commit rejected")
	}
	epoch, _ := s.Session()
	cancel()
	if !b.Mounted() || !s.Valid(epoch) {
		t.Fatal("attempt completion ended adopted session")
	}
	if c.Commit(func() bool { return true }) {
		t.Fatal("double commit")
	}
	if err := c.Rollback(); !errors.Is(err, ErrAdopted) {
		t.Fatalf("rollback adopted: %v", err)
	}
	s.Lock()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if s.Valid(epoch) {
		t.Fatal("old handle valid")
	}
	empty(t, cfg.RuntimeDir)
}
func TestPreparedRejectsInvalidCommit(t *testing.T) {
	for _, kind := range []string{"lock", "cancel", "guard", "rollback"} {
		t.Run(kind, func(t *testing.T) {
			b, s, _, cfg := testBackend(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c, err := b.Prepare(ctx, ticket(t, s), []byte("synthetic-password"))
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "lock":
				s.Lock()
			case "cancel":
				cancel()
			case "rollback":
				if err := c.Rollback(); err != nil {
					t.Fatal(err)
				}
			}
			if c.Commit(func() bool { return kind != "guard" }) {
				t.Fatal("invalid commit accepted")
			}
			if err := c.Rollback(); err != nil {
				t.Fatal(err)
			}
			if err := c.Rollback(); err != nil {
				t.Fatal(err)
			}
			if !s.IsLocked() {
				t.Fatal("rejected candidate authorized")
			}
			empty(t, cfg.RuntimeDir)
		})
	}
}
func TestAdoptedBackendFailureBeforeCleanup(t *testing.T) {
	for _, kind := range []string{"crash", "external", "unmount"} {
		t.Run(kind, func(t *testing.T) {
			b, s, f, cfg := testBackend(t)
			c, err := b.Prepare(context.Background(), ticket(t, s), []byte("synthetic-password"))
			if err != nil {
				t.Fatal(err)
			}
			if !c.Commit(func() bool { return true }) {
				t.Fatal("commit")
			}
			epoch, _ := s.Session()
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			b.ops.unmount = func(ctx context.Context, path string) error {
				once.Do(func() { close(entered) })
				<-release
				return f.unmount(ctx, path)
			}
			f.mu.Lock()
			p := f.child
			if kind == "external" {
				f.entries = nil
			}
			f.mu.Unlock()
			done := make(chan error, 1)
			switch kind {
			case "crash":
				p.exit(2)
			case "unmount":
				go func() { done <- b.Unmount(context.Background()) }()
			}
			if kind != "external" {
				receive(t, entered)
			}
			deadline := time.After(time.Second)
			for s.Valid(epoch) {
				select {
				case <-deadline:
					t.Fatal("backend failure waited for cleanup")
				default:
					time.Sleep(time.Millisecond)
				}
			}
			close(release)
			if kind == "unmount" {
				if err := receive(t, done); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			empty(t, cfg.RuntimeDir)
		})
	}
}
func TestTransactionFailedCleanupRetainsOwner(t *testing.T) {
	b, s, f, cfg := testBackend(t)
	c, err := b.Prepare(context.Background(), ticket(t, s), []byte("synthetic-password"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Commit(func() bool { return true }) {
		t.Fatal("commit")
	}
	f.mu.Lock()
	f.failUnmount = true
	f.mu.Unlock()
	if err := c.Close(); !errors.Is(err, ErrCleanup) {
		t.Fatalf("cleanup: %v", err)
	}
	if !s.IsLocked() || !c.Owned() {
		t.Fatal("failed cleanup lost owner or authorization")
	}
	if _, err := b.Prepare(context.Background(), ticket(t, s), []byte("synthetic-password")); !errors.Is(err, ErrBusy) {
		t.Fatalf("residue reused: %v", err)
	}
	f.mu.Lock()
	f.failUnmount = false
	f.mu.Unlock()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if c.Owned() {
		t.Fatal("confirmed cleanup retained ownership")
	}
	empty(t, cfg.RuntimeDir)
}
func TestTransactionLockCommitUnmountRace(t *testing.T) {
	for range 40 {
		b, s, _, cfg := testBackend(t)
		c, err := b.Prepare(context.Background(), ticket(t, s), []byte("synthetic-password"))
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		done := make(chan struct{}, 3)
		go func() { <-start; c.Commit(func() bool { return true }); done <- struct{}{} }()
		go func() { <-start; s.Lock(); done <- struct{}{} }()
		go func() { <-start; _ = b.Unmount(context.Background()); done <- struct{}{} }()
		close(start)
		for range 3 {
			receive(t, done)
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		if !s.IsLocked() {
			t.Fatal("race left authorization")
		}
		empty(t, cfg.RuntimeDir)
	}
}

func TestPrepareAlreadyCanceledNeverLaunches(t *testing.T) {
	b, s, f, cfg := testBackend(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 200 {
		c, err := b.Prepare(ctx, ticket(t, s), []byte("synthetic-password"))
		if err == nil || c != nil {
			t.Fatalf("canceled prepare: %v", err)
		}
	}
	if f.count() != 0 {
		t.Fatalf("launched %d processes for canceled attempts", f.count())
	}
	empty(t, cfg.RuntimeDir)
}

func TestLockDoesNotHoldTransitionsDuringUnmount(t *testing.T) {
	b, s, f, cfg := testBackend(t)
	c, err := b.Prepare(context.Background(), ticket(t, s), []byte("synthetic-password"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Commit(func() bool { return true }) {
		t.Fatal("commit")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	b.ops.unmount = func(ctx context.Context, path string) error {
		once.Do(func() { close(entered) })
		<-release
		return f.unmount(ctx, path)
	}
	locked := make(chan struct{})
	go func() { s.Lock(); close(locked) }()
	receive(t, entered)
	receive(t, locked)
	if _, ok := s.Challenge(); !ok {
		t.Error("external unmount holds policy transition lock")
	}
	close(release)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	empty(t, cfg.RuntimeDir)
}

func TestOldResourceCannotUnmountOrRevokeNewSession(t *testing.T) {
	b, s, _, cfg := testBackend(t)
	old, err := b.Prepare(context.Background(), ticket(t, s), []byte("synthetic-password"))
	if err != nil {
		t.Fatal(err)
	}
	if !old.Commit(func() bool { return true }) {
		t.Fatal("old commit")
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := b.Prepare(context.Background(), ticket(t, s), []byte("synthetic-password"))
	if err != nil {
		t.Fatal(err)
	}
	if !next.Commit(func() bool { return true }) {
		t.Fatal("new commit")
	}
	epoch, _ := s.Session()
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	if err := old.Rollback(); err != nil {
		t.Fatal(err)
	}
	if !next.Owned() || !s.Valid(epoch) || !b.Mounted() {
		t.Fatal("old owner affected new session")
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
	empty(t, cfg.RuntimeDir)
}

func TestBackendShutdownBeforeCommitRejectsAdoption(t *testing.T) {
	b, s, _, cfg := testBackend(t)
	c, err := b.Prepare(context.Background(), ticket(t, s), []byte("synthetic-password"))
	if err != nil {
		t.Fatal(err)
	}
	b.shutdown()
	if c.Commit(func() bool { return true }) {
		t.Error("closed backend adopted")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if !s.IsLocked() {
		t.Fatal("shutdown authorized")
	}
	empty(t, cfg.RuntimeDir)
}

// The final authorization guard may race cancellation or backend shutdown.
// Liveness observed before that guard cannot authorize its later result.
func TestCommitRechecksLifetimeAfterGuard(t *testing.T) {
	for _, kind := range []string{"attempt cancellation", "backend shutdown"} {
		t.Run(kind, func(t *testing.T) {
			b, s, _, cfg := testBackend(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c, err := b.Prepare(ctx, ticket(t, s), []byte("synthetic-password"))
			if err != nil {
				t.Fatal(err)
			}
			accepted := c.Commit(func() bool {
				if kind == "attempt cancellation" {
					cancel()
				} else {
					b.shutdown()
				}
				return true
			})
			if accepted || !s.IsLocked() {
				t.Error("lifetime ended during guard but candidate was adopted")
			}
			// Close also cleans up if this regression incorrectly adopted.
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			if c.Owned() {
				t.Fatal("rejected candidate retained ownership after cleanup")
			}
			empty(t, cfg.RuntimeDir)
		})
	}
}
