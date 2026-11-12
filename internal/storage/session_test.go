//go:build linux

package storage

import (
	"context"
	"errors"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/poizdev/veyl/internal/policy"
	"golang.org/x/sys/unix"
)

func TestSessionRootRequiresAdoptionAndMountIdentity(t *testing.T) {
	b, s, f, _ := testBackend(t)
	useFixtureMountID(b, f, false)
	c, err := b.Prepare(context.Background(), ticket(t, s), []byte("synthetic-password"))
	if err != nil {
		t.Fatal(err)
	}
	if fd, _, err := b.SessionRoot(context.Background(), s, 1); err == nil {
		fd.Close()
		t.Fatal("prepared view published")
	}
	if !c.Commit(func() bool { return true }) {
		t.Fatal("commit")
	}
	epoch, _ := s.Session()
	if fd, _, err := b.SessionRoot(context.Background(), s, epoch); err == nil {
		fd.Close()
		t.Fatal("unverified mount identity accepted")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	useFixtureMountID(b, f, true)
	c, err = b.Prepare(context.Background(), ticket(t, s), []byte("synthetic-password"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Commit(func() bool { return true }) {
		t.Fatal("second commit")
	}
	epoch, _ = s.Session()
	other := &policy.State{}
	other.Unlock()
	other.Lock()
	other.Unlock()
	if !other.Valid(epoch) {
		t.Fatal("foreign policy must have the same numeric epoch")
	}
	if fd, _, err := b.SessionRoot(context.Background(), other, epoch); err == nil {
		fd.Close()
		t.Fatal("foreign policy accepted")
	}
	fd, life, err := b.SessionRoot(context.Background(), s, epoch)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := fd.Stat(); err != nil || !info.IsDir() {
		t.Fatal("invalid session descriptor")
	}
	fd.Close()
	s.Lock()
	select {
	case <-life.Done():
	default:
		t.Fatal("session descriptor lifetime not canceled")
	}
	if fd, _, err := b.SessionRoot(context.Background(), s, epoch); err == nil {
		fd.Close()
		t.Fatal("revoked tree published")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSessionRootClosedBeforeUnmount(t *testing.T) {
	b, s, f, _ := testBackend(t)
	useFixtureMountID(b, f, true)
	c, err := b.Prepare(context.Background(), ticket(t, s), []byte("synthetic-password"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Commit(func() bool { return true }) {
		t.Fatal("commit")
	}
	epoch, _ := s.Session()
	fd, _, err := b.SessionRoot(context.Background(), s, epoch)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	b.ops.unmount = func(ctx context.Context, path string) error {
		if _, err := fd.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Error("session root still open during unmount")
		}
		return f.unmount(ctx, path)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSessionRootBorrowAndDrainBeforeUnmount(t *testing.T) {
	b, s, f, _ := testBackend(t)
	useFixtureMountID(b, f, true)
	c, err := b.Prepare(context.Background(), ticket(t, s), []byte("synthetic-password"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Commit(func() bool { return true }) {
		t.Fatal("commit")
	}
	epoch, _ := s.Session()
	fd, _, err := b.SessionRoot(context.Background(), s, epoch)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := fd.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	release, ok := s.Begin(epoch)
	if !ok {
		t.Fatal("lease")
	}
	var leaseOnce sync.Once
	endLease := func() { leaseOnce.Do(release) }
	defer endLease()
	entered, resume, borrowed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	resumeBorrow := func() { once.Do(func() { close(resume) }) }
	defer resumeBorrow()
	go func() { _ = raw.Control(func(uintptr) { close(entered); <-resume }); close(borrowed) }()
	receive(t, entered)
	unmounted := make(chan struct{})
	b.ops.unmount = func(ctx context.Context, path string) error { close(unmounted); return f.unmount(ctx, path) }
	ended := make(chan error, 1)
	go func() { ended <- b.Unmount(context.Background()) }()
	deadline := time.After(time.Second)
	for !s.IsLocked() {
		select {
		case <-deadline:
			endLease()
			t.Fatal("revocation not published")
		default:
			runtime.Gosched()
		}
	}
	select {
	case <-unmounted:
		t.Error("unmount preceded admitted I/O drain")
	default:
	}
	// A real tree holds its policy lease throughout root descriptor borrowing.
	// Release the descriptor before the lease, as every bridge operation does.
	resumeBorrow()
	receive(t, borrowed)
	endLease()
	if err := receive(t, ended); err != nil {
		t.Fatal(err)
	}
	receive(t, unmounted)
}

// Set the fake mount table's ID during startup, before Backend publishes m.id
// and starts its watcher. Never mutate the immutable mount identity afterward.
func useFixtureMountID(b *Backend, f *fakeSystem, match bool) {
	start := b.ops.start
	b.ops.start = func(binary string, args []string, proof []byte) (child, error) {
		p, err := start(binary, args, proof)
		if err != nil {
			return p, err
		}
		var st unix.Statx_t
		if err := unix.Statx(unix.AT_FDCWD, args[len(args)-1], unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &st); err != nil {
			return p, err
		}
		if !match {
			st.Mnt_id ^= 1
		}
		f.mu.Lock()
		for i := range f.entries {
			f.entries[i].ID = st.Mnt_id
		}
		f.mu.Unlock()
		return p, nil
	}
}
