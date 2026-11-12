//go:build linux

package ghostfs

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/poizdev/veyl/internal/policy"
)

func TestWritableHandlesRenameAndRevocation(t *testing.T) {
	r, b, base := backingFixture(t)
	r.Writable = true
	ctx := context.Background()
	ghost := backingGhost(t, r).Operations().(*backingNode)
	if again := backingGhost(t, r); again != &ghost.Inode {
		t.Fatal("directory identity changed on lookup")
	}
	file, fh, _, e := ghost.Create(ctx, "notes.txt", syscall.O_RDWR|syscall.O_EXCL, 0600, &fuse.EntryOut{})
	if e != 0 {
		t.Fatal("create", e)
	}
	n := file.Operations().(*backingNode)
	if count, e := n.Write(ctx, fh, []byte("hello"), 0); e != 0 || count != 5 {
		t.Fatal("write", count, e)
	}
	dir, e := ghost.Mkdir(ctx, "projects", 0700, &fuse.EntryOut{})
	if e != 0 {
		t.Fatal(e)
	}
	parent := dir.Operations().(*backingNode)
	if e := ghost.Rename(ctx, "notes.txt", parent, "notes.txt", 0); e != 0 {
		t.Fatal("rename", e)
	}
	if count, e := n.Write(ctx, fh, []byte("!"), 5); e != 0 || count != 1 {
		t.Fatal("write after rename", count, e)
	}
	backingRead(t, file, fh, "hello!")
	if e := ghost.Rename(ctx, "projects", ghost, "renamed", 0); e != 0 {
		t.Fatal("rename directory", e)
	}
	extra, h, _, e := parent.Create(ctx, "extra", syscall.O_RDWR|syscall.O_EXCL, 0600, &fuse.EntryOut{})
	if e != 0 {
		t.Fatal("create using renamed directory", e)
	}
	if e := extra.Operations().(fs.NodeReleaser).Release(ctx, h); e != 0 {
		t.Fatal(e)
	}
	if e := n.Fsync(ctx, fh, 0); e != 0 {
		t.Fatal(e)
	}
	actual, err := os.ReadFile(filepath.Join(base, "renamed", "notes.txt"))
	if err != nil || string(actual) != "hello!" {
		t.Fatal("persistence", err)
	}
	r.State.Lock()
	if _, e := n.Write(ctx, fh, []byte("no"), 0); e != syscall.EACCES {
		t.Fatal("revoked write", e)
	}
	adoptFixture(t, r, b)
	if _, e := n.Write(ctx, fh, []byte("no"), 0); e != syscall.EACCES {
		t.Fatal("revived old handle", e)
	}
	fresh := backingLookup(t, backingLookup(t, backingGhost(t, r), "renamed"), "notes.txt")
	freshHandle, _, e := fresh.Operations().(fs.NodeOpener).Open(ctx, syscall.O_RDWR|syscall.O_NOFOLLOW)
	if e != 0 {
		t.Fatal(e)
	}
	backingRead(t, fresh, freshHandle, "hello!")
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := fresh.Operations().(fs.NodeWriter).Write(canceled, freshHandle, []byte("no"), 0); e == 0 {
		t.Fatal("canceled write authorized")
	}
	if e := fresh.Operations().(fs.NodeReleaser).Release(ctx, freshHandle); e != 0 {
		t.Fatal(e)
	}
}

type delayedSessionRoot struct {
	inner            SessionBacking
	epoch            uint64
	acquired, resume chan struct{}
}

func (b *delayedSessionRoot) SessionRoot(ctx context.Context, s *policy.State, epoch uint64) (*os.File, context.Context, error) {
	fd, life, err := b.inner.SessionRoot(ctx, s, epoch)
	if epoch == b.epoch && err == nil {
		close(b.acquired)
		<-b.resume
	}
	return fd, life, err
}
func TestStaleRootAcquisitionCannotCloseNewSession(t *testing.T) {
	r, b, _ := backingFixture(t)
	r.Writable = true
	delayed := &delayedSessionRoot{inner: b, epoch: b.epoch, acquired: make(chan struct{}), resume: make(chan struct{})}
	r.Backing = delayed
	done := make(chan syscall.Errno, 1)
	go func() { _, e := r.Lookup(context.Background(), ".troll", &fuse.EntryOut{}); done <- e }()
	<-delayed.acquired
	r.State.Lock()
	adoptFixture(t, r, b)
	fresh := backingLookup(t, backingLookup(t, backingGhost(t, r), "nested"), "payload")
	node := fresh.Operations().(*backingNode)
	fh, _, e := node.Open(context.Background(), syscall.O_RDWR)
	if e != 0 {
		close(delayed.resume)
		t.Fatal(e)
	}
	close(delayed.resume)
	if e := <-done; e != syscall.EACCES {
		t.Fatal("stale lookup", e)
	}
	if _, e := node.Write(context.Background(), fh, []byte("current"), 0); e != 0 {
		t.Fatal("stale acquisition closed current tree", e)
	}
	if e := node.Release(context.Background(), fh); e != 0 {
		t.Fatal(e)
	}
}
