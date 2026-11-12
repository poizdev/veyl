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
)

func TestManagedParentPreservesSiblingsAndRejectsChanges(t *testing.T) {
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "ordinary"), []byte("sibling"), 0600); err != nil {
		t.Fatal(err)
	}
	r := &Root{}
	if err := r.SetParent(source); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.CloseParent(); err != nil {
			t.Error(err)
		}
	})
	fs.NewNodeFS(r, OptionsFor(true))
	ctx := context.Background()
	sibling, e := r.Lookup(ctx, "ordinary", &fuse.EntryOut{})
	if e != 0 {
		t.Fatal(e)
	}
	fh, _, e := sibling.Operations().(fs.NodeOpener).Open(ctx, syscall.O_RDWR)
	if e != 0 {
		t.Fatal(e)
	}
	if _, e := sibling.Operations().(fs.NodeWriter).Write(ctx, fh, []byte("public"), 0); e != 0 {
		t.Fatal(e)
	}
	if e := sibling.Operations().(fs.NodeReleaser).Release(ctx, fh); e != 0 {
		t.Fatal(e)
	}
	if !r.State.IsLocked() {
		t.Fatal("public access unlocked protected branch")
	}
	if _, e := r.Mkdir(ctx, ".troll", 0700, &fuse.EntryOut{}); e != syscall.EPERM {
		t.Fatal("reserved anchor", e)
	}
	if e := r.Rename(ctx, "ordinary", r, "renamed", 0); e != 0 {
		t.Fatal(e)
	}
	if _, err := os.Stat(filepath.Join(source, "renamed")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(source, ".troll"), 0700); err != nil {
		t.Fatal(err)
	}
	if r.NamespaceError() == nil {
		t.Fatal("reserved collision accepted")
	}
	if _, e := r.Lookup(ctx, "renamed", &fuse.EntryOut{}); e == 0 {
		t.Fatal("changed namespace still admitted")
	}
}

func TestRemovedParentDirectoriesRetireOnForget(t *testing.T) {
	r := &Root{}
	if err := r.SetParent(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer r.CloseParent()
	fs.NewNodeFS(r, OptionsFor(true))
	ctx := context.Background()
	for range 32 {
		inode, e := r.Mkdir(ctx, "temporary", 0700, &fuse.EntryOut{})
		if e != 0 {
			t.Fatal(e)
		}
		if e := r.Rmdir(ctx, "temporary"); e != 0 {
			t.Fatal(e)
		}
		inode.Operations().(*backingNode).OnForget()
	}
	tree := r.parent.tree
	tree.directoryMu.Lock()
	defer tree.directoryMu.Unlock()
	if len(tree.directories) != 0 {
		t.Fatal("deleted directory identities retained", len(tree.directories))
	}
	tree.mu.RLock()
	defer tree.mu.RUnlock()
	if len(tree.files) != 1 {
		t.Fatal("deleted directory descriptors retained", len(tree.files))
	}
}
