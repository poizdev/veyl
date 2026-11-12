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

func TestOriginalParentPinsEmptyTarget(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "test")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "sibling"), []byte("public"), 0600); err != nil {
		t.Fatal(err)
	}
	r := &Root{HiddenName: "test"}
	if err := r.SetOriginalParent(parent); err != nil {
		t.Fatal(err)
	}
	defer r.CloseParent()
	fs.NewNodeFS(r, OptionsFor(true))
	if _, e := r.Lookup(context.Background(), "sibling", &fuse.EntryOut{}); e != 0 {
		t.Fatal(e)
	}
	stream, e := r.Readdir(context.Background())
	if e != 0 {
		t.Fatal(e)
	}
	defer stream.Close()
	for stream.HasNext() {
		entry, e := stream.Next()
		if e != 0 || entry.Name == "test" {
			t.Fatal(entry, e)
		}
	}
	if err := os.Symlink("sibling", filepath.Join(parent, "link")); err != nil {
		t.Fatal(err)
	}
	linked, e := r.Lookup(context.Background(), "link", &fuse.EntryOut{})
	if e != 0 {
		t.Fatal("public symlink disappeared", e)
	}
	targetBytes, e := linked.Operations().(fs.NodeReadlinker).Readlink(context.Background())
	if e != 0 || string(targetBytes) != "sibling" {
		t.Fatal(string(targetBytes), e)
	}
	in := &fuse.SetAttrIn{}
	in.Valid = fuse.FATTR_MODE
	in.Mode = 0700
	if e := linked.Operations().(fs.NodeSetattrer).Setattr(context.Background(), nil, in, &fuse.AttrOut{}); e != syscall.EOPNOTSUPP {
		t.Fatal("symlink metadata followed backing target", e)
	}
	if info, err := os.Stat(filepath.Join(parent, "sibling")); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("symlink target mode changed", err)
	}
	if e := r.Setattr(context.Background(), nil, &fuse.SetAttrIn{}, &fuse.AttrOut{}); e != 0 {
		t.Fatal("ordinary parent metadata unavailable", e)
	}
	fifo := filepath.Join(parent, "late-ipc")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if stream, e := r.Readdir(context.Background()); e != syscall.EOPNOTSUPP {
		if stream != nil {
			stream.Close()
		}
		t.Fatal("silently omitted unsupported sibling", e)
	}
	if info, err := os.Lstat(fifo); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatal("sibling was altered", err)
	}
	if err := os.Remove(fifo); err != nil {
		t.Fatal(err)
	}
	// An old cwd descriptor can populate the shadowed original. Never adopt it.
	if err := os.WriteFile(filepath.Join(target, "unexpected"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if r.NamespaceError() == nil {
		t.Fatal("accepted populated original target")
	}
	if _, e := r.Lookup(context.Background(), "sibling", &fuse.EntryOut{}); e != syscall.ESTALE {
		t.Fatal(e)
	}
}
