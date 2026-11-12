package ghostfs

import (
	"context"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/poizdev/veyl/internal/policy"
)

func TestConfiguredHiddenNameUsesExistingPolicy(t *testing.T) {
	root := &Root{HiddenName: ".vault"}
	fs.NewNodeFS(root, Options())
	if _, e := root.Lookup(context.Background(), ".vault", &fuse.EntryOut{}); e != syscall.EACCES {
		t.Fatalf("locked name: %v", e)
	}
	root.State.Unlock()
	if _, e := root.Lookup(context.Background(), ".vault", &fuse.EntryOut{}); e != 0 {
		t.Fatalf("configured path: %v", e)
	}
	if _, e := root.Lookup(context.Background(), policy.GhostName, &fuse.EntryOut{}); e != syscall.ENOENT {
		t.Fatalf("default alias exposed: %v", e)
	}
	assertRootListing(t, root)
	root.State.Lock()
}
