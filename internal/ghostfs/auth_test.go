package ghostfs

import (
	"context"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/poizdev/veyl/internal/auth"
)

type mockAgent func(context.Context, auth.Request) (auth.Response, error)

func (f mockAgent) Authenticate(ctx context.Context, req auth.Request) (auth.Response, error) {
	return f(ctx, req)
}

type mockVerifier struct{}

func (mockVerifier) Verify(_ context.Context, _ auth.Request, resp auth.Response) (bool, error) {
	return string(resp.Proof) == "test-only", nil
}

func TestDirectAccessBroker(t *testing.T) {
	root := testRoot()
	var calls atomic.Int64
	root.Auth = auth.New(&root.State, mockAgent(func(_ context.Context, req auth.Request) (auth.Response, error) {
		calls.Add(1)
		return auth.Response{RequestID: req.ID, Approved: true, Proof: []byte("test-only")}, nil
	}), mockVerifier{}, time.Second)
	assertRootListing(t, root)
	if calls.Load() != 0 {
		t.Fatal("listing requested authentication")
	}
	if _, e := root.Lookup(context.Background(), "unknown", &fuse.EntryOut{}); e != syscall.ENOENT || calls.Load() != 0 {
		t.Fatal("unknown path requested authentication")
	}
	node, e := root.Lookup(context.Background(), ".troll", &fuse.EntryOut{})
	if e != 0 || node == nil {
		t.Fatalf("direct approved lookup: %v", e)
	}
	if calls.Load() != 1 {
		t.Fatal("wrong request count")
	}
	dir := node.Operations().(*ghostDirectory)
	file := ghostFile(t, dir)
	handle, flags, e := file.Open(context.Background(), 0)
	if e != 0 || flags&fuse.FOPEN_DIRECT_IO == 0 {
		t.Fatal(e)
	}
	readContent(t, file, handle, HelloContent)
	root.State.Lock()
	assertRootListing(t, root)
	if _, e := root.Lookup(context.Background(), ".troll", &fuse.EntryOut{}); e != 0 {
		t.Fatal(e)
	}
	result, e := file.Read(context.Background(), handle, make([]byte, 32), 0)
	if result != nil {
		result.Done()
	}
	if e != syscall.EACCES {
		t.Fatal("authentication revived old handle")
	}
	assertRootListing(t, root)
}

func TestBrokerRecursiveLookup(t *testing.T) {
	root := testRoot()
	root.Auth = auth.New(&root.State, mockAgent(func(ctx context.Context, _ auth.Request) (auth.Response, error) {
		if _, e := root.Lookup(ctx, ".troll", &fuse.EntryOut{}); e != syscall.EACCES {
			t.Errorf("recursive lookup: %v", e)
		}
		return auth.Response{}, nil
	}), mockVerifier{}, time.Second)
	done := make(chan syscall.Errno, 1)
	go func() { _, e := root.Lookup(context.Background(), ".troll", &fuse.EntryOut{}); done <- e }()
	select {
	case e := <-done:
		if e != syscall.EACCES {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("recursive FUSE lookup deadlocked")
	}
	if !root.State.IsLocked() {
		t.Fatal("recursive access unlocked state")
	}
}

var _ fs.NodeLookuper = (*Root)(nil)

func TestBridgeAuthenticationLookup(t *testing.T) {
	root := &Root{}
	var calls atomic.Int64
	root.Auth = auth.New(&root.State, mockAgent(func(_ context.Context, req auth.Request) (auth.Response, error) {
		calls.Add(1)
		return auth.Response{RequestID: req.ID, Approved: true, Proof: []byte("test-only")}, nil
	}), mockVerifier{}, time.Second)
	raw := fs.NewNodeFS(root, Options())
	var entry fuse.EntryOut
	if status := raw.Lookup(nil, &fuse.InHeader{NodeId: 1}, ".troll", &entry); status != fuse.OK {
		t.Fatal(status)
	}
	if entry.Mode != syscall.S_IFDIR|0555 || calls.Load() != 1 {
		t.Fatal("broker was not used for raw lookup")
	}
	assertRootListing(t, root)
}

func TestExplicitUnlockDoesNotPromptForFilesystemProbes(t *testing.T) {
	root := &Root{ExplicitUnlock: true}
	var calls atomic.Int64
	root.Auth = auth.New(&root.State, mockAgent(func(_ context.Context, req auth.Request) (auth.Response, error) {
		calls.Add(1)
		return auth.Response{RequestID: req.ID, Approved: true, Proof: []byte("test-only")}, nil
	}), mockVerifier{}, time.Second)
	fs.NewNodeFS(root, Options())
	for range 20 {
		if _, e := root.Lookup(context.Background(), ".troll", &fuse.EntryOut{}); e != syscall.EACCES {
			t.Fatal(e)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("filesystem probes requested authentication")
	}
	if err := root.Auth.RequestAccess(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, e := root.Lookup(context.Background(), ".troll", &fuse.EntryOut{}); e != 0 {
		t.Fatal(e)
	}
	if calls.Load() != 1 {
		t.Fatal("explicit authentication not used")
	}
}
