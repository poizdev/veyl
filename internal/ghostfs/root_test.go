package ghostfs

import (
	"context"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func testRoot() *Root {
	root := &Root{}
	fs.NewNodeFS(root, Options())
	return root
}

func TestReaddirHidesGhost(t *testing.T) {
	root := testRoot()
	root.State.Unlock()
	unlockedGhost(t, root)
	assertRootListing(t, root)
	root.State.Lock()
	assertRootListing(t, root)
}

func assertRootListing(t *testing.T, root *Root) {
	t.Helper()
	stream, errno := root.Readdir(context.Background())
	if errno != 0 {
		t.Fatal(errno)
	}
	defer stream.Close()
	var names []string
	for stream.HasNext() {
		entry, errno := stream.Next()
		if errno != 0 {
			t.Fatal(errno)
		}
		names = append(names, entry.Name)
		if entry.Mode != syscall.S_IFREG || entry.Ino == 0 {
			t.Fatalf("invalid visible entry: %+v", entry)
		}
	}
	if len(names) != 1 || names[0] != "visible.txt" {
		t.Fatalf("listing includes wrong entries: %v", names)
	}
}

func TestLookupDeniedAndUnknown(t *testing.T) {
	root := testRoot()
	for _, tc := range []struct {
		name string
		want syscall.Errno
	}{
		{".troll", syscall.EACCES}, {"missing", syscall.ENOENT}, {".other", syscall.ENOENT},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for range 3 {
				node, errno := root.Lookup(context.Background(), tc.name, &fuse.EntryOut{})
				if errno != tc.want || node != nil {
					t.Fatalf("Lookup(%q) = %v, %v", tc.name, node, errno)
				}
				if root.GetChild(tc.name) != nil {
					t.Fatal("denied/unknown child cached")
				}
			}
		})
	}
}

func TestVisibleFile(t *testing.T) {
	ctx := context.Background()
	root := testRoot()
	var entry fuse.EntryOut
	node, errno := root.Lookup(ctx, "visible.txt", &entry)
	if errno != 0 || node == nil {
		t.Fatalf("lookup: %v", errno)
	}
	if entry.Mode != syscall.S_IFREG|0444 || entry.Size != uint64(len(VisibleContent)) {
		t.Fatalf("attributes: %+v", entry.Attr)
	}
	file := node.Operations().(*textFile)
	if _, _, errno := file.Open(ctx, syscall.O_RDONLY); errno != 0 {
		t.Fatal(errno)
	}
	for _, flags := range []uint32{syscall.O_WRONLY, syscall.O_RDWR, syscall.O_TRUNC, syscall.O_APPEND} {
		if _, _, errno := file.Open(ctx, flags); errno != syscall.EROFS {
			t.Fatalf("Open(%d) = %v", flags, errno)
		}
	}
	result, errno := file.Read(ctx, nil, make([]byte, 4096), 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	defer result.Done()
	data, status := result.Bytes(make([]byte, 4096))
	if status != fuse.OK || string(data) != VisibleContent {
		t.Fatalf("read: %q, %v", data, status)
	}
	result, errno = file.Read(ctx, nil, make([]byte, 4), 2)
	if errno != 0 {
		t.Fatal(errno)
	}
	defer result.Done()
	data, status = result.Bytes(make([]byte, 4))
	if status != fuse.OK || string(data) != VisibleContent[2:6] {
		t.Fatalf("partial read: %q", data)
	}
	result, errno = file.Read(ctx, nil, make([]byte, 4), int64(len(VisibleContent)+10))
	if errno != 0 {
		t.Fatal(errno)
	}
	defer result.Done()
	data, _ = result.Bytes(make([]byte, 4))
	if len(data) != 0 {
		t.Fatal("expected EOF")
	}
	if _, errno := file.Read(ctx, nil, make([]byte, 4), -1); errno != syscall.EINVAL {
		t.Fatalf("negative offset: %v", errno)
	}
}

func TestMountOptions(t *testing.T) {
	opts := Options()
	found := false
	for _, opt := range opts.MountOptions.Options {
		if opt == "ro" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing read-only mount option")
	}
	if opts.AllowOther {
		t.Fatal("must not enable allow_other")
	}
	for _, timeout := range []*time.Duration{opts.EntryTimeout, opts.AttrTimeout, opts.NegativeTimeout} {
		if timeout == nil || *timeout != 0 {
			t.Fatal("cache timeout must be explicitly zero")
		}
	}
}

func TestMountOptionsRequestGVfsHidingWithoutChangingAccess(t *testing.T) {
	for _, writable := range []bool{false, true} {
		opts := OptionsForDesktop(writable, true)
		hidden := false
		for _, option := range opts.Options {
			if option == "x-gvfs-hide" {
				hidden = true
			}
		}
		if !hidden {
			t.Fatal("missing per-mount GVfs visibility hint")
		}
		if opts.DirectMount || opts.DirectMountStrict || opts.AllowOther {
			t.Fatal("must retain fusermount mounting and UID isolation")
		}
	}
}

func TestDesktopHintCanBeOmittedForOlderHelpers(t *testing.T) {
	opts := OptionsForDesktop(true, false)
	for _, option := range opts.Options {
		if option == "x-gvfs-hide" {
			t.Fatal("hint cannot be omitted for older helper")
		}
	}
}
