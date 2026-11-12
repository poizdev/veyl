package ghostfs

import (
	"context"
	"sync"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func unlockedGhost(t *testing.T, root *Root) *ghostDirectory {
	t.Helper()
	root.State.Unlock()
	var out fuse.EntryOut
	node, errno := root.Lookup(context.Background(), ".troll", &out)
	if errno != 0 || node == nil {
		t.Fatalf("unlocked lookup: %v", errno)
	}
	if out.Mode != syscall.S_IFDIR|0555 {
		t.Fatalf("directory mode: %o", out.Mode)
	}
	// Model a child already known to go-fuse/the VFS.
	root.AddChild(".troll", node, true)
	return node.Operations().(*ghostDirectory)
}

func ghostFile(t *testing.T, dir *ghostDirectory) *textFile {
	t.Helper()
	var out fuse.EntryOut
	node, errno := dir.Lookup(context.Background(), "hello.txt", &out)
	if errno != 0 || node == nil {
		t.Fatalf("hello lookup: %v", errno)
	}
	if out.Mode != syscall.S_IFREG|0444 || out.Size != uint64(len(HelloContent)) {
		t.Fatalf("file attributes: %+v", out.Attr)
	}
	return node.Operations().(*textFile)
}

func TestGhostTransitionsAndRetainedInodes(t *testing.T) {
	ctx := context.Background()
	root := testRoot()
	if _, errno := root.Lookup(ctx, ".troll", &fuse.EntryOut{}); errno != syscall.EACCES {
		t.Fatal(errno)
	}
	dir := unlockedGhost(t, root)
	file := ghostFile(t, dir)
	if _, errno := root.Lookup(ctx, "unknown", &fuse.EntryOut{}); errno != syscall.ENOENT {
		t.Fatal(errno)
	}
	if _, errno := dir.Lookup(ctx, "unknown", &fuse.EntryOut{}); errno != syscall.ENOENT {
		t.Fatal(errno)
	}
	fh, flags, errno := file.Open(ctx, syscall.O_RDONLY)
	if errno != 0 || flags&fuse.FOPEN_DIRECT_IO == 0 || flags&fuse.FOPEN_KEEP_CACHE != 0 {
		t.Fatalf("open: flags %x errno %v", flags, errno)
	}
	readContent(t, file, fh, HelloContent)
	dh, dirFlags, errno := dir.OpendirHandle(ctx, syscall.O_RDONLY)
	if errno != 0 || dirFlags&(fuse.FOPEN_CACHE_DIR|fuse.FOPEN_KEEP_CACHE) != 0 {
		t.Fatalf("opendir: %v, %x", errno, dirFlags)
	}
	entry, errno := dh.(fs.FileReaddirenter).Readdirent(ctx)
	if errno != 0 || entry == nil || entry.Name != "hello.txt" {
		t.Fatalf("readdir: %v, %v", entry, errno)
	}
	if errno := dir.Access(ctx, 5); errno != 0 {
		t.Fatal(errno)
	}
	if errno := file.Access(ctx, 4); errno != 0 {
		t.Fatal(errno)
	}
	if errno := file.Getattr(ctx, fh, &fuse.AttrOut{}); errno != 0 {
		t.Fatal(errno)
	}
	if errno := dir.Getattr(ctx, nil, &fuse.AttrOut{}); errno != 0 {
		t.Fatal(errno)
	}
	root.State.Lock()
	assertRootListing(t, root)
	if _, errno := root.Lookup(ctx, ".troll", &fuse.EntryOut{}); errno != syscall.EACCES {
		t.Fatalf("root relock: %v", errno)
	}
	for name, check := range map[string]func() syscall.Errno{
		"directory lookup":        func() syscall.Errno { _, e := dir.Lookup(ctx, "hello.txt", &fuse.EntryOut{}); return e },
		"directory getattr":       func() syscall.Errno { return dir.Getattr(ctx, nil, &fuse.AttrOut{}) },
		"directory access":        func() syscall.Errno { return dir.Access(ctx, 5) },
		"directory open":          func() syscall.Errno { _, _, e := dir.OpendirHandle(ctx, 0); return e },
		"retained directory read": func() syscall.Errno { _, e := dh.(fs.FileReaddirenter).Readdirent(ctx); return e },
		"retained directory seek": func() syscall.Errno { return dh.(fs.FileSeekdirer).Seekdir(ctx, 0) },
		"file getattr":            func() syscall.Errno { return file.Getattr(ctx, fh, &fuse.AttrOut{}) },
		"file access":             func() syscall.Errno { return file.Access(ctx, 4) },
		"file open":               func() syscall.Errno { _, _, e := file.Open(ctx, 0); return e },
		"retained file read":      func() syscall.Errno { _, e := file.Read(ctx, fh, make([]byte, 32), 0); return e },
	} {
		t.Run(name, func(t *testing.T) {
			if e := check(); e != syscall.EACCES {
				t.Fatalf("want EACCES, got %v", e)
			}
		})
	}
	// Old handles and old inodes never revive in a later session.
	root.State.Unlock()
	if _, e := file.Read(ctx, fh, make([]byte, 32), 0); e != syscall.EACCES {
		t.Fatalf("old file revived: %v", e)
	}
	if e := dh.(fs.FileSeekdirer).Seekdir(ctx, 0); e != syscall.EACCES {
		t.Fatalf("old directory revived: %v", e)
	}
	freshDir := unlockedGhost(t, root)
	freshFile := ghostFile(t, freshDir)
	freshHandle, _, e := freshFile.Open(ctx, 0)
	if e != 0 {
		t.Fatal(e)
	}
	readContent(t, freshFile, freshHandle, HelloContent)
	other := testRoot()
	if !other.State.IsLocked() {
		t.Fatal("roots share state")
	}
}

func readContent(t *testing.T, file *textFile, fh fs.FileHandle, want string) {
	t.Helper()
	result, errno := file.Read(context.Background(), fh, make([]byte, 4096), 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	defer result.Done()
	data, status := result.Bytes(make([]byte, 4096))
	if status != fuse.OK || string(data) != want {
		t.Fatalf("content: %q, status %v", data, status)
	}
}

func TestGhostReadOnly(t *testing.T) {
	root := testRoot()
	dir := unlockedGhost(t, root)
	file := ghostFile(t, dir)
	ctx := context.Background()
	for _, flags := range []uint32{syscall.O_WRONLY, syscall.O_RDWR, syscall.O_TRUNC, syscall.O_APPEND} {
		if _, _, e := file.Open(ctx, flags); e != syscall.EROFS {
			t.Fatalf("file open flags %x: %v", flags, e)
		}
		if _, _, e := dir.OpendirHandle(ctx, flags); e != syscall.EROFS {
			t.Fatalf("directory open flags %x: %v", flags, e)
		}
	}
	if e := file.Access(ctx, 2); e != syscall.EROFS {
		t.Fatal(e)
	}
	if e := dir.Access(ctx, 2); e != syscall.EROFS {
		t.Fatal(e)
	}
	if e := file.Access(ctx, 1); e != syscall.EACCES {
		t.Fatal(e)
	}
	// The ordinary file stays readable and read-only in both states.
	for _, locked := range []bool{false, true} {
		if locked {
			root.State.Lock()
		} else {
			root.State.Unlock()
		}
		node, e := root.Lookup(ctx, "visible.txt", &fuse.EntryOut{})
		if e != 0 {
			t.Fatal(e)
		}
		visible := node.Operations().(*textFile)
		readContent(t, visible, nil, VisibleContent)
		for _, flags := range []uint32{syscall.O_WRONLY, syscall.O_RDWR, syscall.O_TRUNC, syscall.O_APPEND} {
			if _, _, e := visible.Open(ctx, flags); e != syscall.EROFS {
				t.Fatalf("visible flags %x in locked=%v: %v", flags, locked, e)
			}
		}
	}
}

func TestConcurrentGhostOperations(t *testing.T) {
	root := testRoot()
	dir := unlockedGhost(t, root)
	file := ghostFile(t, dir)
	fh, _, errno := file.Open(context.Background(), 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	dh, _, errno := dir.OpendirHandle(context.Background(), 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for range 500 {
				if i%2 == 0 {
					root.State.Lock()
					root.State.Unlock()
					continue
				}
				ctx := context.Background()
				check := func(e syscall.Errno) {
					if e != 0 && e != syscall.EACCES {
						t.Errorf("operation: %v", e)
					}
				}
				_, e := root.Lookup(ctx, ".troll", &fuse.EntryOut{})
				check(e)
				_, e = dir.Lookup(ctx, "hello.txt", &fuse.EntryOut{})
				check(e)
				check(file.Getattr(ctx, fh, &fuse.AttrOut{}))
				check(dir.Getattr(ctx, nil, &fuse.AttrOut{}))
				_, _, e = file.Open(ctx, 0)
				check(e)
				result, e := file.Read(ctx, fh, make([]byte, 32), 0)
				check(e)
				if result != nil {
					result.Done()
				}
				check(dh.(fs.FileSeekdirer).Seekdir(ctx, 0))
				_, e = dh.(fs.FileReaddirenter).Readdirent(ctx)
				check(e)
				assertRootListing(t, root)
			}
		})
	}
	wg.Wait()
	root.State.Lock()
	if _, e := file.Read(context.Background(), fh, make([]byte, 32), 0); e != syscall.EACCES {
		t.Fatal(e)
	}
}
