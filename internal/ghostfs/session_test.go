package ghostfs

import (
	"context"
	"sync"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func TestSessionBoundHandles(t *testing.T) {
	ctx := context.Background()
	root := testRoot()
	dir := unlockedGhost(t, root)
	file := ghostFile(t, dir)
	fh, _, errno := file.Open(ctx, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	dh, _, errno := dir.OpendirHandle(ctx, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	for range 3 {
		root.State.Unlock()
	}
	readContent(t, file, fh, HelloContent)
	if _, e := dh.(fs.FileReaddirenter).Readdirent(ctx); e != 0 {
		t.Fatal(e)
	}
	for range 3 {
		root.State.Lock()
		root.State.Unlock()
		for name, operation := range map[string]func() syscall.Errno{
			"file read": func() syscall.Errno {
				r, e := file.Read(ctx, fh, make([]byte, 32), 0)
				if r != nil {
					r.Done()
				}
				return e
			},
			"file getattr":          func() syscall.Errno { return file.Getattr(ctx, fh, &fuse.AttrOut{}) },
			"cached file open":      func() syscall.Errno { _, _, e := file.Open(ctx, 0); return e },
			"cached file access":    func() syscall.Errno { return file.Access(ctx, 4) },
			"directory read":        func() syscall.Errno { _, e := dh.(fs.FileReaddirenter).Readdirent(ctx); return e },
			"directory seek":        func() syscall.Errno { return dh.(fs.FileSeekdirer).Seekdir(ctx, 0) },
			"directory getattr":     func() syscall.Errno { return dir.Getattr(ctx, dh, &fuse.AttrOut{}) },
			"directory lookup":      func() syscall.Errno { _, e := dir.Lookup(ctx, "hello.txt", &fuse.EntryOut{}); return e },
			"cached directory open": func() syscall.Errno { _, _, e := dir.OpendirHandle(ctx, 0); return e },
		} {
			t.Run(name, func(t *testing.T) {
				if e := operation(); e != syscall.EACCES {
					t.Fatalf("revoked session accepted: %v", e)
				}
			})
		}
		nextDir := unlockedGhost(t, root)
		nextFile := ghostFile(t, nextDir)
		nextHandle, flags, e := nextFile.Open(ctx, 0)
		if e != 0 || flags&fuse.FOPEN_DIRECT_IO == 0 {
			t.Fatalf("fresh file open: %x, %v", flags, e)
		}
		readContent(t, nextFile, nextHandle, HelloContent)
		nextDH, _, e := nextDir.OpendirHandle(ctx, 0)
		if e != 0 {
			t.Fatal(e)
		}
		entry, e := nextDH.(fs.FileReaddirenter).Readdirent(ctx)
		if e != 0 || entry == nil || entry.Name != "hello.txt" {
			t.Fatalf("fresh dir: %v, %v", entry, e)
		}
		assertRootListing(t, root)
	}
}

func TestStaleHandlesDuringConcurrentSessions(t *testing.T) {
	root := testRoot()
	dir := unlockedGhost(t, root)
	file := ghostFile(t, dir)
	ctx := context.Background()
	fh, _, e := file.Open(ctx, 0)
	if e != 0 {
		t.Fatal(e)
	}
	dh, _, e := dir.OpendirHandle(ctx, 0)
	if e != 0 {
		t.Fatal(e)
	}
	root.State.Lock()
	root.State.Unlock()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for range 500 {
				if i%2 == 0 {
					root.State.Lock()
					root.State.Unlock()
					continue
				}
				result, e := file.Read(ctx, fh, make([]byte, 32), 0)
				if result != nil {
					result.Done()
				}
				if e != syscall.EACCES {
					t.Errorf("stale file read: %v", e)
					return
				}
				if e := dh.(fs.FileSeekdirer).Seekdir(ctx, 0); e != syscall.EACCES {
					t.Errorf("stale seek: %v", e)
					return
				}
				if _, e := dh.(fs.FileReaddirenter).Readdirent(ctx); e != syscall.EACCES {
					t.Errorf("stale directory read: %v", e)
					return
				}
			}
		})
	}
	wg.Wait()
}

func TestProtectedReadRequiresItsOpenHandle(t *testing.T) {
	root := testRoot()
	file := ghostFile(t, unlockedGhost(t, root))
	for _, fh := range []fs.FileHandle{nil, &struct{}{}} {
		result, e := file.Read(context.Background(), fh, make([]byte, 32), 0)
		if result != nil {
			result.Done()
		}
		if e != syscall.EACCES {
			t.Fatalf("missing/invalid handle accepted: %v", e)
		}
	}
}
