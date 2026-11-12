package ghostfs

import (
	"bytes"
	"testing"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// TestBridgeBufferedDirectoryEntryAfterLock characterizes an unresolved
// revocation limit in go-fuse v2.12.0: a dirent fetched before Lock can be
// replayed from the bridge's overflow buffer without calling our handle again.
// This is not a guarantee that directory reads are immediately revoked.
// A bridge upgrade or request-level authorization may intentionally change this
// result; review this characterization alongside the documented limitation.
func TestBridgeBufferedDirectoryEntryAfterLock(t *testing.T) {
	for _, plus := range []bool{false, true} {
		name := "READDIR"
		if plus {
			name = "READDIRPLUS"
		}
		t.Run(name, func(t *testing.T) {
			root := &Root{}
			raw := fs.NewNodeFS(root, Options())
			root.State.Unlock()
			var ghost fuse.EntryOut
			if status := raw.Lookup(nil, &fuse.InHeader{NodeId: 1}, ".troll", &ghost); status != fuse.OK {
				t.Fatalf("lookup: %v", status)
			}
			open := fuse.OpenIn{InHeader: fuse.InHeader{NodeId: ghost.NodeId}}
			var handle fuse.OpenOut
			if status := raw.OpenDir(nil, &open, &handle); status != fuse.OK {
				t.Fatalf("opendir: %v", status)
			}
			defer raw.ReleaseDir(&fuse.ReleaseIn{InHeader: open.InHeader, Fh: handle.Fh})
			read := raw.ReadDir
			if plus {
				read = raw.ReadDirPlus
			}
			input := fuse.ReadIn{InHeader: open.InHeader, Fh: handle.Fh}
			// One byte cannot hold a dirent. The bridge fetches hello.txt from
			// our authorized callback and retains it for the next request.
			tiny := fuse.NewDirEntryList(make([]byte, 1), 0)
			if status := read(nil, &input, tiny); status != fuse.OK || len(tiny.Bytes()) != 0 {
				t.Fatalf("undersized read: status %v, bytes %d", status, len(tiny.Bytes()))
			}
			root.State.Lock()
			buffered := fuse.NewDirEntryList(make([]byte, 4096), 0)
			if status := read(nil, &input, buffered); status != fuse.OK || !bytes.Contains(buffered.Bytes(), []byte("hello.txt")) {
				t.Fatalf("expected documented buffered-name replay: status %v, bytes %x", status, buffered.Bytes())
			}
			// The following request encounters the callback's deferred EACCES.
			input.Offset = buffered.Offset
			denied := fuse.NewDirEntryList(make([]byte, 4096), input.Offset)
			if status := read(nil, &input, denied); status != fuse.EACCES || len(denied.Bytes()) != 0 {
				t.Fatalf("next read: status %v, bytes %x", status, denied.Bytes())
			}
			// Rewinding reaches Seekdir, whose current-state check denies it.
			input.Offset = 0
			denied = fuse.NewDirEntryList(make([]byte, 4096), 0)
			if status := read(nil, &input, denied); status != fuse.EACCES || len(denied.Bytes()) != 0 {
				t.Fatalf("rewind: status %v, bytes %x", status, denied.Bytes())
			}
			if status := raw.OpenDir(nil, &open, &fuse.OpenOut{}); status != fuse.EACCES {
				t.Fatalf("fresh opendir after lock: %v", status)
			}
		})
	}
}

// Exercise dispatch through go-fuse using an already opened file handle, with
// no intervening path lookup. No FUSE device or kernel mount is needed.
func TestBridgeProtectedFileAfterRelock(t *testing.T) {
	root := &Root{}
	raw := fs.NewNodeFS(root, Options())
	root.State.Unlock()
	var ghost, hello fuse.EntryOut
	if status := raw.Lookup(nil, &fuse.InHeader{NodeId: 1}, ".troll", &ghost); status != fuse.OK {
		t.Fatal(status)
	}
	if status := raw.Lookup(nil, &fuse.InHeader{NodeId: ghost.NodeId}, "hello.txt", &hello); status != fuse.OK {
		t.Fatal(status)
	}
	open := fuse.OpenIn{InHeader: fuse.InHeader{NodeId: hello.NodeId}}
	var handle fuse.OpenOut
	if status := raw.Open(nil, &open, &handle); status != fuse.OK {
		t.Fatal(status)
	}
	defer raw.Release(nil, &fuse.ReleaseIn{InHeader: open.InHeader, Fh: handle.Fh})
	if handle.OpenFlags&fuse.FOPEN_DIRECT_IO == 0 {
		t.Fatal("protected open did not request direct I/O")
	}
	input := fuse.ReadIn{InHeader: open.InHeader, Fh: handle.Fh, Size: 4096}
	result, status := raw.Read(nil, &input, make([]byte, 4096))
	if status != fuse.OK {
		t.Fatal(status)
	}
	data, status := result.Bytes(make([]byte, 4096))
	result.Done()
	if status != fuse.OK || string(data) != HelloContent {
		t.Fatalf("read: %q, %v", data, status)
	}
	root.State.Lock()
	result, status = raw.Read(nil, &input, make([]byte, 4096))
	if result != nil {
		result.Done()
	}
	if status != fuse.EACCES {
		t.Fatalf("retained handle read after Lock: %v", status)
	}
	if status := raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: open.InHeader}, &fuse.AttrOut{}); status != fuse.EACCES {
		t.Fatalf("cached inode getattr: %v", status)
	}
	if status := raw.Open(nil, &open, &fuse.OpenOut{}); status != fuse.EACCES {
		t.Fatalf("cached inode open: %v", status)
	}
	root.State.Unlock()
	result, status = raw.Read(nil, &input, make([]byte, 4096))
	if result != nil {
		result.Done()
	}
	if status != fuse.EACCES {
		t.Fatalf("stale handle after Unlock: %v", status)
	}
	var nextGhost, nextHello fuse.EntryOut
	if status := raw.Lookup(nil, &fuse.InHeader{NodeId: 1}, ".troll", &nextGhost); status != fuse.OK {
		t.Fatal(status)
	}
	if status := raw.Lookup(nil, &fuse.InHeader{NodeId: nextGhost.NodeId}, "hello.txt", &nextHello); status != fuse.OK {
		t.Fatal(status)
	}
	if nextGhost.NodeId == ghost.NodeId || nextHello.NodeId == hello.NodeId {
		t.Fatal("new session reused old inode identity")
	}
	nextOpen := fuse.OpenIn{InHeader: fuse.InHeader{NodeId: nextHello.NodeId}}
	var nextHandle fuse.OpenOut
	if status := raw.Open(nil, &nextOpen, &nextHandle); status != fuse.OK {
		t.Fatal(status)
	}
	defer raw.Release(nil, &fuse.ReleaseIn{InHeader: nextOpen.InHeader, Fh: nextHandle.Fh})
	nextRead := fuse.ReadIn{InHeader: nextOpen.InHeader, Fh: nextHandle.Fh, Size: 4096}
	result, status = raw.Read(nil, &nextRead, make([]byte, 4096))
	if status != fuse.OK {
		t.Fatalf("fresh handle: %v", status)
	}
	defer result.Done()
	data, status = result.Bytes(make([]byte, 4096))
	if status != fuse.OK || string(data) != HelloContent {
		t.Fatalf("fresh read: %q, %v", data, status)
	}
	oldResult, oldStatus := raw.Read(nil, &input, make([]byte, 4096))
	if oldResult != nil {
		oldResult.Done()
	}
	if oldStatus != fuse.EACCES {
		t.Fatalf("fresh lookup revived old file handle: %v", oldStatus)
	}
}

func TestBridgeStaleDirectory(t *testing.T) {
	for _, plus := range []bool{false, true} {
		name := "READDIR"
		if plus {
			name = "READDIRPLUS"
		}
		t.Run(name, func(t *testing.T) {
			root := &Root{}
			raw := fs.NewNodeFS(root, Options())
			root.State.Unlock()
			var ghost fuse.EntryOut
			if status := raw.Lookup(nil, &fuse.InHeader{NodeId: 1}, ".troll", &ghost); status != fuse.OK {
				t.Fatal(status)
			}
			oldOpen := fuse.OpenIn{InHeader: fuse.InHeader{NodeId: ghost.NodeId}}
			var oldHandle fuse.OpenOut
			if status := raw.OpenDir(nil, &oldOpen, &oldHandle); status != fuse.OK {
				t.Fatal(status)
			}
			defer raw.ReleaseDir(&fuse.ReleaseIn{InHeader: oldOpen.InHeader, Fh: oldHandle.Fh})
			// No pre-lock read: this test must not confuse replayed buffers with a
			// callback accepting a stale handle. The replay characterization is separate.
			root.State.Lock()
			root.State.Unlock()
			read := raw.ReadDir
			if plus {
				read = raw.ReadDirPlus
			}
			input := fuse.ReadIn{InHeader: oldOpen.InHeader, Fh: oldHandle.Fh}
			out := fuse.NewDirEntryList(make([]byte, 4096), 0)
			if status := read(nil, &input, out); status != fuse.EACCES || len(out.Bytes()) != 0 {
				t.Fatalf("stale directory accepted: %v, %x", status, out.Bytes())
			}
			if status := raw.Lookup(nil, &oldOpen.InHeader, "hello.txt", &fuse.EntryOut{}); status != fuse.EACCES {
				t.Fatalf("old directory relative lookup: %v", status)
			}
			var fresh fuse.EntryOut
			if status := raw.Lookup(nil, &fuse.InHeader{NodeId: 1}, ".troll", &fresh); status != fuse.OK {
				t.Fatal(status)
			}
			if fresh.NodeId == ghost.NodeId || fresh.Generation == ghost.Generation {
				t.Fatal("fresh directory reused old session identity")
			}
			nextOpen := fuse.OpenIn{InHeader: fuse.InHeader{NodeId: fresh.NodeId}}
			var nextHandle fuse.OpenOut
			if status := raw.OpenDir(nil, &nextOpen, &nextHandle); status != fuse.OK {
				t.Fatal(status)
			}
			defer raw.ReleaseDir(&fuse.ReleaseIn{InHeader: nextOpen.InHeader, Fh: nextHandle.Fh})
			input = fuse.ReadIn{InHeader: nextOpen.InHeader, Fh: nextHandle.Fh}
			out = fuse.NewDirEntryList(make([]byte, 4096), 0)
			if status := read(nil, &input, out); status != fuse.OK || !bytes.Contains(out.Bytes(), []byte("hello.txt")) {
				t.Fatalf("fresh directory failed: %v, %x", status, out.Bytes())
			}
			input = fuse.ReadIn{InHeader: oldOpen.InHeader, Fh: oldHandle.Fh}
			out = fuse.NewDirEntryList(make([]byte, 4096), 0)
			if status := read(nil, &input, out); status != fuse.EACCES {
				t.Fatalf("fresh lookup revived old directory: %v", status)
			}
			if status := raw.Lookup(nil, &oldOpen.InHeader, "hello.txt", &fuse.EntryOut{}); status != fuse.EACCES {
				t.Fatalf("fresh lookup rebound old directory: %v", status)
			}
		})
	}
}
