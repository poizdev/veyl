package ghostfs

import (
	"context"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/poizdev/veyl/internal/policy"
)

const HelloContent = "Hello from the ghost directory.\n"
const helloName = "hello.txt"

type ghostDirectory struct {
	fs.Inode
	state   *policy.State
	session uint64
}

var (
	_ fs.NodeLookuper       = (*ghostDirectory)(nil)
	_ fs.NodeGetattrer      = (*ghostDirectory)(nil)
	_ fs.NodeAccesser       = (*ghostDirectory)(nil)
	_ fs.NodeOpendirHandler = (*ghostDirectory)(nil)
	_ fs.FileReaddirenter   = (*ghostDirectoryHandle)(nil)
	_ fs.FileSeekdirer      = (*ghostDirectoryHandle)(nil)
)

func (d *ghostDirectory) attr(out *fuse.Attr) {
	out.Mode = syscall.S_IFDIR | 0555
	out.Ino = ghostIno
	out.Nlink = 2
}

func (d *ghostDirectory) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	release, errno := beginOperation(d.state, d.session)
	if errno != 0 {
		return nil, errno
	}
	defer release()
	if name != helloName {
		return nil, syscall.ENOENT
	}
	file := &textFile{state: d.state, session: d.session, content: HelloContent, ino: helloIno}
	file.attr(&out.Attr)
	return d.NewInode(ctx, file, fs.StableAttr{Mode: syscall.S_IFREG, Ino: helloIno, Gen: d.session}), 0
}

func (d *ghostDirectory) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	release, errno := beginOperation(d.state, d.session)
	if errno != 0 {
		return errno
	}
	defer release()
	d.attr(&out.Attr)
	return 0
}

func (d *ghostDirectory) Access(ctx context.Context, mask uint32) syscall.Errno {
	release, errno := beginOperation(d.state, d.session)
	if errno != 0 {
		return errno
	}
	defer release()
	if mask&2 != 0 {
		return syscall.EROFS
	}
	return 0
}

func (d *ghostDirectory) OpendirHandle(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	release, errno := beginOperation(d.state, d.session)
	if errno != 0 {
		return nil, 0, errno
	}
	defer release()
	if errno := readOnlyOpen(flags); errno != 0 {
		return nil, 0, errno
	}
	return &ghostDirectoryHandle{dir: d}, 0, 0
}

// The handle retains its original inode/session. go-fuse serializes handle
// calls, but the mutex also makes direct concurrent use safe in unit tests.
type ghostDirectoryHandle struct {
	dir *ghostDirectory
	mu  sync.Mutex
	off uint64
}

func (h *ghostDirectoryHandle) Readdirent(ctx context.Context) (*fuse.DirEntry, syscall.Errno) {
	release, errno := beginOperation(h.dir.state, h.dir.session)
	if errno != 0 {
		return nil, errno
	}
	defer release()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.off != 0 {
		return nil, 0
	}
	h.off = 1
	return &fuse.DirEntry{Name: helloName, Mode: syscall.S_IFREG, Ino: helloIno, Off: h.off}, 0
}

func (h *ghostDirectoryHandle) Seekdir(ctx context.Context, off uint64) syscall.Errno {
	release, errno := beginOperation(h.dir.state, h.dir.session)
	if errno != 0 {
		return errno
	}
	defer release()
	h.mu.Lock()
	defer h.mu.Unlock()
	if off > 1 {
		return syscall.EINVAL
	}
	h.off = off
	return 0
}
