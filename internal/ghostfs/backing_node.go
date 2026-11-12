//go:build linux

package ghostfs

import (
	"context"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

type backingNode struct {
	fs.Inode
	tree     *backingTree
	path     string
	identity syscall.Stat_t
	pinned   *backingFile
	anchor   *fs.Inode
}

// Directories need stable virtual identities for getcwd and shell operation.
// Keep a single pinned directory node per physical object for this tree lifetime.
// Files retain separate virtual aliases, avoiding path-based hardlink merging.
func backingInode(ctx context.Context, parent *fs.Inode, node *backingNode) *fs.Inode {
	if node.tree.writable && node.identity.Mode&syscall.S_IFMT == syscall.S_IFDIR {
		t := node.tree
		t.directoryMu.Lock()
		defer t.directoryMu.Unlock()
		if t.directories == nil {
			t.directories = make(map[[2]uint64]*backingNode)
		}
		key := [2]uint64{uint64(node.identity.Dev), node.identity.Ino}
		if existing := t.directories[key]; existing != nil {
			_ = t.release(node.pinned)
			node = existing
		} else {
			t.directories[key] = node
		}
	}
	return parent.NewInode(ctx, node, node.stable())
}
func (n *backingNode) newInode(ctx context.Context, child *backingNode) *fs.Inode {
	parent := &n.Inode
	if n.anchor != nil {
		parent = n.anchor
	}
	return backingInode(ctx, parent, child)
}
func (n *backingNode) stable() fs.StableAttr {
	// Let go-fuse allocate virtual identities. Sharing the backing inode number
	// would merge hardlink aliases while retaining only one alias's stored path.
	return fs.StableAttr{Mode: n.identity.Mode & syscall.S_IFMT, Gen: n.tree.epoch}
}
func (n *backingNode) attr(st *syscall.Stat_t, out *fuse.Attr) {
	out.FromStat(st)
	out.Ino = 0 // go-fuse supplies the virtual identity, not the backing inode ID
	if n.tree.writable {
		out.Mode &= syscall.S_IFMT | 01777
	} else {
		out.Mode &= syscall.S_IFMT | 0555
	} // strip write, set-id and sticky bits
}

// Recheck after serializing on a descriptor or namespace mutation. An operation
// admitted before lock may finish; a queued mutation must not start after revocation.
func (n *backingNode) current(ctx context.Context) syscall.Errno {
	if ctx != nil && ctx.Err() != nil {
		return syscall.EINTR
	}
	if n.tree.life.Err() != nil || n.tree.closing.Load() || (n.tree.state != nil && !n.tree.state.Valid(n.tree.epoch)) {
		return syscall.EACCES
	}
	return 0
}

func (n *backingNode) begin(ctx context.Context) (func(), syscall.Errno) {
	if ctx != nil && ctx.Err() != nil {
		return nil, syscall.EINTR
	}
	if n.tree.life.Err() != nil || n.tree.closing.Load() {
		return nil, syscall.EACCES
	}
	if n.tree.check != nil && n.tree.check() != nil {
		return nil, syscall.ESTALE
	}
	release, e := beginOperation(n.tree.state, n.tree.epoch)
	if e != 0 {
		return nil, e
	}
	n.tree.operations.RLock()
	if n.tree.life.Err() != nil || n.tree.closing.Load() || (ctx != nil && ctx.Err() != nil) {
		n.tree.operations.RUnlock()
		release()
		return nil, syscall.EACCES
	}
	return func() { n.tree.operations.RUnlock(); release() }, 0
}
func (n *backingNode) OnForget() {
	if n.pinned == nil {
		return
	}
	if n.identity.Mode&syscall.S_IFMT == syscall.S_IFDIR {
		// A linked cached directory may be revived by LOOKUP concurrently with
		// Forget. Keep its pin/identity. An unlinked directory cannot be looked up
		// anew and must not accumulate descriptors after mkdir/rmdir churn.
		n.tree.directoryMu.Lock()
		defer n.tree.directoryMu.Unlock()
		fd, st, e := dupFile(n.pinned)
		if e == 0 {
			unix.Close(fd)
			if st.Nlink != 0 {
				return
			}
		} else if e != syscall.ENOENT {
			return
		}
		key := [2]uint64{uint64(n.identity.Dev), n.identity.Ino}
		if n.tree.directories[key] == n {
			delete(n.tree.directories, key)
		}
	}
	_ = n.tree.release(n.pinned)
}
func (n *backingNode) pin() (int, syscall.Stat_t, syscall.Errno) {
	if n.pinned != nil {
		return dupFile(n.pinned)
	}
	fd, st, e := n.tree.openPath(n.path)
	if e != 0 {
		return -1, st, e
	}
	if st.Dev != n.identity.Dev || st.Ino != n.identity.Ino || st.Mode&syscall.S_IFMT != n.identity.Mode&syscall.S_IFMT {
		unix.Close(fd)
		return -1, st, syscall.ESTALE
	}
	return fd, st, 0
}

// Reopen a pinned, already classified regular file/directory. This deliberate
// /proc/self/fd use follows our owned descriptor, never a user-controlled link.
// It prevents a replacement FIFO/device from being opened between stat and open.
func readable(fd int) (*os.File, syscall.Errno) {
	next, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	return os.NewFile(uintptr(next), "veyl-backing"), 0
}
func component(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\x00")
}
func (n *backingNode) childPath(name string) string {
	if n.path == "." {
		return name
	}
	return n.path + "/" + name
}
func (n *backingNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	release, e := n.begin(ctx)
	if e != 0 {
		return nil, e
	}
	defer release()
	if !component(name) {
		return nil, syscall.EACCES
	}
	parent, st, e := n.pin()
	if e != 0 {
		return nil, e
	}
	unix.Close(parent)
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return nil, syscall.ENOTDIR
	}
	path := n.childPath(name)
	fd, st, e := n.child(name)
	if e != 0 {
		return nil, e
	}
	node := &backingNode{tree: n.tree, path: path, identity: st}
	if n.tree.writable {
		node.pinned, e = n.tree.retain(os.NewFile(uintptr(fd), "veyl-node"), false)
		if e != 0 {
			return nil, e
		}
	} else {
		unix.Close(fd)
	}
	node.attr(&st, &out.Attr)
	return n.newInode(ctx, node), 0
}
func (n *backingNode) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	release, e := n.begin(ctx)
	if e != 0 {
		return e
	}
	defer release()
	fd, st, e := n.pin()
	if e != 0 {
		return e
	}
	defer unix.Close(fd)
	n.attr(&st, &out.Attr)
	return 0
}
func (n *backingNode) Access(ctx context.Context, mask uint32) syscall.Errno {
	release, e := n.begin(ctx)
	if e != 0 {
		return e
	}
	defer release()
	if mask&2 != 0 && !n.tree.writable {
		return syscall.EROFS
	}
	fd, _, e := n.pin()
	if e != 0 {
		return e
	}
	defer unix.Close(fd)
	return fs.ToErrno(unix.Faccessat(fd, "", mask, unix.AT_EMPTY_PATH|unix.AT_EACCESS))
}

type backingHandle struct {
	node  *backingNode
	file  *backingFile
	flags uint32
}

func (n *backingNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	release, e := n.begin(ctx)
	if e != 0 {
		return nil, 0, e
	}
	defer release()
	if !n.tree.writable {
		if e := readOnlyOpen(flags); e != 0 {
			return nil, 0, e
		}
	}
	if flags&(syscall.O_CREAT|unix.O_TMPFILE) != 0 {
		return nil, 0, syscall.EROFS
	}
	fd, st, e := n.pin()
	if e != 0 {
		return nil, 0, e
	}
	defer unix.Close(fd)
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, 0, syscall.EISDIR
	}
	if n.tree.writable {
		if flags&syscall.O_ACCMODE == syscall.O_ACCMODE || flags&unix.O_PATH != 0 {
			return nil, 0, syscall.EINVAL
		}
		f, e := reopen(fd, int(flags))
		if e != 0 {
			return nil, 0, e
		}
		owned, e := n.tree.retain(f, flags&syscall.O_ACCMODE != syscall.O_RDONLY)
		if e != 0 {
			return nil, 0, e
		}
		return &backingHandle{node: n, file: owned, flags: flags}, fuse.FOPEN_DIRECT_IO, 0
	}
	f, e := readable(fd)
	if e != 0 {
		return nil, 0, e
	}
	f.Close()
	return &backingHandle{node: n}, fuse.FOPEN_DIRECT_IO, 0
}
func (n *backingNode) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	h, ok := fh.(*backingHandle)
	if !ok || h == nil || h.node != n {
		return nil, syscall.EACCES
	}
	release, e := n.begin(ctx)
	if e != 0 {
		return nil, e
	}
	if off < 0 {
		release()
		return nil, syscall.EINVAL
	}
	if h.file != nil {
		count := 0
		e := h.file.use(func(fd int) syscall.Errno {
			var err error
			count, err = unix.Pread(fd, dest, off)
			return fs.ToErrno(err)
		})
		if e != 0 {
			release()
			return nil, e
		}
		result := fuse.ReadResultData(dest[:count])
		if count == 0 {
			release()
			return result, 0
		}
		return &leasedReadResult{ReadResult: result, release: release}, 0
	}
	fd, _, e := n.pin()
	if e != 0 {
		release()
		return nil, e
	}
	f, e := readable(fd)
	unix.Close(fd)
	if e != 0 {
		release()
		return nil, e
	}
	count, err := f.ReadAt(dest, off)
	f.Close()
	if err != nil && err != io.EOF {
		release()
		return nil, fs.ToErrno(err)
	}
	result := fuse.ReadResultData(dest[:count])
	if count == 0 {
		release()
		return result, 0
	}
	return &leasedReadResult{ReadResult: result, release: release}, 0
}

type backingDirHandle struct {
	node    *backingNode
	file    *backingFile
	mu      sync.Mutex
	entries []fuse.DirEntry
	off     uint64
}

func (n *backingNode) OpendirHandle(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	release, e := n.begin(ctx)
	if e != 0 {
		return nil, 0, e
	}
	defer release()
	if e := readOnlyOpen(flags); e != 0 {
		return nil, 0, e
	}
	fd, st, e := n.pin()
	if e != 0 {
		return nil, 0, e
	}
	defer unix.Close(fd)
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return nil, 0, syscall.ENOTDIR
	}
	f, e := readable(fd)
	if e != 0 {
		return nil, 0, e
	}
	entries, err := f.ReadDir(-1)
	if err != nil {
		f.Close()
		return nil, 0, fs.ToErrno(err)
	}
	h := &backingDirHandle{node: n}
	if n.tree.writable {
		h.file, e = n.tree.retain(f, false)
		if e != 0 {
			return nil, 0, e
		}
	} else {
		f.Close()
	}
	for _, entry := range entries {
		if !component(entry.Name()) {
			continue
		}
		fd, st, e := n.child(entry.Name())
		if e != 0 {
			if n.tree.publicLinks && e == syscall.EOPNOTSUPP {
				h.Releasedir(ctx, 0)
				return nil, 0, e
			}
			continue
		} // symlinks, special files and disappearing entries omitted
		unix.Close(fd)
		h.entries = append(h.entries, fuse.DirEntry{Name: entry.Name(), Mode: st.Mode & syscall.S_IFMT, Off: uint64(len(h.entries) + 1)})
	}
	return h, 0, 0
}
func (h *backingDirHandle) Readdirent(ctx context.Context) (*fuse.DirEntry, syscall.Errno) {
	release, e := h.node.begin(ctx)
	if e != 0 {
		return nil, e
	}
	defer release()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.off >= uint64(len(h.entries)) {
		return nil, 0
	}
	entry := h.entries[h.off]
	h.off++
	return &entry, 0
}
func (h *backingDirHandle) Seekdir(ctx context.Context, off uint64) syscall.Errno {
	release, e := h.node.begin(ctx)
	if e != 0 {
		return e
	}
	defer release()
	h.mu.Lock()
	defer h.mu.Unlock()
	if off > uint64(len(h.entries)) {
		return syscall.EINVAL
	}
	h.off = off
	return 0
}
func (h *backingDirHandle) Releasedir(ctx context.Context, flags uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries = nil
	_ = h.node.tree.release(h.file)
}

func (h *backingDirHandle) Fsyncdir(ctx context.Context, flags uint32) syscall.Errno {
	release, e := h.node.begin(ctx)
	if e != 0 {
		return e
	}
	defer release()
	if h.file == nil {
		return 0
	}
	return h.file.use(func(fd int) syscall.Errno { return fs.ToErrno(unix.Fsync(fd)) })
}
