//go:build linux

package ghostfs

import (
	"context"
	"os"
	"strconv"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

// The object is already pinned and classified without following user symlinks.
// NOFOLLOW must not reject our deliberate, owned procfs descriptor reference.
func reopen(fd, flags int) (*os.File, syscall.Errno) {
	next, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), (flags&^unix.O_NOFOLLOW)|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	return os.NewFile(uintptr(next), "veyl-open-file"), 0
}
func (n *backingNode) child(name string) (int, syscall.Stat_t, syscall.Errno) {
	if !n.tree.writable {
		return n.tree.openPath(n.childPath(name))
	}
	var st syscall.Stat_t
	if !component(name) {
		return -1, st, syscall.EACCES
	}
	parent, _, e := n.pin()
	if e != 0 {
		return -1, st, e
	}
	defer unix.Close(parent)
	fd, err := unix.Openat2(parent, name, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return -1, st, fs.ToErrno(err)
	}
	err = syscall.Fstat(fd, &st)
	if err != nil || (st.Mode&syscall.S_IFMT != syscall.S_IFREG && st.Mode&syscall.S_IFMT != syscall.S_IFDIR && !(n.tree.publicLinks && st.Mode&syscall.S_IFMT == syscall.S_IFLNK)) {
		unix.Close(fd)
		if err != nil {
			return -1, st, fs.ToErrno(err)
		}
		if n.tree.publicLinks {
			return -1, st, syscall.EOPNOTSUPP
		}
		return -1, st, syscall.EACCES
	}
	return fd, st, 0
}
func (n *backingNode) mutation(ctx context.Context) (func(), syscall.Errno) {
	if !n.tree.writable {
		return nil, syscall.EROFS
	}
	return n.begin(ctx)
}
func (n *backingNode) Write(ctx context.Context, fh fs.FileHandle, data []byte, off int64) (uint32, syscall.Errno) {
	release, e := n.mutation(ctx)
	if e != 0 {
		return 0, e
	}
	defer release()
	h, ok := fh.(*backingHandle)
	if !ok || h == nil || h.node != n || h.file == nil {
		return 0, syscall.EACCES
	}
	if off < 0 {
		return 0, syscall.EINVAL
	}
	count := 0
	e = h.file.use(func(fd int) syscall.Errno {
		if e := n.current(ctx); e != 0 {
			return e
		}
		var err error
		// O_APPEND is preserved on the backing descriptor; Linux performs the
		// append at the backing filesystem, rather than a userspace seek/write.
		count, err = unix.Pwrite(fd, data, off)
		return fs.ToErrno(err)
	})
	if count < 0 {
		count = 0
	}
	return uint32(count), e
}
func (n *backingNode) Create(ctx context.Context, name string, flags, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	release, e := n.mutation(ctx)
	if e != 0 {
		return nil, nil, 0, e
	}
	defer release()
	n.tree.namespace.Lock()
	defer n.tree.namespace.Unlock()
	if e := n.current(ctx); e != 0 {
		return nil, nil, 0, e
	}
	if !component(name) {
		return nil, nil, 0, syscall.EACCES
	}
	if flags&unix.O_TMPFILE != 0 || flags&unix.O_PATH != 0 || flags&syscall.O_ACCMODE == syscall.O_ACCMODE {
		return nil, nil, 0, syscall.EOPNOTSUPP
	}
	parent, _, e := n.pin()
	if e != 0 {
		return nil, nil, 0, e
	}
	defer unix.Close(parent)
	fd, err := unix.Openat2(parent, name, &unix.OpenHow{Flags: uint64(flags) | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK, Mode: uint64(mode & 0777), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	created := err == nil
	if err == unix.EEXIST && flags&unix.O_EXCL == 0 {
		pinned, _, e := n.child(name)
		if e != 0 {
			return nil, nil, 0, e
		}
		f, e := reopen(pinned, int(flags&^(unix.O_CREAT|unix.O_EXCL)))
		unix.Close(pinned)
		if e != 0 {
			return nil, nil, 0, e
		}
		owned, e := n.tree.retain(f, flags&syscall.O_ACCMODE != syscall.O_RDONLY)
		if e != 0 {
			return nil, nil, 0, e
		}
		node, inode, e := n.nodeFromFile(ctx, name, owned, out)
		if e != 0 {
			n.tree.release(owned)
			return nil, nil, 0, e
		}
		return inode, &backingHandle{node: node, file: owned, flags: flags}, fuse.FOPEN_DIRECT_IO, 0
	}
	if err != nil {
		return nil, nil, 0, fs.ToErrno(err)
	}
	f := os.NewFile(uintptr(fd), "veyl-created-file")
	// FUSE supplies the caller-masked mode. The supervisor's private umask must
	// not silently change application-requested file permissions.
	if created {
		if err := unix.Fchmod(fd, mode&0777); err != nil {
			f.Close()
			return nil, nil, 0, fs.ToErrno(err)
		}
	}
	owned, e := n.tree.retain(f, flags&syscall.O_ACCMODE != syscall.O_RDONLY)
	if e != 0 {
		return nil, nil, 0, e
	}
	node, inode, e := n.nodeFromFile(ctx, name, owned, out)
	if e != 0 {
		n.tree.release(owned)
		return nil, nil, 0, e
	}
	return inode, &backingHandle{node: node, file: owned, flags: flags}, fuse.FOPEN_DIRECT_IO, 0
}
func (n *backingNode) nodeFromFile(ctx context.Context, name string, opened *backingFile, out *fuse.EntryOut) (*backingNode, *fs.Inode, syscall.Errno) {
	fd := -1
	var st syscall.Stat_t
	e := opened.use(func(original int) syscall.Errno {
		var err error
		fd, err = unix.Open("/proc/self/fd/"+strconv.Itoa(original), unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			return fs.ToErrno(err)
		}
		return 0
	})
	if e != 0 {
		return nil, nil, e
	}
	if err := syscall.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, nil, fs.ToErrno(err)
	}
	owned, e := n.tree.retain(os.NewFile(uintptr(fd), "veyl-pinned-created-object"), false)
	if e != 0 {
		return nil, nil, e
	}
	node := &backingNode{tree: n.tree, path: n.childPath(name), identity: st, pinned: owned}
	node.attr(&st, &out.Attr)
	return node, n.newInode(ctx, node), 0
}

func (n *backingNode) newWritableChild(ctx context.Context, name string, out *fuse.EntryOut) (*backingNode, *fs.Inode, syscall.Errno) {
	fd, st, e := n.child(name)
	if e != 0 {
		return nil, nil, e
	}
	owned, e := n.tree.retain(os.NewFile(uintptr(fd), "veyl-created-node"), false)
	if e != 0 {
		return nil, nil, e
	}
	node := &backingNode{tree: n.tree, path: n.childPath(name), identity: st, pinned: owned}
	node.attr(&st, &out.Attr)
	return node, n.newInode(ctx, node), 0
}
func (n *backingNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	release, e := n.mutation(ctx)
	if e != 0 {
		return nil, e
	}
	defer release()
	n.tree.namespace.Lock()
	defer n.tree.namespace.Unlock()
	if e := n.current(ctx); e != 0 {
		return nil, e
	}
	if !component(name) {
		return nil, syscall.EACCES
	}
	parent, _, e := n.pin()
	if e != 0 {
		return nil, e
	}
	defer unix.Close(parent)
	if err := unix.Mkdirat(parent, name, mode&01777); err != nil {
		return nil, fs.ToErrno(err)
	}
	fd, _, e := n.child(name)
	if e != 0 {
		return nil, e
	}
	err := unix.Chmod("/proc/self/fd/"+strconv.Itoa(fd), mode&01777)
	unix.Close(fd)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	_, inode, e := n.newWritableChild(ctx, name, out)
	return inode, e
}
func (n *backingNode) remove(ctx context.Context, name string, directory bool) syscall.Errno {
	release, e := n.mutation(ctx)
	if e != 0 {
		return e
	}
	defer release()
	n.tree.namespace.Lock()
	defer n.tree.namespace.Unlock()
	if e := n.current(ctx); e != 0 {
		return e
	}
	if !component(name) {
		return syscall.EACCES
	}
	parent, _, e := n.pin()
	if e != 0 {
		return e
	}
	defer unix.Close(parent)
	child, st, e := n.child(name)
	if e != 0 {
		return e
	}
	unix.Close(child)
	flags := 0
	if directory {
		if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
			return syscall.ENOTDIR
		}
		flags = unix.AT_REMOVEDIR
	} else if st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
		return syscall.EISDIR
	}
	return fs.ToErrno(unix.Unlinkat(parent, name, flags))
}
func (n *backingNode) Unlink(ctx context.Context, name string) syscall.Errno {
	return n.remove(ctx, name, false)
}
func (n *backingNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	return n.remove(ctx, name, true)
}
func (n *backingNode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	release, e := n.mutation(ctx)
	if e != 0 {
		return e
	}
	defer release()
	n.tree.namespace.Lock()
	defer n.tree.namespace.Unlock()
	if e := n.current(ctx); e != 0 {
		return e
	}
	if root, ok := newParent.(*Root); ok {
		if root.parent == nil || root.parent.tree != n.tree {
			return syscall.EXDEV
		}
		if newName == root.hidden() {
			return syscall.EPERM
		}
		newParent = root.parent
	}
	other, ok := newParent.(*backingNode)
	if !ok || other.tree != n.tree {
		return syscall.EXDEV
	}
	if !component(name) || !component(newName) {
		return syscall.EACCES
	}
	if flags & ^uint32(unix.RENAME_NOREPLACE|unix.RENAME_EXCHANGE) != 0 {
		return syscall.EOPNOTSUPP
	}
	src, _, e := n.pin()
	if e != 0 {
		return e
	}
	defer unix.Close(src)
	dst, _, e := other.pin()
	if e != 0 {
		return e
	}
	defer unix.Close(dst)
	child, _, e := n.child(name)
	if e != 0 {
		return e
	}
	unix.Close(child)
	if target, _, e := other.child(newName); e == 0 {
		unix.Close(target)
	} else if e != syscall.ENOENT {
		return e
	}
	return fs.ToErrno(unix.Renameat2(src, name, dst, newName, uint(flags)))
}
func (n *backingNode) Flush(ctx context.Context, fh fs.FileHandle) syscall.Errno {
	return n.Fsync(ctx, fh, 0)
}
func (n *backingNode) Fsync(ctx context.Context, fh fs.FileHandle, flags uint32) syscall.Errno {
	release, e := n.begin(ctx)
	if e != 0 {
		return e
	}
	defer release()
	h, ok := fh.(*backingHandle)
	if !ok || h == nil || h.node != n {
		return syscall.EACCES
	}
	if h.file == nil {
		return 0
	}
	return h.file.use(func(fd int) syscall.Errno {
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			return fs.ToErrno(err)
		}
		if st.Nlink == 0 {
			return 0
		}
		if flags&1 != 0 {
			return fs.ToErrno(unix.Fdatasync(fd))
		}
		return fs.ToErrno(unix.Fsync(fd))
	})
}
func (n *backingNode) Release(ctx context.Context, fh fs.FileHandle) syscall.Errno {
	h, ok := fh.(*backingHandle)
	if !ok || h == nil || h.node != n {
		return syscall.EACCES
	}
	// Release is resource retirement, never authorization, and must work after lock.
	return n.tree.release(h.file)
}
func (n *backingNode) Setattr(ctx context.Context, fh fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	release, e := n.mutation(ctx)
	if e != 0 {
		return e
	}
	defer release()
	fd, identity, e := n.pin()
	if e != 0 {
		return e
	}
	defer unix.Close(fd)
	// Never follow a public symlink into the physical backing namespace for
	// metadata changes. The kernel resolves ordinary followed operations in
	// the visible namespace; direct symlink-object metadata is unsupported.
	if identity.Mode&syscall.S_IFMT == syscall.S_IFLNK {
		return syscall.EOPNOTSUPP
	}
	path := "/proc/self/fd/" + strconv.Itoa(fd)
	if mode, ok := in.GetMode(); ok {
		if mode&06000 != 0 {
			return syscall.EPERM
		}
		if err := unix.Chmod(path, mode&01777); err != nil {
			return fs.ToErrno(err)
		}
	}
	uid, uok := in.GetUID()
	gid, gok := in.GetGID()
	if uok || gok {
		u, g := -1, -1
		if uok {
			u = int(uid)
		}
		if gok {
			g = int(gid)
		}
		if err := unix.Fchownat(fd, "", u, g, unix.AT_EMPTY_PATH); err != nil {
			return fs.ToErrno(err)
		}
	}
	if size, ok := in.GetSize(); ok {
		if size > uint64(^uint64(0)>>1) {
			return syscall.EINVAL
		}
		h, valid := fh.(*backingHandle)
		if valid && h != nil && h.node == n && h.file != nil {
			if e := h.file.use(func(fd int) syscall.Errno {
				if e := n.current(ctx); e != 0 {
					return e
				}
				return fs.ToErrno(unix.Ftruncate(fd, int64(size)))
			}); e != 0 {
				return e
			}
		} else {
			f, e := reopen(fd, unix.O_WRONLY)
			if e != 0 {
				return e
			}
			err := f.Truncate(int64(size))
			f.Close()
			if err != nil {
				return fs.ToErrno(err)
			}
		}
	}
	times := []unix.Timespec{{Nsec: unix.UTIME_OMIT}, {Nsec: unix.UTIME_OMIT}}
	at, aok := in.GetATime()
	mt, mok := in.GetMTime()
	if aok {
		times[0] = unix.NsecToTimespec(at.UnixNano())
	}
	if mok {
		times[1] = unix.NsecToTimespec(mt.UnixNano())
	}
	if aok || mok {
		if err := unix.UtimesNanoAt(unix.AT_FDCWD, path, times, 0); err != nil {
			return fs.ToErrno(err)
		}
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fs.ToErrno(err)
	}
	n.attr(&st, &out.Attr)
	return 0
}
