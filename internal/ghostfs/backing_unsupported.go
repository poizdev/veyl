//go:build linux

package ghostfs

import (
	"context"
	"golang.org/x/sys/unix"
	"os"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// Unsupported operations are explicit; no default callback may mutate cached
// children or bypass the session checks on a writable protected tree.
func (n *backingNode) unsupported(ctx context.Context) syscall.Errno {
	if !n.tree.writable {
		return syscall.EROFS
	}
	release, e := n.begin(ctx)
	if e != 0 {
		return e
	}
	defer release()
	return syscall.EOPNOTSUPP
}
func (n *backingNode) Tmpfile(ctx context.Context, mode, flags uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	return nil, nil, 0, n.unsupported(ctx)
}
func (n *backingNode) Mknod(ctx context.Context, name string, mode, dev uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, n.unsupported(ctx)
}
func (n *backingNode) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, n.unsupported(ctx)
}
func (n *backingNode) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if !n.tree.publicLinks {
		return nil, n.unsupported(ctx)
	}
	release, e := n.mutation(ctx)
	if e != 0 {
		return nil, e
	}
	defer release()
	n.tree.namespace.Lock()
	defer n.tree.namespace.Unlock()
	if !component(name) {
		return nil, syscall.EACCES
	}
	fd, _, e := n.pin()
	if e != 0 {
		return nil, e
	}
	defer unix.Close(fd)
	if e := n.current(ctx); e != 0 {
		return nil, e
	}
	if err := unix.Symlinkat(target, fd, name); err != nil {
		return nil, fs.ToErrno(err)
	}
	child, st, e := n.child(name)
	if e != 0 {
		return nil, e
	}
	pin, e := n.tree.retain(os.NewFile(uintptr(child), "veyl-public-link"), false)
	if e != 0 {
		return nil, e
	}
	node := &backingNode{tree: n.tree, path: n.childPath(name), identity: st, pinned: pin}
	node.attr(&st, &out.Attr)
	return n.newInode(ctx, node), 0
}

func (n *backingNode) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	if !n.tree.publicLinks {
		return nil, syscall.EOPNOTSUPP
	}
	release, e := n.begin(ctx)
	if e != 0 {
		return nil, e
	}
	defer release()
	fd, st, e := n.pin()
	if e != 0 {
		return nil, e
	}
	defer unix.Close(fd)
	if st.Mode&syscall.S_IFMT != syscall.S_IFLNK {
		return nil, syscall.EINVAL
	}
	buf := make([]byte, 4096)
	count, err := unix.Readlinkat(fd, "", buf)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	if count == len(buf) {
		return nil, syscall.ENAMETOOLONG
	}
	return buf[:count], 0
}
func (n *backingNode) Setxattr(ctx context.Context, name string, data []byte, flags uint32) syscall.Errno {
	return n.unsupported(ctx)
}
func (n *backingNode) Removexattr(ctx context.Context, name string) syscall.Errno {
	return n.unsupported(ctx)
}
func (n *backingNode) Allocate(ctx context.Context, fh fs.FileHandle, off, size uint64, mode uint32) syscall.Errno {
	return n.unsupported(ctx)
}
