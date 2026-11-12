//go:build linux

package ghostfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/poizdev/veyl/internal/mountpoint"
	"github.com/poizdev/veyl/internal/policy"
	"golang.org/x/sys/unix"
)

var errParentChanged = errors.New("Managed parent is unavailable, replaced, or has a protected-name conflict. Unmount Veyl and inspect the configured backing paths and any original empty target; no files were migrated.")

func (r *Root) hidden() string {
	if r.HiddenName != "" {
		return r.HiddenName
	}
	return policy.GhostName
}

// SetParent pins a separate backing directory. It never mounts, relocates or
// modifies the source. Configure before serving FUSE; CloseParent on shutdown.
func (r *Root) SetParent(path string) error {
	return r.setParent(path, false)
}

// SetOriginalParent pins the original parent BEFORE mounting over it. All
// subsequent backing access is descriptor-relative, including health checks.
// The physical target remains an empty, separately identified directory.
func (r *Root) SetOriginalParent(path string) error {
	if r.parent != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errParentChanged
	}
	if err := mountpoint.ValidatePublicTree(path); err != nil {
		return err
	}
	return r.setParent(path, true)
}

func (r *Root) setParent(path string, original bool) error {
	if r.parent != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errParentChanged
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return errParentChanged
	}
	f := os.NewFile(uintptr(fd), "veyl-managed-parent")
	var st syscall.Stat_t
	var sx unix.Statx_t
	if syscall.Fstat(fd, &st) != nil || unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &sx) != nil || sx.Mask&unix.STATX_MNT_ID == 0 || st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 {
		f.Close()
		return errParentChanged
	}
	tree := &backingTree{root: f, life: context.Background(), writable: true, publicLinks: original}
	pinned, e := tree.retain(f, false)
	if e != 0 {
		f.Close()
		return errParentChanged
	}
	r.parentPath, r.parentMount = path, sx.Mnt_id
	r.originalParent = original
	r.parent = &backingNode{tree: tree, path: ".", identity: st, pinned: pinned, anchor: &r.Inode}
	if original {
		var target unix.Stat_t
		if unix.Fstatat(fd, r.hidden(), &target, unix.AT_SYMLINK_NOFOLLOW) != nil || target.Mode&syscall.S_IFMT != syscall.S_IFDIR || target.Uid != uint32(os.Geteuid()) {
			_ = r.CloseParent()
			r.parent = nil
			return errParentChanged
		}
		r.originalTarget.Dev, r.originalTarget.Ino = target.Dev, target.Ino
	}
	tree.check = r.NamespaceError
	if err := r.NamespaceError(); err != nil {
		_ = r.CloseParent()
		r.parent = nil
		return err
	}
	return nil
}

// NamespaceError rejects redirection and reserved-name collisions rather than
// hiding or adopting physical data. Already-open sibling handles pin objects;
// new operations fail closed until the source is restored or Veyl is stopped.
func (r *Root) NamespaceError() error {
	if r.parent == nil {
		return nil
	}
	if r.originalParent {
		return r.checkOriginalParent()
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, r.parentPath, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return errParentChanged
	}
	defer unix.Close(fd)
	var st syscall.Stat_t
	var sx unix.Statx_t
	if syscall.Fstat(fd, &st) != nil || st.Dev != r.parent.identity.Dev || st.Ino != r.parent.identity.Ino || st.Mode&0022 != 0 || unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &sx) != nil || sx.Mask&unix.STATX_MNT_ID == 0 || sx.Mnt_id != r.parentMount {
		return errParentChanged
	}
	var child unix.Stat_t
	if unix.Fstatat(fd, r.hidden(), &child, unix.AT_SYMLINK_NOFOLLOW) != unix.ENOENT {
		return errParentChanged
	}
	return nil
}

func (r *Root) CloseParent() error {
	if r.parent == nil {
		return nil
	}
	return r.parent.tree.close()
}

func (r *Root) publicMutation(name string) syscall.Errno {
	if r.parent == nil {
		return syscall.EROFS
	}
	if r.NamespaceError() != nil {
		return syscall.ESTALE
	}
	if name == r.hidden() {
		return syscall.EPERM
	}
	return 0
}
func (r *Root) Create(ctx context.Context, name string, flags, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	if e := r.publicMutation(name); e != 0 {
		return nil, nil, 0, e
	}
	return r.parent.Create(ctx, name, flags, mode, out)
}
func (r *Root) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if e := r.publicMutation(name); e != 0 {
		return nil, e
	}
	return r.parent.Mkdir(ctx, name, mode, out)
}
func (r *Root) Unlink(ctx context.Context, name string) syscall.Errno {
	if e := r.publicMutation(name); e != 0 {
		return e
	}
	return r.parent.Unlink(ctx, name)
}
func (r *Root) Rmdir(ctx context.Context, name string) syscall.Errno {
	if e := r.publicMutation(name); e != 0 {
		return e
	}
	return r.parent.Rmdir(ctx, name)
}
func (r *Root) Rename(ctx context.Context, name string, parent fs.InodeEmbedder, next string, flags uint32) syscall.Errno {
	if e := r.publicMutation(name); e != 0 {
		return e
	}
	return r.parent.Rename(ctx, name, parent, next, flags)
}

// The namespace anchor itself is fixed. Metadata updates apply to its children.
func (r *Root) Setattr(ctx context.Context, fh fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if r.originalParent {
		if mode, ok := in.GetMode(); ok && mode&0022 != 0 {
			return syscall.EPERM
		}
		if uid, ok := in.GetUID(); ok && uid != uint32(os.Geteuid()) {
			return syscall.EPERM
		}
		return r.parent.Setattr(ctx, fh, in, out)
	}
	return syscall.EPERM
}
func (r *Root) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if e := r.publicMutation(name); e != 0 {
		return nil, e
	}
	return r.parent.Symlink(ctx, target, name, out)
}

func (r *Root) Link(context.Context, fs.InodeEmbedder, string, *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.EOPNOTSUPP
}
func (r *Root) Mknod(context.Context, string, uint32, uint32, *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.EOPNOTSUPP
}
