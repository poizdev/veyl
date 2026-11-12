//go:build linux

package ghostfs

import (
	"github.com/poizdev/veyl/internal/mountpoint"
	"golang.org/x/sys/unix"
	"syscall"
)

func (r *Root) ConfirmOriginalMount() error {
	id, err := mountpoint.VeylIdentity(r.parentPath)
	if err != nil {
		return errParentChanged
	}
	r.originalMount.Store(id)
	return nil
}

func (r *Root) checkOriginalParent() error {
	if expected := r.originalMount.Load(); expected != 0 {
		id, err := mountpoint.VeylIdentity(r.parentPath)
		if err != nil || id != expected {
			return errParentChanged
		}
	}
	t := r.parent.tree
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.root == nil || t.closing.Load() {
		return errParentChanged
	}
	raw, err := t.root.SyscallConn()
	if err != nil {
		return errParentChanged
	}
	valid := false
	err = raw.Control(func(rootfd uintptr) {
		fd := int(rootfd)
		var st syscall.Stat_t
		var sx unix.Statx_t
		if syscall.Fstat(fd, &st) != nil || st.Dev != r.parent.identity.Dev || st.Ino != r.parent.identity.Ino || st.Mode&0022 != 0 || unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &sx) != nil || sx.Mask&unix.STATX_MNT_ID == 0 || sx.Mnt_id != r.parentMount {
			return
		}
		child, err := unix.Openat2(fd, r.hidden(), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
		if err != nil {
			return
		}
		defer unix.Close(child)
		if syscall.Fstat(child, &st) != nil || st.Dev != r.originalTarget.Dev || st.Ino != r.originalTarget.Ino || st.Mode&0022 != 0 {
			return
		}
		// getdents on a separately opened description does not move any caller's
		// directory offset. Only dot entries may exist in the physical target.
		buf := make([]byte, 4096)
		for {
			n, err := unix.Getdents(child, buf)
			if err != nil {
				return
			}
			if n == 0 {
				break
			}
			_, _, names := syscall.ParseDirent(buf[:n], -1, nil)
			if len(names) != 0 {
				return
			}
		}
		valid = true
	})
	if err != nil || !valid {
		return errParentChanged
	}
	return nil
}
