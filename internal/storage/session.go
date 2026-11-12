//go:build linux

package storage

import (
	"context"
	"os"

	"github.com/poizdev/veyl/internal/policy"
	"golang.org/x/sys/unix"
)

// SessionRoot acquires a descriptor only for this backend's adopted session.
// Callers must not hold a policy I/O lease while acquiring the backend gate.
// The caller closes the descriptor on life cancellation. Backend also retains
// it and closes it before unmount. Use File.SyscallConn.Control to synchronize
// descriptor-relative syscalls with that close; never borrow File.Fd directly.
func (b *Backend) SessionRoot(ctx context.Context, state *policy.State, epoch uint64) (*os.File, context.Context, error) {
	if err := b.acquire(ctx); err != nil {
		return nil, nil, err
	}
	defer b.unlock()
	m := b.active
	if state != b.state || m == nil || m.owner == nil {
		return nil, nil, ErrStale
	}
	c := m.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.phase != 1 || c.failed || c.epoch != epoch || !state.Valid(epoch) || !c.owned.Load() || c.life.Err() != nil || b.lifetime.Err() != nil {
		return nil, nil, ErrStale
	}
	select {
	case <-m.process.Exited():
		return nil, nil, ErrMount
	default:
	}
	// Bind the descriptor to the verified mount ID, not merely its pathname.
	// A replaced/unmounted path must never become the backing tree.
	fd, err := unix.Open(m.view.Path, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, ErrUnsafe
	}
	var st unix.Statx_t
	err = unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &st)
	if err != nil || st.Mask&unix.STATX_MNT_ID == 0 || st.Mnt_id != m.id {
		unix.Close(fd)
		return nil, nil, ErrUnsafe
	}
	if ctx.Err() != nil || !state.Valid(epoch) || c.life.Err() != nil {
		unix.Close(fd)
		return nil, nil, ErrStale
	}
	root := os.NewFile(uintptr(fd), "veyl-session-root")
	m.roots = append(m.roots, root)
	return root, c.life, nil
}
