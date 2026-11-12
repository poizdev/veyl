//go:build linux

package ghostfs

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/poizdev/veyl/internal/policy"
	"golang.org/x/sys/unix"
)

// SessionBacking supplies only an adopted session's owned descriptor. Implementors
// must validate the policy instance as well as the epoch, and cancel life on loss.
// Descriptor acquisition must happen outside policy I/O leases. Providers may
// close the file during teardown; use SyscallConn.Control for raw fd access.
type SessionBacking interface {
	SessionRoot(context.Context, *policy.State, uint64) (*os.File, context.Context, error)
}

// A tree owns one pinned root, shared by all inodes in exactly one epoch.
// Cancellation closes it independently of inode-cache/Forget lifetimes.
type backingTree struct {
	mu          sync.RWMutex
	operations  sync.RWMutex
	namespace   sync.Mutex
	directoryMu sync.Mutex
	directories map[[2]uint64]*backingNode
	closing     atomic.Bool
	files       map[*backingFile]struct{}
	publicLinks bool
	writable    bool
	root        *os.File
	state       *policy.State
	epoch       uint64
	life        context.Context
	check       func() error
}

func (t *backingTree) close() error {
	t.closing.Store(true)
	t.operations.Lock()
	defer t.operations.Unlock()
	if err := t.closeFiles(); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.root != nil {
		err := t.root.Close()
		t.root = nil
		if err != nil && !errors.Is(err, os.ErrClosed) {
			return err
		}
	}
	return nil
}

// CloseBacking is called by storage after revocation/draining and before
// unmount. It also waits for asynchronous lifetime cleanup and retries errors.
func (r *Root) CloseBacking() error {
	r.backingMu.Lock()
	tree := r.tree
	r.backingMu.Unlock()
	if tree == nil {
		return nil
	}
	return tree.close()
}

func (t *backingTree) openPath(path string) (int, syscall.Stat_t, syscall.Errno) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var st syscall.Stat_t
	if t.root == nil || t.life.Err() != nil || (t.state != nil && !t.state.Valid(t.epoch)) {
		return -1, st, syscall.EACCES
	}
	fd := -1
	raw, err := t.root.SyscallConn()
	if err != nil {
		return -1, st, syscall.EACCES
	}
	var openErr error
	err = raw.Control(func(rootfd uintptr) {
		fd, openErr = unix.Openat2(int(rootfd), path, &unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
		})
	})
	if err == nil {
		err = openErr
	}
	if err != nil {
		return -1, st, fs.ToErrno(err)
	}
	if err := syscall.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, st, fs.ToErrno(err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG && st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		unix.Close(fd)
		return -1, st, syscall.EACCES
	}
	return fd, st, 0
}

func (r *Root) lookupBacking(ctx context.Context, epoch uint64, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	// Do not take a policy lease before SessionRoot: backend cleanup can hold its
	// gate while revoking/draining the old epoch. That lock order would deadlock.
	r.backingMu.Lock()
	tree := r.tree
	r.backingMu.Unlock()
	var candidate *backingTree
	if tree == nil || tree.epoch != epoch {
		fd, life, err := r.Backing.SessionRoot(ctx, &r.State, epoch)
		if err != nil || fd == nil || life == nil {
			if fd != nil {
				fd.Close()
			}
			return nil, syscall.EACCES
		}
		candidate = &backingTree{root: fd, state: &r.State, epoch: epoch, life: life, writable: r.Writable}
	}
	// Acquire admission AFTER the backend gate, but BEFORE publishing. A delayed
	// old SessionRoot result must never replace or close a newer session's tree.
	release, e := beginOperation(&r.State, epoch)
	if e != 0 {
		if candidate != nil {
			_ = candidate.close()
		}
		return nil, e
	}
	defer release()
	if candidate != nil {
		r.backingMu.Lock()
		if r.tree != nil && r.tree.epoch == epoch {
			tree = r.tree
			r.backingMu.Unlock()
			_ = candidate.close()
		} else {
			old := r.tree
			r.tree, tree = candidate, candidate
			r.backingMu.Unlock()
			if old != nil {
				_ = old.close()
			}
			context.AfterFunc(tree.life, func() { _ = tree.close() })
		}
	}
	fd, st, e := tree.openPath(".")
	if e != 0 {
		return nil, e
	}
	node := &backingNode{tree: tree, path: ".", identity: st}
	if tree.writable {
		node.pinned, e = tree.retain(os.NewFile(uintptr(fd), "veyl-directory"), false)
		if e != 0 {
			return nil, e
		}
	} else {
		unix.Close(fd)
	}
	node.attr(&st, &out.Attr)
	return backingInode(ctx, &r.Inode, node), 0
}
