//go:build linux

package ghostfs

import (
	"context"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/poizdev/veyl/internal/policy"
)

// Keep root enumeration separate from cached children, including after unlock.
// The real parent handle also gives directory fsync a backing descriptor.
func (r *Root) OpendirHandle(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if e := readOnlyOpen(flags); e != 0 {
		return nil, 0, e
	}
	h := &rootDirectoryHandle{root: r, entries: []fuse.DirEntry{{Name: policy.VisibleName, Mode: syscall.S_IFREG, Ino: visibleIno, Off: 1}}}
	if r.parent != nil {
		fh, _, e := r.parent.OpendirHandle(ctx, flags)
		if e != 0 {
			return nil, 0, e
		}
		h.parent = fh.(*backingDirHandle)
		h.entries = nil
		for _, entry := range h.parent.entries {
			if entry.Name == r.hidden() {
				continue
			}
			entry.Off = uint64(len(h.entries) + 1)
			h.entries = append(h.entries, entry)
		}
	}
	return h, 0, 0
}

type rootDirectoryHandle struct {
	root    *Root
	parent  *backingDirHandle
	mu      sync.Mutex
	entries []fuse.DirEntry
	off     uint64
}

func (h *rootDirectoryHandle) Readdirent(ctx context.Context) (*fuse.DirEntry, syscall.Errno) {
	if h.root.NamespaceError() != nil {
		return nil, syscall.ESTALE
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.off >= uint64(len(h.entries)) {
		return nil, 0
	}
	entry := h.entries[h.off]
	h.off++
	return &entry, 0
}
func (h *rootDirectoryHandle) Seekdir(ctx context.Context, off uint64) syscall.Errno {
	if h.root.NamespaceError() != nil {
		return syscall.ESTALE
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if off > uint64(len(h.entries)) {
		return syscall.EINVAL
	}
	h.off = off
	return 0
}
func (h *rootDirectoryHandle) Releasedir(ctx context.Context, flags uint32) {
	if h.parent != nil {
		h.parent.Releasedir(ctx, flags)
	}
	h.mu.Lock()
	h.entries = nil
	h.mu.Unlock()
}
func (h *rootDirectoryHandle) Fsyncdir(ctx context.Context, flags uint32) syscall.Errno {
	if h.parent == nil {
		return 0
	}
	return h.parent.Fsyncdir(ctx, flags)
}
