package ghostfs

import (
	"context"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/poizdev/veyl/internal/policy"
)

// A nil state marks the ordinary public file; protected files share root state.
type textFile struct {
	fs.Inode
	state   *policy.State
	session uint64
	content string
	ino     uint64
}

var (
	_ fs.NodeOpener    = (*textFile)(nil)
	_ fs.NodeReader    = (*textFile)(nil)
	_ fs.NodeGetattrer = (*textFile)(nil)
	_ fs.NodeAccesser  = (*textFile)(nil)
)

// beginOperation admits protected work until release. Public operations need
// no lease. Snapshot validation alone is not an operation admission boundary.
func beginOperation(state *policy.State, session uint64) (func(), syscall.Errno) {
	if state == nil {
		return func() {}, 0
	}
	release, ok := state.Begin(session)
	if !ok {
		return nil, syscall.EACCES
	}
	return release, 0
}

func readOnlyOpen(flags uint32) syscall.Errno {
	if flags&(syscall.O_ACCMODE|syscall.O_TRUNC|syscall.O_APPEND) != 0 {
		return syscall.EROFS
	}
	return 0
}

func (f *textFile) attr(out *fuse.Attr) {
	out.Mode = syscall.S_IFREG | 0444
	out.Ino = f.ino
	out.Nlink = 1
	out.Size = uint64(len(f.content))
}

func (f *textFile) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	release, errno := beginOperation(f.state, f.session)
	if errno != 0 {
		return errno
	}
	defer release()
	f.attr(&out.Attr)
	return 0
}

func (f *textFile) Access(ctx context.Context, mask uint32) syscall.Errno {
	release, errno := beginOperation(f.state, f.session)
	if errno != 0 {
		return errno
	}
	defer release()
	if mask&2 != 0 {
		return syscall.EROFS
	}
	if mask&1 != 0 {
		return syscall.EACCES
	}
	return 0
}

func (f *textFile) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	release, errno := beginOperation(f.state, f.session)
	if errno != 0 {
		return nil, 0, errno
	}
	defer release()
	if errno := readOnlyOpen(flags); errno != 0 {
		return nil, 0, errno
	}
	if f.state != nil {
		// Route each ordinary read, including existing-handle reads, to Read.
		// Do not opt into KEEP_CACHE or direct-I/O mmap capabilities.
		return &textHandle{file: f}, fuse.FOPEN_DIRECT_IO, 0
	}
	return nil, 0, 0
}

func (f *textFile) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	if f.state != nil {
		handle, ok := fh.(*textHandle)
		if !ok || handle == nil || handle.file != f {
			return nil, syscall.EACCES
		}
	}
	release, errno := beginOperation(f.state, f.session)
	if errno != 0 {
		return nil, errno
	}
	if off < 0 {
		release()
		return nil, syscall.EINVAL
	}
	var data []byte
	if off < int64(len(f.content)) {
		data = []byte(f.content)[off:]
		if len(data) > len(dest) {
			data = data[:len(dest)]
		}
	}
	result := fuse.ReadResultData(data)
	if f.state == nil || len(data) == 0 {
		// Linux go-fuse v2.12.0 skips Done on zero-payload replies. There is no
		// remaining plaintext work to drain for EOF or a zero-length destination.
		release()
		return result, 0
	}
	// Keep admission through go-fuse's result lifecycle. With the configured
	// Linux path Done follows the reply write attempt; other paths can finish
	// the result earlier, so this is not a universal delivery guarantee.
	return &leasedReadResult{ReadResult: result, release: release}, 0
}

// leasedReadResult holds admission through result completion. Done is idempotent;
// callers must finish every nonempty protected read and must not use the result
// after Done or call Lock synchronously before completing their result.
type leasedReadResult struct {
	fuse.ReadResult
	release func()
	once    sync.Once
}

func (r *leasedReadResult) Done() {
	r.once.Do(func() {
		defer r.release()
		r.ReadResult.Done()
	})
}

// The immutable inode carries the session; a handle keeps that inode alive and
// can never be rebound to a newer session by a later Open.
type textHandle struct{ file *textFile }
