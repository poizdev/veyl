//go:build linux

package ghostfs

import (
	"errors"
	"os"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"golang.org/x/sys/unix"
)

// An opened object belongs to one tree lifetime, never a pathname in a later
// session. Failed synchronization retains the descriptor for cleanup retry.
type backingFile struct {
	mu       sync.Mutex
	file     *os.File
	writable bool
	closeErr error
}

func (f *backingFile) use(fn func(int) syscall.Errno) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.file == nil {
		return syscall.EBADF
	}
	raw, err := f.file.SyscallConn()
	if err != nil {
		return fs.ToErrno(err)
	}
	result := syscall.EBADF
	if err := raw.Control(func(fd uintptr) { result = fn(int(fd)) }); err != nil {
		return fs.ToErrno(err)
	}
	return result
}
func (f *backingFile) close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.file == nil {
		return f.closeErr
	}
	if f.writable {
		info, err := f.file.Stat()
		if err != nil {
			return err
		}
		// An unlinked open object has no persistent name. gocryptfs can return
		// ENOENT for its fsync; it must still be releasable after an editor replaces it.
		if info.Sys().(*syscall.Stat_t).Nlink != 0 {
			if err := f.file.Sync(); err != nil {
				return err
			}
		}
	}
	f.closeErr = f.file.Close()
	f.file = nil
	return f.closeErr
}
func (t *backingTree) retain(file *os.File, writable bool) (*backingFile, syscall.Errno) {
	owned := &backingFile{file: file, writable: writable}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closing.Load() || t.life.Err() != nil {
		file.Close()
		return nil, syscall.EACCES
	}
	if t.files == nil {
		t.files = make(map[*backingFile]struct{})
	}
	t.files[owned] = struct{}{}
	return owned, 0
}
func (t *backingTree) release(file *backingFile) syscall.Errno {
	if file == nil {
		return 0
	}
	err := file.close()
	if err == nil {
		t.mu.Lock()
		delete(t.files, file)
		t.mu.Unlock()
	}
	return fs.ToErrno(err)
}
func (t *backingTree) closeFiles() error {
	t.mu.RLock()
	files := make([]*backingFile, 0, len(t.files))
	for f := range t.files {
		files = append(files, f)
	}
	t.mu.RUnlock()
	var result error
	for _, f := range files {
		if err := f.close(); err != nil {
			result = errors.Join(result, err)
		} else {
			t.mu.Lock()
			delete(t.files, f)
			t.mu.Unlock()
		}
	}
	return result
}
func dupFile(f *backingFile) (fd int, st syscall.Stat_t, e syscall.Errno) {
	fd = -1
	e = f.use(func(original int) syscall.Errno {
		var err error
		fd, err = unix.FcntlInt(uintptr(original), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return fs.ToErrno(err)
		}
		if err = syscall.Fstat(fd, &st); err != nil {
			unix.Close(fd)
			fd = -1
			return fs.ToErrno(err)
		}
		return 0
	})
	return
}
