//go:build linux

package app

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/poizdev/veyl/internal/storage"
	"golang.org/x/sys/unix"
)

var errAlreadyRunning = errors.New("Veyl is already running or starting. Use veyl status with this configuration.")
var errCleanupPending = errors.New("Cleanup is incomplete. Keep the mount process running and retry veyl lock or veyl unmount.")
var errRuntime = errors.New("Cannot use the private runtime directory. Check ownership, mode 0700, and that no unrelated files occupy its control paths.")

type runtimeOwner struct {
	path       string
	lock       *os.File
	listener   *net.UnixListener
	socketInfo os.FileInfo
}

func claimRuntime(c Config) (owner *runtimeOwner, err error) {
	if storage.ValidateDirectory(c.RuntimeDir, true) != nil {
		return nil, errRuntime
	}
	fd, e := unix.Open(filepath.Join(c.RuntimeDir, "instance.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if e != nil {
		return nil, errRuntime
	}
	f := os.NewFile(uintptr(fd), "veyl-instance-lock")
	good := false
	defer func() {
		if !good {
			f.Close()
		}
	}()
	info, e := f.Stat()
	if e != nil || !owned(info, 0600) || !info.Mode().IsRegular() || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return nil, errRuntime
	}
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return nil, errAlreadyRunning
	}
	views := filepath.Join(c.RuntimeDir, "views")
	if e := os.Mkdir(views, 0700); e != nil && !os.IsExist(e) {
		return nil, errRuntime
	}
	if residue(c.RuntimeDir) {
		return nil, errCleanupPending
	}
	socket := filepath.Join(c.RuntimeDir, "control.sock")
	if info, e := os.Lstat(socket); e == nil {
		if !owned(info, 0600) || info.Mode()&os.ModeSocket == 0 {
			return nil, errRuntime
		}
		conn, e := net.DialTimeout("unix", socket, 200*time.Millisecond)
		if e == nil {
			conn.Close()
			return nil, errAlreadyRunning
		}
		if !errors.Is(e, syscall.ECONNREFUSED) && !errors.Is(e, syscall.ENOENT) {
			return nil, errRuntime
		}
		again, e := os.Lstat(socket)
		if e != nil || !os.SameFile(info, again) {
			return nil, errRuntime
		}
		if os.Remove(socket) != nil {
			return nil, errRuntime
		}
	} else if !os.IsNotExist(e) {
		return nil, errRuntime
	}
	good = true
	return &runtimeOwner{path: c.RuntimeDir, lock: f}, nil
}
func owned(info os.FileInfo, mode os.FileMode) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid()) && info.Mode().Perm() == mode
}
func residue(runtime string) bool {
	views := filepath.Join(runtime, "views")
	if _, err := os.Lstat(views); os.IsNotExist(err) {
		return false
	}
	if storage.ValidateDirectory(views, true) != nil {
		return true
	}
	mounted, err := storage.HasMountsUnder(views)
	if err != nil || mounted {
		return true
	}
	entries, err := os.ReadDir(views)
	return err != nil || len(entries) != 0
}
func (o *runtimeOwner) listen() error {
	path := filepath.Join(o.path, "control.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return errRuntime
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		os.Remove(path)
		return errRuntime
	}
	info, err := os.Lstat(path)
	if err != nil {
		listener.Close()
		return errRuntime
	}
	o.listener, o.socketInfo = listener, info
	return nil
}
func (o *runtimeOwner) release() error {
	if o.listener != nil {
		path := filepath.Join(o.path, "control.sock")
		info, err := os.Lstat(path)
		if err != nil || !os.SameFile(info, o.socketInfo) || !owned(info, 0600) || info.Mode()&os.ModeSocket == 0 {
			return errCleanupPending
		}
		if os.Remove(path) != nil {
			return errCleanupPending
		}
		o.listener.Close()
		o.listener = nil
	}
	if o.lock != nil {
		o.lock.Close()
		o.lock = nil
	}
	return nil
}
func samePeer(conn *net.UnixConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return errRuntime
	}
	var cred *unix.Ucred
	var inner error
	if err = raw.Control(func(fd uintptr) { cred, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil || inner != nil || cred == nil || cred.Uid != uint32(os.Geteuid()) {
		return errRuntime
	}
	return nil
}
