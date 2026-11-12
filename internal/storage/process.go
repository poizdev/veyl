//go:build linux

package storage

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const credentialFD = "/proc/self/fd/3"
const maxPassword = 1024

var childEnvironment = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}

type child interface {
	Done() <-chan struct{}
	Exited() <-chan struct{}
	ExitCode() int
	Signal(os.Signal) error
}

// The leader stays unreaped until its inherited process group has drained. This
// reserves the numeric PID/PGID, so group signals cannot target a recycled ID.
type process struct {
	cmd                *exec.Cmd
	exited, done       chan struct{}
	code               int
	mu                 sync.Mutex
	reaped, waitFailed bool
}

func (p *process) Done() <-chan struct{}   { return p.done }
func (p *process) Exited() <-chan struct{} { return p.exited }
func (p *process) ExitCode() int           { <-p.done; return p.code }
func (p *process) Signal(signal os.Signal) error {
	sig, ok := signal.(syscall.Signal)
	if !ok {
		return ErrMount
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.reaped {
		return os.ErrProcessDone
	}
	if p.waitFailed {
		return p.cmd.Process.Signal(signal)
	} // pidfd-safe; group ownership unproven
	return syscall.Kill(-p.cmd.Process.Pid, sig)
}
func validPassword(password []byte) bool {
	return len(password) > 0 && len(password) <= maxPassword && !bytes.ContainsAny(password, "\x00\r\n")
}

// groupAlive examines only public process-group metadata, never cmdlines or
// environment. Zombies cannot initiate a late mount and do not count as live.
func groupAlive(pgid int) (bool, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false, err
		}
		split := strings.LastIndexByte(string(data), ')')
		if split < 0 {
			return false, ErrMount
		}
		fields := strings.Fields(string(data[split+1:]))
		if len(fields) < 3 {
			return false, ErrMount
		}
		group, err := strconv.Atoi(fields[2])
		if err != nil {
			return false, ErrMount
		}
		if group == pgid && fields[0] != "Z" && fields[0] != "X" {
			return true, nil
		}
	}
	return false, nil
}
func (p *process) observe() {
	var info unix.Siginfo
	var err error
	for {
		err = unix.Waitid(unix.P_PID, p.cmd.Process.Pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		// Never assume numeric group ownership after an unexpected wait failure.
		// Leave Done open, retain backend ownership, and report incomplete cleanup.
		p.mu.Lock()
		p.waitFailed = true
		p.mu.Unlock()
		close(p.exited)
		return
	}
	close(p.exited)
	for {
		p.mu.Lock()
		_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		p.mu.Unlock()
		alive, err := groupAlive(p.cmd.Process.Pid)
		if err == nil && !alive {
			break
		}
		// A restricted /proc or uninterruptible helper leaves ownership retained.
		// Backend stop deadlines remain bounded; the observer can finish later.
		time.Sleep(10 * time.Millisecond)
	}
	p.mu.Lock()
	_ = p.cmd.Wait()
	p.reaped = true
	p.code = -1
	if p.cmd.ProcessState != nil {
		p.code = p.cmd.ProcessState.ExitCode()
	}
	close(p.done)
	p.mu.Unlock()
}

// startCommand writes one bounded line to an anonymous pipe before execution.
// Linux PIPE_BUF exceeds this line limit, so no credential writer can hang.
func startCommand(binary string, args []string, password []byte) (child, error) {
	if !validPassword(password) {
		return nil, ErrCredentials
	}
	read, write, err := os.Pipe()
	if err != nil {
		return nil, ErrMount
	}
	defer read.Close()
	line := make([]byte, len(password)+1)
	copy(line, password)
	line[len(password)] = '\n'
	n, err := write.Write(line)
	short := n != len(line)
	clear(line)
	write.Close()
	if err != nil || short {
		return nil, ErrMount
	}
	cmd := exec.Command(binary, args...)
	cmd.ExtraFiles = []*os.File{read}
	cmd.Env = append([]string(nil), childEnvironment...)
	// Nil stdio uses /dev/null, not exec-managed copier goroutines inherited by
	// helpers. No child output, master-key hints or backend errors are retained.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return nil, ErrMount
	}
	p := &process{cmd: cmd, exited: make(chan struct{}), done: make(chan struct{})}
	go p.observe()
	return p, nil
}
func resolveBinary(path, name string) (string, error) {
	if path == "" {
		path = name
	}
	located, err := exec.LookPath(path)
	if err != nil {
		return "", ErrUnavailable
	}
	absolute, err := filepath.EvalSymlinks(located)
	if err != nil || !filepath.IsAbs(absolute) {
		return "", ErrUnsafe
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return "", ErrUnsafe
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", ErrUnsafe
	}
	if stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
		var filesystem syscall.Statfs_t
		if err := syscall.Statfs(absolute, &filesystem); err != nil || filesystem.Flags&syscall.MS_RDONLY == 0 {
			return "", ErrUnsafe
		}
	}
	if err := safeAncestors(filepath.Dir(absolute)); err != nil {
		return "", err
	}
	return absolute, nil
}
func unmountCommand(binary string) func(context.Context, string) error {
	return func(ctx context.Context, path string) error {
		cmd := exec.CommandContext(ctx, binary, "-u", "--", path)
		cmd.Env = append([]string(nil), childEnvironment...)
		if err := cmd.Run(); err != nil {
			return ErrCleanup
		}
		return nil
	}
}
