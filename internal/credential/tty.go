package credential

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/poizdev/veyl/internal/auth"
	"golang.org/x/sys/unix"
)

var ttyGate = make(chan struct{}, 1)

// ReadTTY reads only the caller's controlling terminal. Invoke it client-side
// only after receiving an authenticated server's per-flight challenge. Catchable
// termination/job-control signals cancel the prompt after restoring settings.
// SIGKILL cannot run terminal restoration or any other userspace cleanup.
func ReadTTY(ctx context.Context) (proof []byte, result error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case ttyGate <- struct{}{}:
		defer func() { <-ttyGate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	fd, err := unix.Open("/dev/tty", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, auth.ErrUnavailable
	}
	defer unix.Close(fd)
	original, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, auth.ErrUnavailable
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTSTP)
	defer signal.Stop(signals)
	changed := *original
	changed.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON
	changed.Cc[unix.VMIN], changed.Cc[unix.VTIME] = 1, 0
	if unix.IoctlSetTermios(fd, unix.TCSETS, &changed) != nil {
		return nil, auth.ErrUnavailable
	}
	defer func() {
		// Immediate ioctls avoid waiting for an unresponsive terminal to drain.
		_ = unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH)
		if unix.IoctlSetTermios(fd, unix.TCSETS, original) != nil {
			result = auth.ErrFailed
		}
		_, _ = unix.Write(fd, []byte("\n"))
		if result != nil {
			clear(proof)
			proof = nil
		}
	}()
	_, _ = unix.Write(fd, []byte("Veyl password: "))
	var buffer [128]byte
	defer clear(buffer[:])
	for {
		if err := ctx.Err(); err != nil {
			return proof, err
		}
		select {
		case <-signals:
			return proof, auth.ErrCanceled
		default:
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, err := unix.Poll(fds, 50)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return proof, auth.ErrUnavailable
		}
		if fds[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return proof, auth.ErrCanceled
		}
		if fds[0].Revents&unix.POLLIN == 0 {
			continue
		}
		n, err := unix.Read(fd, buffer[:])
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		if err != nil {
			return proof, auth.ErrUnavailable
		}
		if n == 0 {
			return proof, auth.ErrCanceled
		}
		for _, c := range buffer[:n] {
			switch c {
			case '\r', '\n':
				if err := ctx.Err(); err != nil {
					return proof, err
				}
				if len(proof) == 0 {
					return proof, auth.ErrInvalidCredentials
				}
				return proof, nil
			case 0:
				return proof, auth.ErrInvalidCredentials
			case 4:
				return proof, auth.ErrCanceled
			case 8, 127:
				if len(proof) > 0 {
					proof[len(proof)-1] = 0
					proof = proof[:len(proof)-1]
				}
			case 21:
				clear(proof)
				proof = proof[:0]
			default:
				if len(proof) >= maxProof {
					return proof, auth.ErrInvalidCredentials
				}
				proof = append(proof, c)
			}
		}
	}
}
