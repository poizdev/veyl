package credential

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/poizdev/veyl/internal/auth"
	"golang.org/x/sys/unix"
)

func TestTTYHelper(t *testing.T) {
	mode := os.Getenv("VEYL_CREDENTIAL_TTY_TEST")
	if mode == "" {
		return
	}
	ctx := context.Background()
	if mode == "timeout" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 150*time.Millisecond)
		defer cancel()
	}
	proof, err := ReadTTY(ctx)
	ok := false
	switch mode {
	case "success":
		ok = err == nil && string(proof) == "synthetic+secret"
	case "limit", "nul":
		ok = errors.Is(err, auth.ErrInvalidCredentials) && len(proof) == 0
	case "timeout":
		ok = errors.Is(err, context.DeadlineExceeded) && len(proof) == 0
	case "signal", "eof":
		ok = errors.Is(err, auth.ErrCanceled) && len(proof) == 0
	}
	clear(proof)
	if !ok {
		fmt.Fprintln(os.Stdout, "RESULT failed")
		os.Exit(3)
	}
	fmt.Fprintln(os.Stdout, "RESULT ok")
	os.Exit(0)
}

func pty(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Skipf("PTY unavailable: %v", err)
	}
	master := os.NewFile(uintptr(fd), "synthetic-pty-master")
	t.Cleanup(func() { master.Close() })
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile("/dev/pts/"+strconv.Itoa(number), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { slave.Close() })
	return master, slave
}

func readPTYUntil(t *testing.T, master *os.File, needle string) []byte {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var output []byte
	for time.Now().Before(deadline) {
		fds := []unix.PollFd{{Fd: int32(master.Fd()), Events: unix.POLLIN}}
		_, err := unix.Poll(fds, 50)
		if err != nil && err != unix.EINTR {
			t.Fatal(err)
		}
		if fds[0].Revents&unix.POLLIN == 0 {
			continue
		}
		buf := make([]byte, 4096)
		n, err := unix.Read(int(master.Fd()), buf)
		if err != nil && err != unix.EAGAIN {
			t.Fatal(err)
		}
		if n > 0 {
			output = append(output, buf[:n]...)
		}
		if bytes.Contains(output, []byte(needle)) {
			return output
		}
	}
	t.Fatal("synthetic terminal exchange timed out")
	return nil
}

func TestTTYOwnTerminalEchoRestorationAndCancellation(t *testing.T) {
	for _, mode := range []string{"success", "limit", "nul", "timeout", "signal", "eof"} {
		t.Run(mode, func(t *testing.T) {
			master, slave := pty(t)
			before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
			if err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(executable, "-test.run=^TestTTYHelper$")
			cmd.Env = append(os.Environ(), "VEYL_CREDENTIAL_TTY_TEST="+mode)
			cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cmd.Process.Kill() })
			output := readPTYUntil(t, master, "Veyl password: ")
			during, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
			if err != nil || during.Lflag&(unix.ECHO|unix.ECHONL) != 0 {
				t.Fatal("terminal echo was enabled during prompt")
			}
			switch mode {
			case "success":
				_, err = master.Write([]byte("synthetic+secrex\x7ft\n"))
			case "limit":
				_, err = master.Write([]byte(strings.Repeat("x", 1025) + "\n"))
			case "nul":
				_, err = master.Write([]byte("secret\x00\n"))
			case "signal":
				err = cmd.Process.Signal(syscall.SIGTERM)
			case "eof":
				_, err = master.Write([]byte{4})
			}
			if err != nil {
				t.Fatal(err)
			}
			output = append(output, readPTYUntil(t, master, "RESULT ok")...)
			if err := cmd.Wait(); err != nil {
				t.Fatalf("synthetic terminal helper: %v", err)
			}
			after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
			if err != nil || *before != *after {
				t.Fatal("terminal settings were not restored")
			}
			if bytes.Contains(output, []byte("synthetic+secret")) {
				t.Fatal("password echoed")
			}
		})
	}
}

func TestTTYPreCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	proof, err := ReadTTY(ctx)
	if !errors.Is(err, context.Canceled) || len(proof) != 0 {
		t.Fatal("canceled read proceeded")
	}
}
