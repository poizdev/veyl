// Package credential collects bounded credentials without authenticating them.
// Proofs must still be verified by the existing authentication broker/backend.
package credential

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/poizdev/veyl/internal/auth"
)

const maxProof = 1024

type pinentry struct {
	path, mount string
	env         []string
}

// New selects a graphical pinentry. Unavailable agents fail only when requested,
// allowing an instance to mount and later accept an explicit terminal unlock.
func New(preference, protectedMount string) auth.Agent {
	env, gui := guiEnvironment(protectedMount)
	a := &pinentry{mount: protectedMount, env: env}
	if !gui || preference == "none" {
		return a
	}
	if preference == "auto" {
		for _, name := range []string{"pinentry-qt", "pinentry-qt5", "pinentry-gnome3", "pinentry-gtk-2", "pinentry-gtk"} {
			if located, err := exec.LookPath(name); err == nil {
				if path, err := trustedExecutable(located, protectedMount); err == nil {
					a.path = path
					break
				}
			}
		}
	} else if filepath.IsAbs(preference) {
		a.path, _ = trustedExecutable(preference, protectedMount)
	}
	return a
}

func (a *pinentry) Authenticate(ctx context.Context, req auth.Request) (auth.Response, error) {
	response := auth.Response{RequestID: req.ID}
	if err := ctx.Err(); err != nil {
		return response, err
	}
	if a.path == "" {
		return response, auth.ErrUnavailable
	}
	path, err := trustedExecutable(a.path, a.mount)
	if err != nil {
		return response, auth.ErrUnavailable
	}
	proof, err := runPinentry(ctx, path, a.env, 60)
	if err != nil {
		return response, err
	}
	response.Approved, response.Proof = true, proof
	return response, nil
}

func inside(path, tree string) bool {
	if tree == "" {
		return false
	}
	rel, err := filepath.Rel(tree, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func readonly(path string) bool {
	var st syscall.Statfs_t
	return syscall.Statfs(path, &st) == nil && st.Flags&syscall.MS_RDONLY != 0
}

func trustedExecutable(path, mount string) (string, error) {
	if !filepath.IsAbs(path) || inside(filepath.Clean(path), mount) {
		return "", auth.ErrUnavailable
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || inside(resolved, mount) {
		return "", auth.ErrUnavailable
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
		return "", auth.ErrUnavailable
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 && st.Uid != uint32(os.Geteuid()) && !readonly(resolved) {
		return "", auth.ErrUnavailable
	}
	if !safeAncestors(filepath.Dir(resolved)) {
		return "", auth.ErrUnavailable
	}
	return resolved, nil
}

func safeAncestors(path string) bool {
	root, err := os.Stat("/")
	if err != nil {
		return false
	}
	rootStat, ok := root.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	for parent := path; ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() {
			return false
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return false
		}
		// A system-owned sticky directory protects the caller-owned private child
		// from replacement; arbitrary writable parents remain forbidden.
		sticky := info.Mode()&os.ModeSticky != 0 && (st.Uid == 0 || st.Uid == rootStat.Uid)
		if info.Mode().Perm()&0022 != 0 && !sticky {
			return false
		}
		if st.Uid != 0 && st.Uid != uint32(os.Geteuid()) && !readonly(parent) && !sticky {
			return false
		}
		if parent == "/" {
			break
		}
	}
	return true
}

var displayPattern = regexp.MustCompile(`^([A-Za-z0-9_.-]*|unix):[0-9]+(\.[0-9]+)?$`)
var localePattern = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,128}$`)
var waylandPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

func privateRuntime(path, mount string) bool {
	if !filepath.IsAbs(path) || inside(path, mount) {
		return false
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return false
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid()) && safeAncestors(path)
}

// Do not inherit plugin loaders, GPG_TTY, HOME, or arbitrary caller variables.
func guiEnvironment(mount string) ([]string, bool) {
	env := []string{"PATH=/usr/bin:/bin"}
	gui := false
	if display := os.Getenv("DISPLAY"); len(display) <= 256 && displayPattern.MatchString(display) {
		env = append(env, "DISPLAY="+display)
		gui = true
		if path := os.Getenv("XAUTHORITY"); filepath.IsAbs(path) && !inside(path, mount) && !strings.ContainsAny(path, "\x00\r\n") && len(path) <= 4096 {
			canonical, err := filepath.EvalSymlinks(path)
			if err == nil && !inside(canonical, mount) && safeAncestors(filepath.Dir(canonical)) {
				if info, err := os.Stat(canonical); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0022 == 0 {
					if st, ok := info.Sys().(*syscall.Stat_t); ok && (st.Uid == 0 || st.Uid == uint32(os.Geteuid())) {
						env = append(env, "XAUTHORITY="+canonical)
					}
				}
			}
		}
	}
	runtime := os.Getenv("XDG_RUNTIME_DIR")
	if privateRuntime(runtime, mount) {
		env = append(env, "XDG_RUNTIME_DIR="+runtime)
		if display := os.Getenv("WAYLAND_DISPLAY"); waylandPattern.MatchString(display) && display != "." && display != ".." {
			env = append(env, "WAYLAND_DISPLAY="+display)
			gui = true
		}
		// Restrict the session bus to a local socket in the owned runtime tree.
		address := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
		if strings.HasPrefix(address, "unix:path=") {
			path := strings.TrimPrefix(address, "unix:path=")
			if filepath.IsAbs(path) && filepath.Clean(path) == path && inside(path, runtime) && !strings.ContainsAny(path, ",;\x00\r\n%") {
				env = append(env, "DBUS_SESSION_BUS_ADDRESS="+address)
			}
		}
	}
	for _, name := range []string{"LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES"} {
		if value := os.Getenv(name); localePattern.MatchString(value) {
			env = append(env, name+"="+value)
		}
	}
	return env, gui
}

func runPinentry(parent context.Context, path string, env []string, seconds int) (proof []byte, result error) {
	ctx, cancel := context.WithTimeout(parent, time.Duration(seconds)*time.Second+time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	input, childInput, err := os.Pipe()
	if err != nil {
		return nil, auth.ErrUnavailable
	}
	defer input.Close()
	defer childInput.Close()
	output, childOutput, err := os.Pipe()
	if err != nil {
		return nil, auth.ErrUnavailable
	}
	defer output.Close()
	defer childOutput.Close()
	diagnostics, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return nil, auth.ErrUnavailable
	}
	defer diagnostics.Close()
	// os.Pipe returns reader, writer; the child reads input, parent writes it.
	cmd := exec.Command(path)
	// A real /dev/null descriptor avoids an exec copy goroutine waiting on
	// inherited diagnostic pipes after the pinentry process has exited.
	cmd.Dir, cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = "/", append([]string{}, env...), input, childOutput, diagnostics
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return nil, auth.ErrUnavailable
	}
	input.Close()
	childOutput.Close()
	waited := make(chan struct{})
	var waitErr error
	go func() { waitErr = cmd.Wait(); close(waited) }()
	finished := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-ctx.Done():
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			childInput.Close()
			output.Close()
		case <-finished:
		}
	}()
	defer func() {
		close(finished)
		<-watchDone
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		childInput.Close()
		output.Close()
		<-waited
		if ctx.Err() != nil {
			result = ctx.Err()
		}
		if result != nil {
			clear(proof)
			proof = nil
		}
	}()
	reader := bufio.NewReaderSize(output, 1001)
	if _, err := readResponse(reader, false); err != nil {
		return nil, err
	}
	for _, command := range []string{"SETTITLE Veyl pinentry", "SETDESC Enter Veyl encrypted store password", "SETPROMPT Password:", "SETTIMEOUT " + strconv.Itoa(seconds), "GETPIN", "BYE"} {
		if _, err := io.WriteString(childInput, command+"\n"); err != nil {
			return proof, auth.ErrFailed
		}
		data, err := readResponse(reader, command == "GETPIN")
		if err != nil {
			return proof, err
		}
		if command == "GETPIN" {
			proof = data
		}
	}
	if len(proof) == 0 {
		return proof, auth.ErrInvalidCredentials
	}
	// BYE must cause a timely exit, independently of the longer prompt timeout.
	select {
	case <-waited:
		if waitErr != nil {
			return proof, auth.ErrFailed
		}
	case <-ctx.Done():
		return proof, ctx.Err()
	// A pinentry can acknowledge BYE promptly but need a little more than one
	// second to exit (race-instrumented test helpers do this by default).
	case <-time.After(2 * time.Second):
		return proof, auth.ErrFailed
	}
	return proof, nil
}

func readResponse(reader *bufio.Reader, dataAllowed bool) (proof []byte, result error) {
	defer func() {
		if result != nil {
			clear(proof)
			proof = nil
		}
	}()
	for records := 0; records < 4096; records++ {
		line, err := reader.ReadSlice('\n')
		if err != nil || len(line) > 1000 {
			return proof, auth.ErrFailed
		}
		line = bytes.TrimSuffix(line[:len(line)-1], []byte{'\r'})
		switch {
		case bytes.Equal(line, []byte("OK")), bytes.HasPrefix(line, []byte("OK ")):
			return proof, nil
		case bytes.HasPrefix(line, []byte("ERR ")):
			fields := bytes.Fields(line[4:])
			if len(fields) > 0 {
				code, err := strconv.ParseUint(string(fields[0]), 10, 32)
				if err == nil {
					switch code & 0xffff {
					case 99:
						return proof, auth.ErrCanceled
					case 62:
						return proof, context.DeadlineExceeded
					default:
						// Pinentry collects a proof; it does not verify credentials.
						// Other operational errors (including a stale display or
						// unavailable toolkit) therefore mean no usable agent.
						return proof, auth.ErrUnavailable
					}
				}
			}
			return proof, auth.ErrFailed
		case len(line) == 0, line[0] == '#', bytes.HasPrefix(line, []byte("S ")):
			continue
		case bytes.HasPrefix(line, []byte("D ")) && dataAllowed:
			for encoded := line[2:]; len(encoded) > 0; {
				c := encoded[0]
				encoded = encoded[1:]
				if c == '%' {
					if len(encoded) < 2 {
						return proof, auth.ErrFailed
					}
					var decoded [1]byte
					if _, err := hex.Decode(decoded[:], encoded[:2]); err != nil {
						return proof, auth.ErrFailed
					}
					c, encoded = decoded[0], encoded[2:]
				}
				if c == 0 || c == '\r' || c == '\n' || len(proof) >= maxProof {
					return proof, auth.ErrInvalidCredentials
				}
				proof = append(proof, c)
			}
		default:
			return proof, auth.ErrFailed
		}
	}
	return proof, auth.ErrFailed
}
