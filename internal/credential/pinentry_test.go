package credential

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/poizdev/veyl/internal/auth"
)

// Only deterministic synthetic Assuan servers are launched by these tests.
func cleanGUIEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{"DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} {
		t.Setenv(name, "")
	}
}

func script(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pinentry-test")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func exchange(reply string) string {
	return "printf 'OK ready\\n'\n" +
		"for expected in 'SETTITLE Veyl pinentry' 'SETDESC Enter Veyl encrypted store password' 'SETPROMPT Password:' 'SETTIMEOUT 60' GETPIN BYE; do\n" +
		"IFS= read -r line || exit 10\n[ \"$line\" = \"$expected\" ] || exit 11\n" +
		"if [ \"$line\" = GETPIN ]; then printf '%s\\n' '" + reply + "'; else printf 'OK\\n'; fi\ndone\n"
}

func TestPinentrySequentialExchangeAndLiteralPlus(t *testing.T) {
	path := script(t, exchange("# comment\nS TEST ignored\nD first+%25%20\nD second%21\nOK"))
	proof, err := runPinentry(context.Background(), path, []string{}, 60)
	if err != nil || string(proof) != "first+% second!" {
		t.Fatalf("exchange: proof length=%d err=%v", len(proof), err)
	}
}

// Pinentry may acknowledge BYE before its process has completed a brief,
// clean exit delay. Do not misclassify a valid proof as an operational failure.
func TestPinentryAllowsDelayedCleanExit(t *testing.T) {
	path := script(t, exchange("D synthetic-proof\nOK")+"sleep 1.2\n")
	proof, err := runPinentry(context.Background(), path, nil, 60)
	if err != nil || string(proof) != "synthetic-proof" {
		t.Fatalf("delayed exit: proof length=%d err=%v", len(proof), err)
	}
}

func TestPinentryRejectsUnsafeResponses(t *testing.T) {
	for name, reply := range map[string]string{
		"bad escape": "D secret%GG\nOK", "truncated escape": "D secret%\nOK",
		"nul": "D secret%00\nOK", "lf": "D secret%0A\nOK", "cr": "D secret%0D\nOK",
		"oversize line": "D " + strings.Repeat("x", 1000) + "\nOK",
		"aggregate":     "D " + strings.Repeat("x", 600) + "\nD " + strings.Repeat("y", 600) + "\nOK",
		"unexpected":    "INQUIRE secret\nOK", "empty": "OK", "malformed terminal": "OKAY secret",
		"generic error": "ERR 42 secret-transcript",
	} {
		t.Run(name, func(t *testing.T) {
			proof, err := runPinentry(context.Background(), script(t, exchange(reply)), nil, 60)
			if err == nil || len(proof) != 0 {
				t.Fatal("unsafe response accepted")
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("transcript exposed")
			}
		})
	}
}

func TestPinentryCancellationCode(t *testing.T) {
	for _, code := range []string{"99", "83886179"} {
		_, err := runPinentry(context.Background(), script(t, exchange("ERR "+code+" private-text")), nil, 60)
		if !errors.Is(err, auth.ErrCanceled) {
			t.Fatalf("cancel code: %v", err)
		}
	}
}

func TestPinentryCancellationBoundsOwnedProcess(t *testing.T) {
	for _, body := range []string{"sleep 30\n", "printf 'OK\\n'\nsleep 30\n", exchange("D proof\nOK") + "sleep 30\n"} {
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
		start := time.Now()
		proof, err := runPinentry(ctx, script(t, body), nil, 60)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) || len(proof) != 0 || time.Since(start) > 2*time.Second {
			t.Fatalf("unbounded cancellation: %v", err)
		}
	}
}

func TestNewCorrelatesResponseAndRejectsUntrustedExecutable(t *testing.T) {
	cleanGUIEnv(t)
	t.Setenv("DISPLAY", ":99")
	t.Setenv("WAYLAND_DISPLAY", "")
	path := script(t, exchange("D synthetic-proof\nOK"))
	agent := New(path, "/nonexistent-protected-mount")
	response, err := agent.Authenticate(context.Background(), auth.Request{ID: 91, Directory: "not-a-transcript"})
	if err != nil || response.RequestID != 91 || !response.Approved || string(response.Proof) != "synthetic-proof" {
		t.Fatalf("response: id=%d approved=%v err=%v", response.RequestID, response.Approved, err)
	}
	for _, mode := range []os.FileMode{0777, 0666} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err = New(path, "").Authenticate(context.Background(), auth.Request{})
		if !errors.Is(err, auth.ErrUnavailable) {
			t.Fatalf("unsafe executable: %v", err)
		}
	}
}

func TestUnavailableNeverStartsTerminalFallback(t *testing.T) {
	cleanGUIEnv(t)
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	for _, preference := range []string{"none", "auto", "relative-pinentry", "/missing-pinentry"} {
		_, err := New(preference, "").Authenticate(context.Background(), auth.Request{})
		if !errors.Is(err, auth.ErrUnavailable) {
			t.Fatalf("unavailable %q: %v", preference, err)
		}
	}
}

func TestExecutableWithinProtectedMountAndWritableParentRejected(t *testing.T) {
	cleanGUIEnv(t)
	t.Setenv("DISPLAY", ":99")
	path := script(t, exchange("D synthetic-proof\nOK"))
	for _, mount := range []string{filepath.Dir(path), path} {
		_, err := New(path, mount).Authenticate(context.Background(), auth.Request{})
		if !errors.Is(err, auth.ErrUnavailable) {
			t.Fatal("recursive executable accepted")
		}
	}
	if err := os.Chmod(filepath.Dir(path), 0777); err != nil {
		t.Fatal(err)
	}
	_, err := New(path, "").Authenticate(context.Background(), auth.Request{})
	if !errors.Is(err, auth.ErrUnavailable) {
		t.Fatal("writable parent accepted")
	}
}

func TestEnvironmentAllowsSessionAndExcludesInjection(t *testing.T) {
	cleanGUIEnv(t)
	t.Setenv("DISPLAY", ":99")
	t.Setenv("LANG", "C.UTF-8")
	t.Setenv("GPG_TTY", "/dev/pts/100")
	t.Setenv("LD_PRELOAD", "/tmp/inject.so")
	t.Setenv("QT_PLUGIN_PATH", "/tmp/plugins")
	t.Setenv("PASSWORD", "private-text")
	env, gui := guiEnvironment("")
	if !gui {
		t.Fatal("valid X11 display rejected")
	}
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "DISPLAY=:99\n") && !strings.HasSuffix(joined, "DISPLAY=:99") {
		t.Fatal("display omitted")
	}
	for _, key := range []string{"GPG_TTY=", "LD_PRELOAD=", "QT_PLUGIN_PATH=", "PASSWORD="} {
		if strings.Contains(joined, key) {
			t.Fatal("injection environment accepted")
		}
	}
	t.Setenv("DISPLAY", ":99\nINJECT")
	t.Setenv("WAYLAND_DISPLAY", "../../untrusted")
	_, gui = guiEnvironment("")
	if gui {
		t.Fatal("invalid GUI environment accepted")
	}
}

func TestPinentryProcessHasPrivatePipesDetachedSessionAndCleanEnvironment(t *testing.T) {
	cleanGUIEnv(t)
	t.Setenv("DISPLAY", ":99")
	t.Setenv("LD_PRELOAD", "/synthetic-do-not-load.so")
	t.Setenv("GPG_TTY", "/dev/pts/999")
	t.Setenv("QT_QPA_PLATFORM_PLUGIN_PATH", "/synthetic-plugins")
	body := `[ "$PWD" = / ] || exit 21
[ "$#" -eq 0 ] || exit 22
[ -z "${LD_PRELOAD+x}${GPG_TTY+x}${QT_QPA_PLATFORM_PLUGIN_PATH+x}" ] || exit 23
if (: </dev/tty) 2>/dev/null; then exit 24; fi
[ ! -t 0 ] && [ ! -t 1 ] || exit 25
printf 'private-diagnostics' >&2
`
	response, err := New(script(t, body+exchange("D synthetic-proof\nOK")), "").Authenticate(context.Background(), auth.Request{ID: 5})
	if err != nil || !response.Approved {
		t.Fatalf("process isolation: %v", err)
	}
}

func TestAutoSelectsGraphicalVariantWithoutDesktopEnvironment(t *testing.T) {
	cleanGUIEnv(t)
	t.Setenv("DISPLAY", ":99")
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("XDG_CURRENT_DESKTOP", "unrelated-desktop")
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	for _, name := range []string{"pinentry", "pinentry-curses"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+exchange("D synthetic-proof\nOK")), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := New("auto", "").Authenticate(context.Background(), auth.Request{}); !errors.Is(err, auth.ErrUnavailable) {
		t.Fatal("terminal-only variant selected")
	}
	if err := os.WriteFile(filepath.Join(dir, "pinentry-qt"), []byte("#!/bin/sh\n"+exchange("D synthetic-proof\nOK")), 0700); err != nil {
		t.Fatal(err)
	}
	response, err := New("auto", "").Authenticate(context.Background(), auth.Request{})
	if err != nil || !response.Approved {
		t.Fatalf("graphical variant not selected: %v", err)
	}
}

func TestEnvironmentRejectsRecursiveAuthorityAndUnsafeRuntimeAncestors(t *testing.T) {
	cleanGUIEnv(t)
	t.Setenv("DISPLAY", ":99")
	mount := t.TempDir()
	authority := filepath.Join(mount, "synthetic-authority")
	if err := os.WriteFile(authority, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "authority-link")
	if err := os.Symlink(authority, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XAUTHORITY", link)
	env, _ := guiEnvironment(mount)
	if strings.Contains(strings.Join(env, "\n"), "XAUTHORITY=") {
		t.Error("recursive authority path accepted")
	}
	parent := t.TempDir()
	runtime := filepath.Join(parent, "runtime")
	if err := os.Mkdir(runtime, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", runtime)
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")
	t.Setenv("DISPLAY", "")
	_, gui := guiEnvironment("")
	if gui {
		t.Fatal("runtime under untrusted writable parent accepted")
	}
}

func TestPinentryUnavailableCode(t *testing.T) {
	for _, code := range []string{"85", "83886165", "83918950"} {
		_, err := runPinentry(context.Background(), script(t, exchange("ERR "+code+" private-text")), nil, 60)
		if !errors.Is(err, auth.ErrUnavailable) {
			t.Fatalf("unavailable code: %v", err)
		}
	}
}

func TestPinentryPromptTimeoutCode(t *testing.T) {
	_, err := runPinentry(context.Background(), script(t, exchange("ERR 83886142 private-text")), nil, 60)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout code: %v", err)
	}
}

func TestPinentryDoesNotWaitForInheritedDiscardedDiagnostics(t *testing.T) {
	if _, err := os.Stat("/usr/bin/setsid"); err != nil {
		t.Skip("synthetic session helper unavailable")
	}
	marker := filepath.Join(t.TempDir(), "synthetic-process-id")
	body := "/usr/bin/setsid /bin/sh -c 'exec 1>/dev/null; sleep 2' &\nprintf '%s' \"$!\" > '" + marker + "'\n"
	t.Cleanup(func() {
		data, err := os.ReadFile(marker)
		if err != nil {
			return
		}
		pid, err := strconv.Atoi(string(data))
		if err == nil {
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
	})
	start := time.Now()
	proof, err := runPinentry(context.Background(), script(t, body+exchange("D synthetic-proof\nOK")), []string{"PATH=/usr/bin:/bin"}, 60)
	if err != nil || string(proof) != "synthetic-proof" || time.Since(start) > time.Second {
		t.Fatalf("diagnostic descendant delayed or rejected completed prompt: %v", err)
	}
}
