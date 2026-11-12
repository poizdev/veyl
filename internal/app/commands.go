//go:build linux

package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/poizdev/veyl/internal/auth"
	"github.com/poizdev/veyl/internal/credential"
	"github.com/poizdev/veyl/internal/ghostfs"
	"github.com/poizdev/veyl/internal/policy"
	"github.com/poizdev/veyl/internal/storage"
	"golang.org/x/sys/unix"
)

func runCommand(ctx context.Context, c Config, command string, tty bool, out io.Writer) Result {
	if command == "mount" {
		return mountCommand(ctx, c, out)
	}
	return clientCommand(ctx, c, command, tty)
}
func clientCommand(ctx context.Context, c Config, command string, tty bool) Result {
	if storage.ValidateDirectory(c.RuntimeDir, true) != nil {
		return Result{Code: 1, Message: errRuntime.Error()}
	}
	socket := filepath.Join(c.RuntimeDir, "control.sock")
	info, err := os.Lstat(socket)
	if err == nil && (!owned(info, 0600) || info.Mode()&os.ModeSocket == 0) {
		return Result{Code: 1, Message: errRuntime.Error()}
	}
	if err != nil && !os.IsNotExist(err) {
		return Result{Code: 1, Message: errRuntime.Error()}
	}
	if os.IsNotExist(err) {
		return absentInstance(c)
	}
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
			return absentInstance(c)
		}
		return Result{Code: 1, Message: "Cannot connect to Veyl. Check the runtime directory and retry status."}
	}
	defer conn.Close()
	uc, ok := conn.(*net.UnixConn)
	if !ok || samePeer(uc) != nil {
		return Result{Code: 1, Message: errRuntime.Error()}
	}
	return exchange(ctx, uc, command, tty, credential.ReadTTY)
}

func absentInstance(c Config) Result {
	if mounted, err := storage.HasMountsUnder(c.Mountpoint); err != nil || mounted || residue(c.RuntimeDir) {
		return Result{Code: 5, State: "cleanup_pending", Message: "A previous instance left cleanup pending. Inspect the private runtime directory; do not start another mount over it."}
	}
	fd, err := unix.Open(filepath.Join(c.RuntimeDir, "instance.lock"), unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err == nil {
		busy := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil
		unix.Close(fd)
		if busy {
			return Result{Code: 1, State: "starting", Message: "Veyl is starting or stopping. Retry status shortly."}
		}
	}
	return Result{Code: 3, State: "not_running", Message: "Veyl is not running. Use veyl service start for the registered service, or veyl mount --config FILE for foreground mode. Check veyl service status if startup failed."}
}

type collectingAgent struct {
	inner    auth.Agent
	instance *instance
	message  func(string)
}

func (a collectingAgent) Authenticate(ctx context.Context, r auth.Request) (auth.Response, error) {
	if a.instance.status().Code == 5 {
		return auth.Response{}, auth.ErrUnavailable
	}
	response, err := a.inner.Authenticate(ctx, r)
	if err != nil {
		a.message(authResult(err).Message)
	}
	return response, err
}
func mountCommand(ctx context.Context, c Config, out io.Writer) Result {
	if os.Geteuid() == 0 {
		return Result{Code: 1, Message: "Run Veyl as your normal desktop user, not root."}
	}
	if c.Original != nil {
		if err := ensureServiceDirectory(c.RuntimeDir, true); err != nil {
			return Result{Code: 2, Message: err.Error()}
		}
	}
	if err := c.validateMount(); err != nil {
		return Result{Code: 2, Message: err.Error()}
	}
	runtime, err := claimRuntime(c)
	if err != nil {
		code := 1
		if errors.Is(err, errCleanupPending) {
			code = 5
		}
		return Result{Code: code, Message: err.Error()}
	}
	// Bind control before exposing FUSE. No authentication is admitted until both
	// surfaces are ready; a socket startup failure cannot leave an unlocked view.
	if runtime.listen() != nil {
		runtime.release()
		return Result{Code: 1, Message: errRuntime.Error()}
	}
	root := &ghostfs.Root{HiddenName: c.HiddenName, Writable: c.Writable(), ExplicitUnlock: c.ExplicitUnlock}
	if c.Original != nil {
		// Keep the physical empty target read-only, including after stop/crash.
		if err := os.Chmod(filepath.Join(c.Mountpoint, c.HiddenName), 0500); err != nil {
			runtime.release()
			return Result{Code: 2, Message: "Cannot guard the original directory; nothing was mounted."}
		}
		if err := root.SetOriginalParent(c.Mountpoint); err != nil {
			runtime.release()
			return Result{Code: 2, Message: err.Error()}
		}
	} else if c.Parent != "" {
		if err := root.SetParent(c.Parent); err != nil {
			runtime.release()
			return Result{Code: 2, Message: err.Error()}
		}
	}
	defer root.CloseParent()
	hideDesktop := desktopMountHint(ctx)
	backend, err := storage.New(storage.Config{HideFromDesktop: hideDesktop, Store: c.Store, RuntimeDir: filepath.Join(c.RuntimeDir, "views"), BeforeUnmount: root.CloseBacking}, &root.State)
	if err != nil {
		runtime.release()
		return Result{Code: 1, Message: "Cannot open the encrypted store. Check gocryptfs, fusermount3, store permissions and configuration."}
	}
	i := newInstance(root, nil, backend, nil, runtime)
	i.mountpoint = c.Mountpoint
	var outputMu sync.Mutex
	message := func(s string) { outputMu.Lock(); defer outputMu.Unlock(); fmt.Fprintln(out, s) }
	agent := collectingAgent{inner: credential.New(c.CredentialAgent, c.Mountpoint), instance: i, message: message}
	broker := auth.NewTransactional(&root.State, agent, func(ctx context.Context, ticket policy.Challenge, response auth.Response) (auth.Transaction, error) {
		candidate, err := backend.Prepare(ctx, ticket, response.Proof)
		if candidate != nil {
			i.owner.Store(candidate)
		}
		if err != nil {
			switch {
			case errors.Is(err, storage.ErrCleanup):
				err = auth.ErrCleanup
			case errors.Is(err, storage.ErrCredentials):
				err = auth.ErrInvalidCredentials
				message("Incorrect password. Directory remains locked.")
			case errors.Is(err, context.Canceled):
				err = auth.ErrCanceled
			case errors.Is(err, context.DeadlineExceeded):
				err = context.DeadlineExceeded
			default:
				err = auth.ErrFailed
			}
		}
		if candidate == nil {
			return nil, err
		}
		return candidate, err
	}, 60*time.Second)
	i.broker, root.Auth, root.Backing = broker, broker, backend
	broker.Suspend(false)
	// Recheck target safety immediately before mounting; same-UID path replacement
	// remains outside the accepted threat model.
	if err := c.validateMount(); err != nil {
		backend.Close()
		runtime.release()
		return Result{Code: 2, Message: err.Error()}
	}
	server, err := fs.Mount(c.Mountpoint, root, ghostfs.OptionsForDesktop(c.Writable() || c.Parent != "" || c.Original != nil, hideDesktop))
	if err != nil {
		backend.Close()
		runtime.release()
		return Result{Code: 1, Message: "Unable to mount Veyl. Check /dev/fuse, fusermount3, and that the mountpoint is empty and not already mounted."}
	}
	i.server = server
	if c.Original != nil {
		if err := root.ConfirmOriginalMount(); err != nil {
			result := i.lock(context.Background(), true)
			if result.Code != 0 {
				return result
			}
			return Result{Code: 1, Message: "Original mount identity could not be confirmed; cleanup confirmed."}
		}
	}
	control := serveControl(runtime, i)
	broker.Resume()
	message("Veyl is mounted and locked. Open the known hidden path to unlock; Ctrl+C requests cleanup.")
	message("Security limit: other processes running as your user and root can access the decrypted backing mount.")
	gone := make(chan struct{})
	go func() { server.Wait(); close(gone) }()
	interrupted, controlGone := ctx.Done(), control.stopped
	shutdown := func() {
		r := i.lock(context.Background(), true)
		if r.Code == 0 {
			i.finish()
		} else {
			message(r.Message)
		}
	}
	readinessErr := notifyReady()
	if readinessErr != nil {
		message("Cannot notify the user service manager that the mount is ready. Requesting cleanup; inspect journalctl --user -u veyl.service -b.")
		shutdown()
	}
	for {
		select {
		case <-i.done:
			control.close()
			if readinessErr != nil {
				return Result{Code: 1, Message: "Service readiness failed; mount cleanup confirmed."}
			}
			return Result{Message: "Veyl stopped; cleanup confirmed."}
		case <-interrupted:
			interrupted = nil
			if !i.stopping.Load() {
				shutdown()
			}
		case <-gone:
			gone = nil
			if !i.stopping.Load() {
				shutdown()
			}
		case <-controlGone:
			controlGone = nil
			if !i.stopping.Load() {
				shutdown()
			}
		}
	}
}
