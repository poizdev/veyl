//go:build linux

package app

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/poizdev/veyl/internal/auth"
	"github.com/poizdev/veyl/internal/ghostfs"
	"github.com/poizdev/veyl/internal/storage"
)

type teardown interface {
	Unmount(context.Context) error
	Close() error
}
type fuseServer interface {
	Unmount() error
	Wait()
}

// instance owns process resources. Authorization remains exclusively in State;
// the flags below describe cleanup/admission, never an independent session.
type instance struct {
	root                         *ghostfs.Root
	broker                       *auth.Broker
	backend                      teardown
	server                       fuseServer
	runtime                      *runtimeOwner
	mountpoint                   string
	owner                        atomic.Pointer[storage.Candidate]
	gate                         chan struct{}
	stopping, cleanup, completed atomic.Bool
	done                         chan struct{}
	once                         sync.Once
}

func newInstance(r *ghostfs.Root, b *auth.Broker, backend teardown, server fuseServer, owner *runtimeOwner) *instance {
	i := &instance{root: r, broker: b, backend: backend, server: server, runtime: owner, gate: make(chan struct{}, 1), done: make(chan struct{})}
	i.gate <- struct{}{}
	return i
}
func (i *instance) finish() { i.once.Do(func() { close(i.done) }) }
func (i *instance) status() Result {
	snap := i.broker.Snapshot()
	c := i.owner.Load()
	badOwner := c != nil && c.Owned() && errors.Is(c.View().Err(), storage.ErrCleanup)
	if i.cleanup.Load() || snap.Cleanup || badOwner {
		if !i.root.State.IsLocked() {
			return Result{Code: 5, State: "cleanup_pending", Message: "Session cleanup is in progress. Check status again before relying on revocation."}
		}
		return Result{Code: 5, State: "cleanup_pending", Message: "Session locked; encrypted mount cleanup pending. Retry veyl lock or veyl unmount."}
	}
	if err := i.root.NamespaceError(); err != nil {
		return Result{Code: 1, State: "namespace_unavailable", Message: err.Error()}
	}
	if snap.Authenticating {
		return Result{State: "authenticating", Message: "Authentication is in progress."}
	}
	if !i.root.State.IsLocked() {
		return Result{State: "unlocked", Message: "Session unlocked."}
	}
	if c != nil && c.Owned() {
		return Result{Code: 5, State: "cleanup_pending", Message: "Session locked; encrypted mount cleanup pending. Retry veyl lock or veyl unmount."}
	}
	return Result{State: "locked", Message: "Veyl is mounted and locked."}
}
func (i *instance) lock(ctx context.Context, shutdown bool) Result {
	select {
	case <-ctx.Done():
		return Result{Code: 5, Message: errCleanupPending.Error()}
	case <-i.gate:
	}
	defer func() { i.gate <- struct{}{} }()
	if i.completed.Load() {
		return Result{Message: "Veyl is unmounted; cleanup confirmed."}
	}
	if shutdown {
		i.stopping.Store(true)
	}
	i.cleanup.Store(true)
	i.broker.Suspend(i.stopping.Load())
	i.root.State.Lock() // revokes, signals cancellation, then drains admitted I/O
	failed := func() Result { return Result{Code: 5, State: "cleanup_pending", Message: errCleanupPending.Error()} }
	if i.broker.WaitIdle(ctx) != nil {
		return failed()
	}
	var err error
	if i.stopping.Load() {
		err = i.backend.Close()
	} else {
		err = i.backend.Unmount(ctx)
	}
	if err != nil {
		return failed()
	}
	if i.broker.RetryCleanup() != nil {
		return failed()
	}
	if i.stopping.Load() {
		if i.server != nil {
			if i.server.Unmount() != nil {
				// External fusermount may have already removed this mount.
				// Only a mount-table confirmation permits successful teardown.
				if i.mountpoint == "" {
					return failed()
				}
				mounted, err := storage.HasMountsUnder(i.mountpoint)
				if err != nil || mounted {
					return failed()
				}
			}
			i.server.Wait()
			if i.mountpoint != "" {
				mounted, err := storage.HasMountsUnder(i.mountpoint)
				if err != nil || mounted {
					return failed()
				}
			}
			i.server = nil
		}
		if i.root.CloseParent() != nil {
			return failed()
		}
		if i.runtime != nil {
			if i.runtime.release() != nil {
				return failed()
			}
		}
		i.completed.Store(true)
		i.cleanup.Store(false)
		return Result{Message: "Veyl is unmounted; encrypted storage cleanup confirmed."}
	}
	i.cleanup.Store(false)
	i.broker.Resume()
	return Result{Message: "Session locked; encrypted storage cleanup confirmed."}
}
func authResult(err error) Result {
	switch {
	case err == nil:
		return Result{Message: "Session unlocked."}
	case errors.Is(err, auth.ErrInvalidCredentials):
		return Result{Code: 4, Message: "Incorrect password. Directory remains locked."}
	case errors.Is(err, auth.ErrCanceled) || errors.Is(err, auth.ErrDenied) || errors.Is(err, context.Canceled):
		return Result{Code: 4, Message: "Authentication canceled. Directory remains locked."}
	case errors.Is(err, auth.ErrStale) || errors.Is(err, context.DeadlineExceeded):
		return Result{Code: 4, Message: "Authentication expired. Directory remains locked; retry unlock."}
	case errors.Is(err, auth.ErrCleanup) || errors.Is(err, storage.ErrCleanup):
		return Result{Code: 5, Message: errCleanupPending.Error()}
	case errors.Is(err, auth.ErrUnavailable):
		return Result{Code: 1, Message: "Authentication is unavailable. Check pinentry or use veyl unlock --config FILE --tty. If cleanup is pending, retry lock first."}
	default:
		return Result{Code: 1, Message: "Authentication failed. Directory remains locked; check veyl status and retry unlock."}
	}
}
