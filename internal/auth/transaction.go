package auth

import (
	"context"
	"errors"
	"time"

	"github.com/poizdev/veyl/internal/policy"
)

// Transaction owns an external verification resource. Commit must atomically
// validate policy and invoke valid immediately before adoption; it must be short
// and must not reenter Broker. Rollback may wait for external cleanup and must
// retain ownership on error. A successful Commit transfers ownership to a session.
type Transaction interface {
	Commit(valid func() bool) bool
	Rollback() error
}
type PrepareFunc func(context.Context, policy.Challenge, Response) (Transaction, error)

// NewTransactional preserves the shared authentication flight but replaces the
// boolean verifier with explicit preparation and atomic resource adoption.
// Prepare must return its candidate even on error if cleanup remains incomplete.
func NewTransactional(state *policy.State, agent Agent, prepare PrepareFunc, timeout time.Duration) *Broker {
	b := New(state, agent, nil, timeout)
	b.prepare = prepare
	return b
}

func contextLive(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	deadline, ok := ctx.Deadline()
	return !ok || time.Now().Before(deadline)
}
func (b *Broker) live(f *flight) bool {
	if b.suspended || b.pending != f || !contextLive(f.ctx) {
		return false
	}
	for w := range f.waiters {
		if contextLive(w.ctx) {
			return true
		}
	}
	return false
}

func (b *Broker) complete(f *flight, resource Transaction, accepted bool, outcome error) {
	adopted := false
	cleanupFinished := false
	// The outer finalizer also runs when Commit or Rollback calls Goexit.
	// Register it before rollback so an aborted cleanup cannot skip retirement.
	defer func() {
		if recover() != nil {
			outcome = errors.Join(outcome, ErrFailed)
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if resource != nil && !adopted && !cleanupFinished {
			b.cleanup, b.cleanupErr = resource, ErrCleanup
			outcome = errors.Join(outcome, ErrCleanup)
		}
		if b.running == f {
			b.running = nil
		}
		close(f.retired)
		if b.pending != f {
			return
		}
		if !contextLive(f.ctx) {
			err := f.ctx.Err()
			if err == nil {
				err = context.DeadlineExceeded
			}
			b.finishLocked(f, err)
			return
		}
		if !adopted && !b.live(f) {
			outcome = context.Canceled
		}
		b.finishLocked(f, outcome)
	}()
	defer func() {
		if resource == nil || adopted {
			return
		}
		cleanupErr := rollback(resource)
		cleanupFinished = true
		if cleanupErr != nil {
			b.mu.Lock()
			b.cleanup, b.cleanupErr = resource, cleanupErr
			b.mu.Unlock()
			outcome = errors.Join(outcome, cleanupErr)
		}
	}()
	// All external waits occur after this short ownership decision releases mu.
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.live(f) && accepted {
		if resource != nil {
			adopted = resource.Commit(func() bool { return b.live(f) })
		} else {
			adopted = b.state.Authorize(f.ticket)
		}
		if adopted {
			outcome = nil
		} else {
			outcome = ErrStale
		}
	}
}

func rollback(resource Transaction) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrCleanup
		}
	}()
	return resource.Rollback()
}

// ErrCleanup includes panicking cleanup implementations without exposing details.
var ErrCleanup = errors.New("authentication resource cleanup incomplete")

// CleanupError remains observable even when cancellation already returned to the
// requester. A nonnil error blocks further attempts until RetryCleanup succeeds.
func (b *Broker) CleanupError() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cleanupErr
}
func (b *Broker) RetryCleanup() error {
	b.cleanupMu.Lock()
	defer b.cleanupMu.Unlock()
	b.mu.Lock()
	resource := b.cleanup
	b.mu.Unlock()
	if resource == nil {
		return nil
	}
	err := rollback(resource)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cleanupErr = err
	if err == nil {
		b.cleanup = nil
	}
	return err
}
