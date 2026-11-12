//go:build linux

package storage

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/poizdev/veyl/internal/policy"
)

var ErrAdopted = errors.New("storage candidate already adopted")

// Candidate owns a verified view from preparation through confirmed cleanup.
// The backend retains this record on failure even if its caller drops it.
// Filesystem access requires SessionRoot, not View.Path. Do not copy it.
type Candidate struct {
	backend     *Backend
	ticket      policy.Challenge
	attempt     context.Context
	life        context.Context
	cancel      context.CancelFunc
	stopAttempt func() bool
	mount       *mount // assigned during serialized startup, immutable after publication
	owned       atomic.Bool
	mu          sync.Mutex
	phase       uint8 // 0 prepared, 1 adopted, 2 rejected/closed
	failed      bool
	epoch       uint64
}

// Prepare separates request cancellation from the eventual session lifetime.
// A nonnil candidate with an error means cleanup is incomplete: retain/retry it.
func (b *Backend) Prepare(ctx context.Context, ticket policy.Challenge, password []byte) (*Candidate, error) {
	life, cancel := context.WithCancel(context.Background())
	c := &Candidate{backend: b, ticket: ticket, attempt: ctx, life: life, cancel: cancel}
	c.stopAttempt = context.AfterFunc(ctx, func() {
		c.mu.Lock()
		if c.phase == 0 {
			c.cancel()
		}
		c.mu.Unlock()
	})
	if err := b.acquire(ctx); err != nil {
		c.stopAttempt()
		cancel()
		return nil, err
	}
	if !live(ctx) {
		b.unlock()
		c.stopAttempt()
		cancel()
		err := ctx.Err()
		if err == nil {
			err = context.DeadlineExceeded
		}
		return nil, err
	}
	_, err := b.mount(life, ctx, ticket, password, c)
	b.unlock()
	if err == nil && !live(ctx) {
		err = ctx.Err()
		if err == nil {
			err = context.DeadlineExceeded
		}
	}
	if err != nil {
		cleanup := c.Rollback()
		if cleanup != nil {
			return c, errors.Join(err, cleanup)
		}
		return nil, err
	}
	return c, nil
}

func live(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	deadline, ok := ctx.Deadline()
	return !ok || time.Now().Before(deadline)
}

// Commit's final liveness observation under policy's transition lock is the
// adoption linearization point. valid checks broker waiters without blocking.
// Cancellation observed before it wins; cancellation after adoption cannot undo
// a completed grant. Lock is the explicit session revocation operation.
func (c *Candidate) Commit(valid func() bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.phase != 0 || c.failed || !c.owned.Load() || valid == nil {
		return false
	}
	epoch, ok := c.backend.state.Adopt(c.ticket, func() bool {
		if !valid() {
			return false
		}
		// Observe lifetimes after the caller's guard: cancellation or shutdown
		// during that callback must reject adoption too.
		if c.backend.lifetime.Err() != nil || c.life.Err() != nil || !live(c.attempt) {
			return false
		}
		select {
		case <-c.mount.process.Exited():
			return false
		default:
		}
		return true
	}, c.cancel)
	if !ok {
		return false
	}
	c.epoch = epoch
	c.phase = 1
	c.stopAttempt()
	// Cancellation only schedules teardown; no external wait occurs under policy.
	context.AfterFunc(c.life, func() { _ = c.Close() })
	return true
}

// Rollback rejects an unadopted candidate and waits for its cleanup result.
// It cannot tear down an adopted session; use Close for explicit revocation.
func (c *Candidate) Rollback() error {
	c.mu.Lock()
	if c.phase == 1 {
		c.mu.Unlock()
		return ErrAdopted
	}
	c.phase = 2
	c.stopAttempt()
	c.cancel()
	c.mu.Unlock()
	return c.release()
}

// Close revokes this epoch before waiting for external teardown. Failed teardown
// retains ownership and may be retried by Close or Backend.Unmount/Close.
func (c *Candidate) Close() error {
	c.mu.Lock()
	c.phase = 2
	epoch := c.epoch
	c.stopAttempt()
	c.mu.Unlock()
	c.backend.state.Revoke(epoch)
	c.cancel()
	return c.release()
}
func (c *Candidate) release() error {
	b := c.backend
	<-b.gate
	defer b.unlock()
	if b.active == nil || b.active.owner != c {
		return nil
	}
	return b.cleanup(b.active, nil)
}
func (c *Candidate) Owned() bool { return c.owned.Load() }

// View exposes lifecycle metadata and the isolated backing mount path.
// It does not authorize filesystem access; use SessionRoot for session checks.
func (c *Candidate) View() *View { return c.mount.view }

// Retained returns the owner of a transactional view, including cleanup residue.
// Direct Mount views remain owned by Backend and return nil here.
func (b *Backend) Retained() *Candidate {
	<-b.gate
	defer b.unlock()
	if b.active == nil {
		return nil
	}
	return b.active.owner
}

// lost is called before any external cleanup wait. Commit and loss serialize on
// the candidate mutex. Revoke is epoch conditional, so delayed loss is harmless
// to any later session. No caller holds the candidate mutex while taking gate.
func (b *Backend) lost(m *mount) {
	if m.owner == nil {
		return
	}
	c := m.owner
	c.mu.Lock()
	c.failed = true
	epoch := c.epoch
	c.mu.Unlock()
	b.state.Revoke(epoch)
}
