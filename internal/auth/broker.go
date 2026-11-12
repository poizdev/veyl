// Package auth coordinates credential collection and verification for one
// protected directory, including transactional adoption of verified resources.
package auth

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/poizdev/veyl/internal/policy"
)

var (
	ErrDenied             = errors.New("authentication denied")
	ErrUnavailable        = errors.New("authentication unavailable")
	ErrCanceled           = errors.New("authentication canceled")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrFailed             = errors.New("authentication failed")
	ErrStale              = errors.New("authentication request expired")
	ErrRecursive          = errors.New("recursive authentication denied")
)

// IDs correlate responses; they are not secrets or cryptographic authenticators.
type Request struct {
	ID        uint64
	Directory string
}

// Proof is opaque verifier input. Never log it or include it in errors. Its
// returned slice remains agent-owned. Broker copies it for verification and
// clears that owned copy after use; backends must manage any other copies.
type Response struct {
	RequestID uint64
	Approved  bool
	Proof     []byte
}
type Agent interface {
	Authenticate(context.Context, Request) (Response, error)
}
type Verifier interface {
	Verify(context.Context, Request, Response) (bool, error)
}

// Status is an in-memory snapshot of broker work and access suspension.
type Status struct {
	Authenticating bool
	Cleanup        bool
	Suspended      bool
}

type recursiveKey struct{}
type waiter struct{ ctx context.Context }
type flight struct {
	agent   Agent
	request Request
	ticket  policy.Challenge
	ctx     context.Context
	cancel  context.CancelFunc
	stop    func() bool
	waiters map[*waiter]struct{}
	done    chan struct{}
	retired chan struct{}
	err     error
}

// Broker is configured once before use and must not be copied. One instance
// serves one root's protected directory. A stuck backend keeps it unavailable rather
// than allowing an unbounded number of detached authentication goroutines.
type Broker struct {
	state      *policy.State
	agent      Agent
	verifier   Verifier
	prepare    PrepareFunc
	cleanup    Transaction
	cleanupErr error
	cleanupMu  sync.Mutex
	timeout    time.Duration
	mu         sync.Mutex
	nextID     uint64
	pending    *flight
	running    *flight
	suspended  bool
	permanent  bool
}

func New(state *policy.State, agent Agent, verifier Verifier, timeout time.Duration) *Broker {
	return &Broker{state: state, agent: agent, verifier: verifier, timeout: timeout}
}

// RequestAccess joins one shared attempt. Canceling a caller detaches only that
// caller; the last caller cancels the attempt. Backend calls hold no broker or
// filesystem authorization locks. Cancellation racing a committed grant cannot
// retroactively revoke the session; Lock is the explicit revocation operation.
func (b *Broker) RequestAccess(ctx context.Context) error {
	var agent Agent
	if b != nil {
		agent = b.agent
	}
	return b.RequestAccessWithAgent(ctx, agent)
}

// RequestAccessWithAgent overrides the agent only when starting a flight. Every
// caller joining an existing flight shares the first caller's agent.
func (b *Broker) RequestAccessWithAgent(ctx context.Context, agent Agent) error {
	if ctx.Value(recursiveKey{}) != nil {
		return ErrRecursive
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if b == nil || b.state == nil {
		return ErrUnavailable
	}
	b.mu.Lock()
	if b.suspended {
		b.mu.Unlock()
		return ErrUnavailable
	}
	// Unlocked access needs no agent, but suspension always takes precedence.
	if !b.state.IsLocked() {
		b.mu.Unlock()
		return nil
	}
	if (b.verifier == nil && b.prepare == nil) || b.timeout <= 0 {
		b.mu.Unlock()
		return ErrUnavailable
	}
	if b.cleanup != nil {
		b.mu.Unlock()
		return ErrUnavailable
	}
	f := b.pending
	if f != nil && f.ctx.Err() != nil {
		b.finishLocked(f, f.ctx.Err())
		f = nil
	}
	if f == nil {
		if agent == nil || b.running != nil || b.nextID == ^uint64(0) {
			b.mu.Unlock()
			return ErrUnavailable
		}
		ticket, ok := b.state.Challenge()
		if !ok {
			b.mu.Unlock()
			return ErrStale
		}
		b.nextID++
		shared, cancel := context.WithTimeout(context.WithValue(context.Background(), recursiveKey{}, true), b.timeout)
		f = &flight{agent: agent, request: Request{ID: b.nextID, Directory: policy.GhostName}, ticket: ticket,
			ctx: shared, cancel: cancel, waiters: make(map[*waiter]struct{}), done: make(chan struct{}), retired: make(chan struct{})}
		b.pending, b.running = f, f
		f.stop = context.AfterFunc(shared, func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			b.finishLocked(f, shared.Err())
		})
		go b.run(f)
	}
	w := &waiter{ctx: ctx}
	f.waiters[w] = struct{}{}
	b.mu.Unlock()
	defer b.leave(f, w)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-f.done:
		if err := ctx.Err(); err != nil {
			return err
		}
		return f.err // close(done) publishes the immutable result.
	}
}

// Suspend prevents new access, including requests for an unlocked state, and
// cancels any pending attempt. It does not wait for backend work or rollback.
func (b *Broker) Suspend(permanent bool) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.suspended = true
	b.permanent = b.permanent || permanent
	if b.pending != nil {
		b.finishLocked(b.pending, ErrCanceled)
	}
}

// Resume lifts temporary suspension. Permanent suspension cannot be reversed.
func (b *Broker) Resume() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.permanent {
		b.suspended = false
	}
}

// WaitIdle waits outside the broker mutex until workers and their rollback have
// retired. Suspension can prevent a new caller from starting another worker.
func (b *Broker) WaitIdle(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if b == nil {
			return nil
		}
		b.mu.Lock()
		f := b.running
		b.mu.Unlock()
		if f == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-f.retired:
		}
	}
}

// Snapshot reads only broker memory and never waits on backend or filesystem
// work. Authenticating remains true until the worker's rollback has retired.
func (b *Broker) Snapshot() Status {
	if b == nil {
		return Status{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return Status{Authenticating: b.running != nil, Cleanup: b.cleanup != nil, Suspended: b.suspended}
}

func (b *Broker) leave(f *flight, w *waiter) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(f.waiters, w)
	if len(f.waiters) == 0 {
		b.finishLocked(f, context.Canceled)
	}
}

// finishLocked never grants access. Retire running only when backend execution
// actually exits; cancellation cannot kill an uncooperative Go goroutine.
func (b *Broker) finishLocked(f *flight, err error) {
	if b.pending != f {
		return
	}
	f.err = err
	b.pending = nil
	if f.stop != nil {
		f.stop()
	}
	f.cancel()
	close(f.done)
}

func (b *Broker) run(f *flight) {
	outcome := ErrFailed
	accepted := false
	var resource Transaction
	// Fail closed on panic/Goexit. Rollback executes outside broker and policy
	// locks. Keep the running slot until cleanup has returned.
	defer func() {
		if recover() != nil {
			outcome, accepted = ErrFailed, false
		}
		b.complete(f, resource, accepted, outcome)
	}()

	if f.ctx.Err() != nil {
		return
	}
	response, err := f.agent.Authenticate(f.ctx, f.request)
	response.Proof = append([]byte(nil), response.Proof...)
	defer clear(response.Proof)
	if err != nil {
		outcome = safeError(err)
		return
	}
	if f.ctx.Err() != nil {
		return
	}
	if response.RequestID != f.request.ID {
		outcome = ErrStale
		return
	}
	if !response.Approved {
		outcome = ErrDenied
		return
	}
	if b.prepare != nil {
		resource, err = b.prepare(f.ctx, f.ticket, response)
		if err != nil {
			outcome = safeError(err)
			return
		}
		accepted = resource != nil
		return
	}
	verified, err := b.verifier.Verify(f.ctx, f.request, response)
	if err != nil {
		outcome = safeError(err)
		return
	}
	if !verified {
		outcome = ErrDenied
		return
	}
	accepted = true
}

// safeError preserves categories without exposing wrapped backend details.
func safeError(err error) error {
	for _, category := range []error{ErrCanceled, ErrInvalidCredentials, ErrUnavailable, ErrDenied, ErrStale, ErrCleanup} {
		if errors.Is(err, category) {
			return category
		}
	}
	if errors.Is(err, context.Canceled) {
		return ErrCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return ErrFailed
}
