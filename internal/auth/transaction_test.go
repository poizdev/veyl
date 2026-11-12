package auth

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/poizdev/veyl/internal/policy"
)

// This dependency double models an external resource, not credential validity.
// End-to-end storage tests exercise real mount ownership separately.
type preparedResource struct {
	state      *policy.State
	ticket     policy.Challenge
	ctx        context.Context
	canceled   context.CancelFunc
	rolled     atomic.Bool
	committed  atomic.Bool
	cleanupErr error
}

func (p *preparedResource) Commit(valid func() bool) bool {
	_, ok := p.state.Adopt(p.ticket, func() bool { return p.ctx.Err() == nil && valid() }, p.canceled)
	if ok {
		p.committed.Store(true)
	}
	return ok
}
func (p *preparedResource) Rollback() error { p.rolled.Store(true); return p.cleanupErr }

func TestTransactionalBrokerAdoptsAndDeduplicates(t *testing.T) {
	var s policy.State
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int64
	var prepared *preparedResource
	session, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := NewTransactional(&s, agentFunc(approve), func(ctx context.Context, ticket policy.Challenge, _ Response) (Transaction, error) {
		calls.Add(1)
		prepared = &preparedResource{state: &s, ticket: ticket, ctx: ctx, canceled: cancel}
		close(entered)
		<-release
		return prepared, nil
	}, time.Second)
	results := make(chan error, 8)
	for range 8 {
		go func() { results <- b.RequestAccess(context.Background()) }()
	}
	receive(t, entered)
	waiters(t, b, 8)
	close(release)
	for range 8 {
		if err := receive(t, results); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 || !prepared.committed.Load() || prepared.rolled.Load() {
		t.Fatal("bad resource transfer")
	}
	select {
	case <-session.Done():
		t.Fatal("attempt completion canceled session")
	default:
	}
	s.Lock()
	receive(t, session.Done())
}
func TestTransactionalBrokerRejectedResourceRollback(t *testing.T) {
	for _, kind := range []string{"lock", "cancel", "timeout", "prepare error"} {
		t.Run(kind, func(t *testing.T) {
			var s policy.State
			entered, release := make(chan struct{}), make(chan struct{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := &preparedResource{state: &s, canceled: func() {}}
			timeout := time.Second
			if kind == "timeout" {
				timeout = 25 * time.Millisecond
			}
			b := NewTransactional(&s, agentFunc(approve), func(ctx context.Context, ticket policy.Challenge, _ Response) (Transaction, error) {
				p.ticket = ticket
				p.ctx = ctx
				close(entered)
				<-release
				if kind == "prepare error" {
					return p, errors.New("backend error")
				}
				return p, nil
			}, timeout)
			result := make(chan error, 1)
			go func() { result <- b.RequestAccess(ctx) }()
			receive(t, entered)
			switch kind {
			case "lock":
				s.Lock()
			case "cancel":
				cancel()
			case "timeout":
				receive(t, p.ctx.Done())
			}
			close(release)
			if err := receive(t, result); err == nil {
				t.Fatal("invalid resource adopted")
			}
			retired(t, b)
			if !p.rolled.Load() || p.committed.Load() || !s.IsLocked() {
				t.Fatal("rejected resource leaked")
			}
		})
	}
}
func TestTransactionalBrokerDeniedNeverPrepares(t *testing.T) {
	var s policy.State
	b := NewTransactional(&s, agentFunc(func(_ context.Context, r Request) (Response, error) { return Response{RequestID: r.ID}, nil }), func(context.Context, policy.Challenge, Response) (Transaction, error) {
		t.Error("denied attempt prepared")
		return nil, nil
	}, time.Second)
	if err := b.RequestAccess(context.Background()); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
}
func TestTransactionalBrokerRetainsCleanupFailure(t *testing.T) {
	var s policy.State
	cleanupErr := errors.New("incomplete cleanup")
	p := &preparedResource{state: &s, canceled: func() {}, cleanupErr: cleanupErr}
	b := NewTransactional(&s, agentFunc(approve), func(ctx context.Context, ticket policy.Challenge, _ Response) (Transaction, error) {
		p.ctx = ctx
		p.ticket = ticket
		s.Lock()
		return p, nil
	}, time.Second)
	if err := b.RequestAccess(context.Background()); !errors.Is(err, cleanupErr) {
		t.Fatalf("cleanup not reported: %v", err)
	}
	if b.CleanupError() == nil {
		t.Fatal("cleanup failure not observable")
	}
	if err := b.RequestAccess(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cleanup failure allowed new flight: %v", err)
	}
}
func TestTransactionalCommitChecksLastWaiterAtAdoption(t *testing.T) {
	var s policy.State
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	p := &guardedResource{entered: entered, release: release, cancel: cancel}
	b := NewTransactional(&s, agentFunc(approve), func(context.Context, policy.Challenge, Response) (Transaction, error) { return p, nil }, time.Second)
	result := make(chan error, 1)
	go func() { result <- b.RequestAccess(ctx) }()
	receive(t, entered)
	// Commit is entered while broker.mu is held. Cancellation must be observed
	// by its final guard even before leave can acquire broker.mu.
	cancel()
	close(release)
	if err := receive(t, result); err == nil {
		t.Fatal("canceled requester succeeded")
	}
	retired(t, b)
	if p.adopted.Load() || !p.rolled.Load() {
		t.Fatal("last waiter canceled before adoption")
	}
}

type guardedResource struct {
	entered, release chan struct{}
	cancel           context.CancelFunc
	adopted, rolled  atomic.Bool
	once             sync.Once
}

func (p *guardedResource) Commit(valid func() bool) bool {
	p.once.Do(func() { close(p.entered) })
	<-p.release
	ok := valid()
	p.adopted.Store(ok)
	return ok
}
func (p *guardedResource) Rollback() error { p.rolled.Store(true); return nil }

func TestTransactionalCallbacksGoexitRetireAndRetain(t *testing.T) {
	for _, mode := range []string{"commit", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			var s policy.State
			p := &exitingTransaction{mode: mode}
			b := NewTransactional(&s, agentFunc(approve), func(context.Context, policy.Challenge, Response) (Transaction, error) { return p, nil }, time.Second)
			if err := b.RequestAccess(context.Background()); err == nil {
				t.Fatal("Goexit authorized")
			}
			retired(t, b)
			if !p.rolled.Load() {
				t.Fatal("Goexit skipped rollback")
			}
			if mode == "rollback" && b.CleanupError() == nil {
				t.Fatal("aborted rollback lost ownership")
			}
		})
	}
}

type exitingTransaction struct {
	mode   string
	rolled atomic.Bool
}

func (p *exitingTransaction) Commit(func() bool) bool {
	if p.mode == "commit" {
		runtime.Goexit()
	}
	return false
}
func (p *exitingTransaction) Rollback() error {
	p.rolled.Store(true)
	if p.mode == "rollback" {
		runtime.Goexit()
	}
	return nil
}
