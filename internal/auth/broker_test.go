package auth

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/poizdev/veyl/internal/policy"
)

type agentFunc func(context.Context, Request) (Response, error)

func (f agentFunc) Authenticate(ctx context.Context, req Request) (Response, error) {
	return f(ctx, req)
}

type verifierFunc func(context.Context, Request, Response) (bool, error)

func (f verifierFunc) Verify(ctx context.Context, req Request, resp Response) (bool, error) {
	return f(ctx, req, resp)
}

func approve(_ context.Context, req Request) (Response, error) {
	return Response{RequestID: req.ID, Approved: true, Proof: []byte("mock-proof")}, nil
}
func verifyMock(_ context.Context, req Request, resp Response) (bool, error) {
	return req.Directory == policy.GhostName && string(resp.Proof) == "mock-proof", nil
}
func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("request stalled/deadlocked")
		var zero T
		return zero
	}
}
func waitFor(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !predicate() {
		if time.Now().After(deadline) {
			t.Fatal("lifecycle barrier not reached")
		}
		runtime.Gosched()
	}
}
func waiters(t *testing.T, b *Broker, count int) {
	t.Helper()
	waitFor(t, func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.pending != nil && len(b.pending.waiters) == count
	})
}
func retired(t *testing.T, b *Broker) {
	t.Helper()
	waitFor(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.running == nil })
}

func TestAccepted(t *testing.T) {
	var state policy.State
	var agents, verifiers atomic.Int64
	b := New(&state, agentFunc(func(ctx context.Context, req Request) (Response, error) { agents.Add(1); return approve(ctx, req) }),
		verifierFunc(func(ctx context.Context, req Request, resp Response) (bool, error) {
			verifiers.Add(1)
			return verifyMock(ctx, req, resp)
		}), time.Second)
	if err := b.RequestAccess(context.Background()); err != nil {
		t.Fatalf("approved/verified request: %v", err)
	}
	if state.IsLocked() || agents.Load() != 1 || verifiers.Load() != 1 {
		t.Fatal("request did not verify and authorize")
	}
	if err := b.RequestAccess(context.Background()); err != nil || agents.Load() != 1 {
		t.Fatal("unlocked access requested authentication again")
	}
}

func TestDeniedAndUnverified(t *testing.T) {
	for _, approved := range []bool{false, true} {
		t.Run(fmt.Sprint(approved), func(t *testing.T) {
			var state policy.State
			var checks atomic.Int64
			b := New(&state, agentFunc(func(_ context.Context, req Request) (Response, error) {
				return Response{RequestID: req.ID, Approved: approved}, nil
			}),
				verifierFunc(func(context.Context, Request, Response) (bool, error) { checks.Add(1); return false, nil }), time.Second)
			if err := b.RequestAccess(context.Background()); !errors.Is(err, ErrDenied) || !state.IsLocked() {
				t.Fatalf("denial: %v", err)
			}
			if checks.Load() != map[bool]int64{false: 0, true: 1}[approved] {
				t.Fatal("incorrect verification flow")
			}
		})
	}
}

func TestConcurrentDeduplicationAndCallerCancellation(t *testing.T) {
	var state policy.State
	var calls atomic.Int64
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	finish := func() { releaseOnce.Do(func() { close(release) }) }
	defer finish()
	b := New(&state, agentFunc(func(ctx context.Context, req Request) (Response, error) {
		calls.Add(1)
		close(entered)
		select {
		case <-release:
			return approve(ctx, req)
		case <-ctx.Done():
			return Response{}, ctx.Err()
		}
	}), verifierFunc(verifyMock), time.Second)
	canceled, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan error, 1)
	go func() { first <- b.RequestAccess(canceled) }()
	receive(t, entered)
	const others = 8
	results := make(chan error, others)
	for range others {
		go func() { results <- b.RequestAccess(context.Background()) }()
	}
	waiters(t, b, others+1)
	cancel()
	if err := receive(t, first); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	waiters(t, b, others)
	// The shared attempt must outlive cancellation of its original caller.
	b.mu.Lock()
	pending := b.pending
	b.mu.Unlock()
	// Use the shared context's independent lifetime to verify the canceled leader
	// did not cancel the other callers.
	if pending.ctx.Err() != nil {
		t.Fatal("leader cancellation canceled shared attempt")
	}
	finish()
	for range others {
		if err := receive(t, results); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 || state.IsLocked() {
		t.Fatal("requests were not coalesced")
	}
}

func TestLastCancellationRejectsLateApproval(t *testing.T) {
	var state policy.State
	entered := make(chan struct{})
	release := make(chan struct{})
	b := New(&state, agentFunc(func(ctx context.Context, req Request) (Response, error) {
		close(entered)
		<-release
		return approve(ctx, req)
	}), verifierFunc(verifyMock), time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- b.RequestAccess(ctx) }()
	receive(t, entered)
	cancel()
	if err := receive(t, result); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(release)
	retired(t, b)
	if !state.IsLocked() {
		t.Fatal("canceled response unlocked state")
	}
}

func TestTimeoutBoundsUncooperativeAgent(t *testing.T) {
	var state policy.State
	var calls atomic.Int64
	release := make(chan struct{})
	b := New(&state, agentFunc(func(ctx context.Context, req Request) (Response, error) {
		calls.Add(1)
		<-release
		return approve(ctx, req)
	}), verifierFunc(verifyMock), 20*time.Millisecond)
	result := make(chan error, 1)
	go func() { result <- b.RequestAccess(context.Background()) }()
	if err := receive(t, result); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout: %v", err)
	}
	if err := b.RequestAccess(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unbounded retry worker: %v", err)
	}
	close(release)
	retired(t, b)
	if !state.IsLocked() || calls.Load() != 1 {
		t.Fatal("late timed-out approval accepted")
	}
}

func TestUnavailableAndFailures(t *testing.T) {
	for _, tc := range []struct {
		name     string
		agent    Agent
		verifier Verifier
		want     error
	}{
		{"missing agent", nil, verifierFunc(verifyMock), ErrUnavailable},
		{"missing verifier", agentFunc(approve), nil, ErrUnavailable},
		{"agent error", agentFunc(func(context.Context, Request) (Response, error) { return Response{}, errors.New("credential-secret") }), verifierFunc(verifyMock), ErrFailed},
		{"agent panic", agentFunc(func(context.Context, Request) (Response, error) { panic("credential-secret") }), verifierFunc(verifyMock), ErrFailed},
		{"agent exit", agentFunc(func(context.Context, Request) (Response, error) { runtime.Goexit(); return Response{}, nil }), verifierFunc(verifyMock), ErrFailed},
		{"verifier error", agentFunc(approve), verifierFunc(func(context.Context, Request, Response) (bool, error) { return false, errors.New("credential-secret") }), ErrFailed},
		{"verifier panic", agentFunc(approve), verifierFunc(func(context.Context, Request, Response) (bool, error) { panic("credential-secret") }), ErrFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var state policy.State
			b := New(&state, tc.agent, tc.verifier, time.Second)
			result := make(chan error, 1)
			go func() { result <- b.RequestAccess(context.Background()) }()
			err := receive(t, result)
			if !errors.Is(err, tc.want) || !state.IsLocked() {
				t.Fatalf("failure was not closed: %v", err)
			}
			if strings.Contains(err.Error(), "credential-secret") {
				t.Fatal("backend details exposed")
			}
		})
	}
}

func TestLockInvalidatesPendingAuthentication(t *testing.T) {
	for _, cycle := range []bool{false, true} {
		t.Run(fmt.Sprint(cycle), func(t *testing.T) {
			var state policy.State
			entered := make(chan struct{})
			release := make(chan struct{})
			b := New(&state, agentFunc(func(ctx context.Context, req Request) (Response, error) {
				close(entered)
				<-release
				return approve(ctx, req)
			}), verifierFunc(verifyMock), time.Second)
			result := make(chan error, 1)
			go func() { result <- b.RequestAccess(context.Background()) }()
			receive(t, entered)
			locked := make(chan struct{})
			go func() {
				if cycle {
					state.Unlock()
				}
				state.Lock()
				close(locked)
			}()
			receive(t, locked) // Authentication waits without holding an FS lease/transition.
			close(release)
			if err := receive(t, result); !errors.Is(err, ErrStale) || !state.IsLocked() {
				t.Fatalf("stale grant: %v", err)
			}
		})
	}
}

func TestMismatchedResponseRejected(t *testing.T) {
	var state policy.State
	var old uint64
	var calls int
	b := New(&state, agentFunc(func(_ context.Context, req Request) (Response, error) {
		calls++
		if calls == 1 {
			old = req.ID
			return Response{RequestID: req.ID}, nil
		}
		return Response{RequestID: old, Approved: true, Proof: []byte("mock-proof")}, nil
	}), verifierFunc(verifyMock), time.Second)
	if err := b.RequestAccess(context.Background()); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	if err := b.RequestAccess(context.Background()); !errors.Is(err, ErrStale) || !state.IsLocked() {
		t.Fatalf("replayed response: %v", err)
	}
}

func TestRecursiveRequestRejected(t *testing.T) {
	var state policy.State
	var b *Broker
	recursive := make(chan error, 1)
	b = New(&state, agentFunc(func(ctx context.Context, _ Request) (Response, error) {
		err := b.RequestAccess(ctx)
		recursive <- err
		return Response{}, err
	}), verifierFunc(verifyMock), time.Second)
	if err := b.RequestAccess(context.Background()); !errors.Is(err, ErrFailed) {
		t.Fatal(err)
	}
	if err := receive(t, recursive); !errors.Is(err, ErrRecursive) || !state.IsLocked() {
		t.Fatalf("recursion: %v", err)
	}
}

func TestAuthenticationDoesNotWaitForDrain(t *testing.T) {
	var state policy.State
	state.Unlock()
	token, _ := state.Session()
	release, ok := state.Begin(token)
	if !ok {
		t.Fatal("lease failed")
	}
	var once sync.Once
	finish := func() { once.Do(release) }
	defer finish()
	done := make(chan struct{})
	go func() { state.Lock(); close(done) }()
	waitFor(t, state.IsLocked)
	var calls atomic.Int64
	b := New(&state, agentFunc(func(ctx context.Context, req Request) (Response, error) { calls.Add(1); return approve(ctx, req) }), verifierFunc(verifyMock), time.Second)
	result := make(chan error, 1)
	go func() { result <- b.RequestAccess(context.Background()) }()
	if err := receive(t, result); !errors.Is(err, ErrStale) || calls.Load() != 0 {
		t.Fatalf("draining state: %v", err)
	}
	// release is consumed exactly once despite cleanup.
	finish()
	receive(t, done)
}

func TestCancellationBeforeRequestAndInvalidConfiguration(t *testing.T) {
	var state policy.State
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls atomic.Int64
	agent := agentFunc(func(ctx context.Context, req Request) (Response, error) { calls.Add(1); return approve(ctx, req) })
	b := New(&state, agent, verifierFunc(verifyMock), time.Second)
	if err := b.RequestAccess(ctx); !errors.Is(err, context.Canceled) || calls.Load() != 0 {
		t.Fatal("canceled request started agent")
	}
	for _, invalid := range []*Broker{nil, New(nil, agent, verifierFunc(verifyMock), time.Second), New(&state, agent, verifierFunc(verifyMock), 0)} {
		if err := invalid.RequestAccess(context.Background()); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("invalid configuration: %v", err)
		}
	}
}

func TestLateVerifierCannotAuthorizeAfterTimeout(t *testing.T) {
	var state policy.State
	entered := make(chan struct{})
	release := make(chan struct{})
	b := New(&state, agentFunc(approve), verifierFunc(func(context.Context, Request, Response) (bool, error) { close(entered); <-release; return true, nil }), 50*time.Millisecond)
	result := make(chan error, 1)
	go func() { result <- b.RequestAccess(context.Background()) }()
	receive(t, entered)
	if err := receive(t, result); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	close(release)
	retired(t, b)
	if !state.IsLocked() {
		t.Fatal("late verifier unlocked state")
	}
}

func TestConcurrentFastApproval(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	for range 30 {
		var state policy.State
		var calls atomic.Int64
		b := New(&state, agentFunc(func(ctx context.Context, req Request) (Response, error) { calls.Add(1); return approve(ctx, req) }), verifierFunc(verifyMock), time.Second)
		start := make(chan struct{})
		results := make(chan error, 32)
		for range 32 {
			go func() { <-start; results <- b.RequestAccess(context.Background()) }()
		}
		close(start)
		for range 32 {
			if err := receive(t, results); err != nil {
				t.Fatalf("concurrent completed approval denied: %v", err)
			}
		}
		if calls.Load() != 1 {
			t.Fatalf("duplicate agent calls: %d", calls.Load())
		}
	}
}

func TestAuthenticationDuringTransitionContention(t *testing.T) {
	var state policy.State
	entered := make(chan struct{})
	release := make(chan struct{})
	b := New(&state, agentFunc(func(ctx context.Context, req Request) (Response, error) {
		close(entered)
		<-release
		return approve(ctx, req)
	}), verifierFunc(verifyMock), 5*time.Second)
	result := make(chan error, 1)
	go func() { result <- b.RequestAccess(context.Background()) }()
	receive(t, entered)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				state.Lock()
				state.Unlock()
			}
		})
	}
	transitions := make(chan struct{})
	go func() { wg.Wait(); state.Lock(); close(transitions) }()
	receive(t, transitions)
	close(release)
	if err := receive(t, result); !errors.Is(err, ErrStale) || !state.IsLocked() {
		t.Fatalf("contended stale response: %v", err)
	}
}

func TestRequestIDsNeverWrap(t *testing.T) {
	var state policy.State
	var calls atomic.Int64
	b := New(&state, agentFunc(func(ctx context.Context, req Request) (Response, error) { calls.Add(1); return approve(ctx, req) }), verifierFunc(verifyMock), time.Second)
	b.nextID = ^uint64(0)
	if err := b.RequestAccess(context.Background()); !errors.Is(err, ErrUnavailable) || calls.Load() != 0 || !state.IsLocked() {
		t.Fatal("request ID space reused")
	}
}
