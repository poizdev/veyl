package auth

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/poizdev/veyl/internal/policy"
)

type accessOverride interface {
	RequestAccessWithAgent(context.Context, Agent) error
}

func TestOverrideChoosesFirstAgentAndJoinsConfiguredRequest(t *testing.T) {
	for _, withConfiguredAgent := range []bool{false, true} {
		t.Run(map[bool]string{false: "no default", true: "configured default"}[withConfiguredAgent], func(t *testing.T) {
			var state policy.State
			entered, release := make(chan struct{}), make(chan struct{})
			var configuredCalls, otherCalls atomic.Int64
			var configured Agent
			if withConfiguredAgent {
				configured = agentFunc(func(context.Context, Request) (Response, error) {
					configuredCalls.Add(1)
					return Response{}, errors.New("configured agent must not run")
				})
			}
			b := New(&state, configured, verifierFunc(verifyMock), time.Second)
			override, ok := any(b).(accessOverride)
			if !ok {
				t.Fatal("broker does not support per-flight agent override")
			}
			leader := agentFunc(func(ctx context.Context, req Request) (Response, error) {
				close(entered)
				<-release
				return approve(ctx, req)
			})
			other := agentFunc(func(context.Context, Request) (Response, error) {
				otherCalls.Add(1)
				return Response{}, errors.New("joining agent must not run")
			})
			results := make(chan error, 3)
			go func() { results <- override.RequestAccessWithAgent(context.Background(), leader) }()
			receive(t, entered)
			go func() { results <- b.RequestAccess(context.Background()) }()
			go func() { results <- override.RequestAccessWithAgent(context.Background(), other) }()
			waiters(t, b, 3)
			close(release)
			for range 3 {
				if err := receive(t, results); err != nil {
					t.Fatal(err)
				}
			}
			if state.IsLocked() || configuredCalls.Load() != 0 || otherCalls.Load() != 0 {
				t.Fatal("joining caller changed the flight's agent")
			}

		})
	}
}

func TestOverrideWorksWithoutConfiguredAgent(t *testing.T) {
	var state policy.State
	b := New(&state, nil, verifierFunc(verifyMock), time.Second)
	override, ok := any(b).(accessOverride)
	if !ok {
		t.Fatal("broker does not support per-flight agent override")
	}
	if err := override.RequestAccessWithAgent(context.Background(), agentFunc(approve)); err != nil || state.IsLocked() {
		t.Fatalf("override with no configured agent: %v", err)
	}
}

type lifecycle interface {
	Suspend(bool)
	Resume()
	WaitIdle(context.Context) error
}

func lifecycleOf(t *testing.T, b *Broker) lifecycle {
	t.Helper()
	l, ok := any(b).(lifecycle)
	if !ok {
		t.Fatal("broker does not support suspension and worker retirement")
	}
	return l
}

func TestSuspendRejectsLateApprovalWithoutWaiting(t *testing.T) {
	var state policy.State
	entered, release := make(chan struct{}), make(chan struct{})
	b := New(&state, agentFunc(func(ctx context.Context, req Request) (Response, error) {
		close(entered)
		<-release
		return approve(ctx, req)
	}), verifierFunc(verifyMock), time.Second)
	l := lifecycleOf(t, b)
	result := make(chan error, 1)
	go func() { result <- b.RequestAccess(context.Background()) }()
	receive(t, entered)
	suspended := make(chan struct{})
	go func() { l.Suspend(false); close(suspended) }()
	receive(t, suspended)
	if err := receive(t, result); !errors.Is(err, ErrCanceled) {
		t.Fatalf("suspension did not finish pending request safely: %v", err)
	}
	if err := b.RequestAccess(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("suspended request: %v", err)
	}
	close(release)
	if err := l.WaitIdle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !state.IsLocked() {
		t.Fatal("suspended late approval authorized")
	}
	l.Resume()
	if err := b.RequestAccessWithAgent(context.Background(), agentFunc(approve)); err != nil {
		t.Fatalf("temporary suspension did not resume: %v", err)
	}
}

func TestSuspendBlocksUnlockedBypassAndPermanentCannotResume(t *testing.T) {
	for _, permanent := range []bool{false, true} {
		t.Run(map[bool]string{false: "temporary", true: "permanent"}[permanent], func(t *testing.T) {
			var state policy.State
			state.Unlock()
			b := New(&state, nil, nil, 0)
			l := lifecycleOf(t, b)
			l.Suspend(permanent)
			if err := b.RequestAccess(context.Background()); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("unlocked state bypassed suspension: %v", err)
			}
			l.Suspend(false) // A temporary request must never downgrade permanent suspension.
			l.Resume()
			err := b.RequestAccess(context.Background())
			if permanent && !errors.Is(err, ErrUnavailable) {
				t.Fatalf("permanent suspension resumed: %v", err)
			}
			if !permanent && err != nil {
				t.Fatalf("unlocked access remained suspended: %v", err)
			}
		})
	}
}

type blockingRollback struct{ entered, release chan struct{} }

func (*blockingRollback) Commit(func() bool) bool { return false }
func (p *blockingRollback) Rollback() error       { close(p.entered); <-p.release; return nil }

func TestWaitIdleIncludesRollbackAndSupportsCancellation(t *testing.T) {
	var state policy.State
	resource := &blockingRollback{entered: make(chan struct{}), release: make(chan struct{})}
	b := NewTransactional(&state, agentFunc(approve), func(context.Context, policy.Challenge, Response) (Transaction, error) {
		return resource, nil
	}, time.Second)
	l := lifecycleOf(t, b)
	result := make(chan error, 1)
	go func() { result <- b.RequestAccess(context.Background()) }()
	receive(t, resource.entered)
	l.Suspend(false)
	if err := receive(t, result); !errors.Is(err, ErrCanceled) {
		t.Fatalf("suspension waited for rollback or lost cancellation: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := l.WaitIdle(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitIdle returned before rollback retired: %v", err)
	}
	idle := make(chan error, 1)
	go func() { idle <- l.WaitIdle(context.Background()) }()
	close(resource.release)
	if err := receive(t, idle); err != nil {
		t.Fatal(err)
	}
	if err := l.WaitIdle(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestWaitIdleRetiresPanicAndGoexitPaths(t *testing.T) {
	for _, mode := range []string{"agent panic", "agent Goexit", "prepare Goexit", "commit Goexit", "rollback Goexit"} {
		t.Run(mode, func(t *testing.T) {
			var state policy.State
			agent := agentFunc(func(ctx context.Context, req Request) (Response, error) {
				switch mode {
				case "agent panic":
					panic("secret")
				case "agent Goexit":
					runtime.Goexit()
				}
				return approve(ctx, req)
			})
			b := NewTransactional(&state, agent, func(context.Context, policy.Challenge, Response) (Transaction, error) {
				if mode == "prepare Goexit" {
					runtime.Goexit()
				}
				return &exitingTransaction{mode: strings.TrimSuffix(mode, " Goexit")}, nil
			}, time.Second)
			l := lifecycleOf(t, b)
			if err := b.RequestAccess(context.Background()); err == nil {
				t.Fatal("aborted worker succeeded")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := l.WaitIdle(ctx); err != nil {
				t.Fatalf("worker did not retire: %v", err)
			}
			if !state.IsLocked() {
				t.Fatal("aborted worker authorized")
			}
		})
	}
}

func TestAgentErrorCategoriesDiscardPrivateDetails(t *testing.T) {
	for _, tc := range []struct {
		name    string
		backend error
		want    error
		message string
	}{
		{"unavailable", errors.Join(errors.New("credential-secret"), ErrUnavailable), ErrUnavailable, "authentication unavailable"},
		{"denied", errors.Join(errors.New("credential-secret"), ErrDenied), ErrDenied, "authentication denied"},
		{"stale", errors.Join(errors.New("credential-secret"), ErrStale), ErrStale, "authentication request expired"},
		{"agent cancel", errors.Join(errors.New("credential-secret"), context.Canceled), ErrCanceled, "authentication canceled"},
		{"canceled sentinel", errors.Join(errors.New("credential-secret"), ErrCanceled), ErrCanceled, "authentication canceled"},
		{"invalid credentials", errors.Join(errors.New("credential-secret"), ErrInvalidCredentials), ErrInvalidCredentials, "invalid credentials"},
		{"unknown", errors.New("credential-secret"), ErrFailed, "authentication failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var state policy.State
			b := New(&state, agentFunc(func(context.Context, Request) (Response, error) { return Response{}, tc.backend }), verifierFunc(verifyMock), time.Second)
			err := b.RequestAccess(context.Background())
			if err == nil || err.Error() != tc.message || (tc.want != nil && !errors.Is(err, tc.want)) || !state.IsLocked() {
				t.Fatalf("unsafe or lost error category: %v", err)
			}
		})
	}
}

func TestPrepareAndVerifierErrorCategoriesAreSafe(t *testing.T) {
	for _, transactional := range []bool{false, true} {
		t.Run(map[bool]string{false: "verifier", true: "prepare"}[transactional], func(t *testing.T) {
			var state policy.State
			private := errors.Join(ErrInvalidCredentials, errors.New("credential-secret"))
			b := New(&state, agentFunc(approve), verifierFunc(func(context.Context, Request, Response) (bool, error) { return false, private }), time.Second)
			if transactional {
				b = NewTransactional(&state, agentFunc(approve), func(context.Context, policy.Challenge, Response) (Transaction, error) { return nil, private }, time.Second)
			}
			err := b.RequestAccess(context.Background())
			if !errors.Is(err, ErrInvalidCredentials) || strings.Contains(err.Error(), "credential-secret") || !state.IsLocked() {
				t.Fatalf("unsafe or lost backend category: %v", err)
			}
		})
	}
}

type statusSnapshot interface{ Snapshot() Status }

func snapshotOf(t *testing.T, b *Broker) Status {
	t.Helper()
	s, ok := any(b).(statusSnapshot)
	if !ok {
		t.Fatal("broker does not expose an in-memory status snapshot")
	}
	return s.Snapshot()
}

func TestSnapshotTracksWorkerRetirementAndSuspension(t *testing.T) {
	var state policy.State
	entered, release := make(chan struct{}), make(chan struct{})
	b := New(&state, agentFunc(func(ctx context.Context, req Request) (Response, error) {
		close(entered)
		<-release
		return approve(ctx, req)
	}), verifierFunc(verifyMock), time.Second)
	if got := snapshotOf(t, b); got != (Status{}) {
		t.Fatalf("idle status: %+v", got)
	}
	result := make(chan error, 1)
	go func() { result <- b.RequestAccess(context.Background()) }()
	receive(t, entered)
	if got := snapshotOf(t, b); got != (Status{Authenticating: true}) {
		t.Fatalf("running status: %+v", got)
	}
	b.Suspend(false)
	receive(t, result)
	if got := snapshotOf(t, b); got != (Status{Authenticating: true, Suspended: true}) {
		t.Fatalf("detached worker status: %+v", got)
	}
	close(release)
	if err := b.WaitIdle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := snapshotOf(t, b); got != (Status{Suspended: true}) {
		t.Fatalf("retired status: %+v", got)
	}
	b.Resume()
	if got := snapshotOf(t, b); got != (Status{}) {
		t.Fatalf("resumed status: %+v", got)
	}
}

func TestSnapshotTracksRetainedCleanup(t *testing.T) {
	var state policy.State
	resource := &preparedResource{cleanupErr: errors.New("private cleanup details")}
	b := NewTransactional(&state, agentFunc(approve), func(context.Context, policy.Challenge, Response) (Transaction, error) {
		return resource, ErrInvalidCredentials
	}, time.Second)
	if err := b.RequestAccess(context.Background()); err == nil {
		t.Fatal("failed preparation succeeded")
	}
	if err := b.WaitIdle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := snapshotOf(t, b); got != (Status{Cleanup: true}) {
		t.Fatalf("cleanup status: %+v", got)
	}
	resource.cleanupErr = nil
	if err := b.RetryCleanup(); err != nil {
		t.Fatal(err)
	}
	if got := snapshotOf(t, b); got != (Status{}) {
		t.Fatalf("completed cleanup status: %+v", got)
	}
}

func TestProofCopyClearedWithoutChangingAgentProofOnWorkerExit(t *testing.T) {
	for _, mode := range []string{"agent error", "denied", "stale", "verified", "verifier panic", "verifier Goexit", "prepare error", "prepare Goexit"} {
		t.Run(mode, func(t *testing.T) {
			var state policy.State
			proof := []byte("private-proof")
			var observedProof []byte
			agent := agentFunc(func(_ context.Context, req Request) (Response, error) {
				response := Response{RequestID: req.ID, Approved: true, Proof: proof}
				switch mode {
				case "agent error":
					return response, ErrUnavailable
				case "denied":
					response.Approved = false
				case "stale":
					response.RequestID++
				}
				return response, nil
			})
			b := New(&state, agent, verifierFunc(func(_ context.Context, _ Request, response Response) (bool, error) {
				observedProof = response.Proof
				if string(response.Proof) != "private-proof" {
					t.Error("proof was cleared before verification")
				}
				switch mode {
				case "verifier panic":
					panic("private")
				case "verifier Goexit":
					runtime.Goexit()
				}
				return true, nil
			}), time.Second)
			if strings.HasPrefix(mode, "prepare") {
				b = NewTransactional(&state, agent, func(_ context.Context, _ policy.Challenge, response Response) (Transaction, error) {
					observedProof = response.Proof
					if string(response.Proof) != "private-proof" {
						t.Error("proof was cleared before preparation")
					}
					if mode == "prepare Goexit" {
						runtime.Goexit()
					}
					return nil, ErrInvalidCredentials
				}, time.Second)
			}
			b.RequestAccess(context.Background())
			if err := b.WaitIdle(context.Background()); err != nil {
				t.Fatal(err)
			}
			if string(proof) != "private-proof" {
				t.Error("worker changed the agent's borrowed proof")
			}
			for _, value := range observedProof {
				if value != 0 {
					t.Fatal("worker retained its own proof copy")
				}
			}
		})
	}
}

func TestAgentCanReuseBorrowedProofAcrossFlights(t *testing.T) {
	var state policy.State
	proof := []byte("reusable-proof")
	b := New(&state, agentFunc(func(_ context.Context, req Request) (Response, error) {
		return Response{RequestID: req.ID, Approved: true, Proof: proof}, nil
	}), verifierFunc(func(_ context.Context, _ Request, response Response) (bool, error) {
		return string(response.Proof) == "reusable-proof", nil
	}), time.Second)
	for range 2 {
		if err := b.RequestAccess(context.Background()); err != nil {
			t.Errorf("reused borrowed proof did not authenticate: %v", err)
		}
		if err := b.WaitIdle(context.Background()); err != nil {
			t.Fatal(err)
		}
		if string(proof) != "reusable-proof" {
			t.Error("broker mutated agent-owned proof")
		}
		state.Lock()
	}
}

func TestAgentDeadlineBeforeSharedExpiryKeepsSafeCategory(t *testing.T) {
	var state policy.State
	b := New(&state, agentFunc(func(ctx context.Context, _ Request) (Response, error) {
		if ctx.Err() != nil {
			t.Error("shared authentication context expired before agent result")
		}
		return Response{}, errors.Join(context.DeadlineExceeded, errors.New("private-agent-details"))
	}), verifierFunc(verifyMock), time.Hour)
	err := b.RequestAccess(context.Background())
	if err != context.DeadlineExceeded || !state.IsLocked() {
		t.Fatalf("agent expiry was lost or exposed private details: %v", err)
	}
}
