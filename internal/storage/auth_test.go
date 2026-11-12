//go:build linux

package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/poizdev/veyl/internal/auth"
	"github.com/poizdev/veyl/internal/policy"
)

type credentialAgent struct {
	proof  []byte
	denied bool
}

func (a credentialAgent) Authenticate(_ context.Context, r auth.Request) (auth.Response, error) {
	return auth.Response{RequestID: r.ID, Approved: !a.denied, Proof: a.proof}, nil
}

// These tests retain the real broker, policy, and storage lifecycle; only
// subprocesses and kernel mountinfo are replaced by the existing fake system.
func TestBrokerStorageTransaction(t *testing.T) {
	for _, kind := range []string{"success", "invalid password", "denied", "lock after verification", "cancel after verification", "timeout startup", "failed rollback"} {
		t.Run(kind, func(t *testing.T) {
			b, s, f, cfg := testBackend(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			proof := []byte("synthetic-password")
			if kind == "invalid password" {
				proof = []byte("incorrect")
			}
			if kind == "timeout startup" {
				f.mode = "pending"
			}
			var candidate *Candidate
			timeout := time.Second
			if kind == "timeout startup" {
				timeout = 25 * time.Millisecond
			}
			broker := auth.NewTransactional(s, credentialAgent{proof: proof, denied: kind == "denied"}, func(ctx context.Context, ticket policy.Challenge, response auth.Response) (auth.Transaction, error) {
				c, err := b.Prepare(ctx, ticket, response.Proof)
				candidate = c
				if c != nil && err == nil {
					switch kind {
					case "lock after verification":
						s.Lock()
					case "cancel after verification":
						cancel()
					case "failed rollback":
						f.mu.Lock()
						f.failUnmount = true
						f.mu.Unlock()
						s.Lock()
					}
				}
				// Avoid returning a typed nil inside an interface.
				if c == nil {
					return nil, err
				}
				return c, err
			}, timeout)
			err := broker.RequestAccess(ctx)
			if kind == "success" {
				if err != nil {
					t.Fatal(err)
				}
				if candidate == nil || !candidate.Owned() || !b.Mounted() || s.IsLocked() {
					t.Fatal("missing adopted session")
				}
				if err := candidate.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				if err == nil || !s.IsLocked() {
					t.Fatalf("rejected authentication: %v", err)
				}
				// A canceled caller may return before its cleanup worker retires.
				deadline := time.After(time.Second)
				for {
					select {
					case <-deadline:
						t.Fatal("cleanup worker did not finish")
					default:
					}
					if kind == "failed rollback" {
						if broker.CleanupError() != nil {
							break
						}
					} else if b.Retained() == nil {
						break
					}
					time.Sleep(time.Millisecond)
				}
				if kind == "failed rollback" {
					if !errors.Is(broker.CleanupError(), ErrCleanup) || b.Retained() == nil {
						t.Fatal("failed rollback not retained")
					}
					if err := broker.RequestAccess(context.Background()); !errors.Is(err, auth.ErrUnavailable) {
						t.Fatal("residue permitted new attempt")
					}
					f.mu.Lock()
					f.failUnmount = false
					f.mu.Unlock()
					if err := broker.RetryCleanup(); err != nil {
						t.Fatal(err)
					}
				}
			}
			empty(t, cfg.RuntimeDir)
		})
	}
}
func TestRollbackFailureRetainsCandidateAndBlocksMount(t *testing.T) {
	b, s, f, cfg := testBackend(t)
	c, err := b.Prepare(context.Background(), ticket(t, s), []byte("synthetic-password"))
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.failUnmount = true
	f.mu.Unlock()
	if err := c.Rollback(); !errors.Is(err, ErrCleanup) {
		t.Fatal(err)
	}
	if !c.Owned() || b.Retained() != c || !errors.Is(c.View().Err(), ErrCleanup) {
		t.Fatal("rollback residue forgotten")
	}
	if _, err := b.Mount(context.Background(), ticket(t, s), []byte("synthetic-password")); !errors.Is(err, ErrBusy) {
		t.Fatal("residue replaced")
	}
	f.mu.Lock()
	f.failUnmount = false
	f.mu.Unlock()
	if err := c.Rollback(); err != nil {
		t.Fatal(err)
	}
	empty(t, cfg.RuntimeDir)
}
