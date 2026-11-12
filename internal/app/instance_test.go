//go:build linux

package app

import (
	"context"
	"errors"
	"github.com/poizdev/veyl/internal/auth"
	"github.com/poizdev/veyl/internal/ghostfs"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type cleanupFixture struct{ fail atomic.Bool }

func (f *cleanupFixture) Unmount(context.Context) error {
	if f.fail.Load() {
		return errors.New("private backend details")
	}
	return nil
}
func (f *cleanupFixture) Close() error { return f.Unmount(context.Background()) }

type agentFunc func(context.Context, auth.Request) (auth.Response, error)

func (f agentFunc) Authenticate(c context.Context, r auth.Request) (auth.Response, error) {
	return f(c, r)
}

type verifyFunc func(context.Context, auth.Request, auth.Response) (bool, error)

func (f verifyFunc) Verify(c context.Context, r auth.Request, p auth.Response) (bool, error) {
	return f(c, r, p)
}
func testInstance(t *testing.T) (*instance, *cleanupFixture) {
	t.Helper()
	r := &ghostfs.Root{}
	f := &cleanupFixture{}
	a := agentFunc(func(_ context.Context, r auth.Request) (auth.Response, error) {
		return auth.Response{RequestID: r.ID, Approved: true}, nil
	})
	b := auth.New(&r.State, a, verifyFunc(func(context.Context, auth.Request, auth.Response) (bool, error) { return true, nil }), time.Second)
	i := newInstance(r, b, f, nil, nil)
	return i, f
}
func TestInstanceStatesAndTruthfulCleanupRetry(t *testing.T) {
	i, f := testInstance(t)
	if s := i.status(); s.State != "locked" || s.Code != 0 {
		t.Fatal(s)
	}
	if err := i.broker.RequestAccess(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := i.status(); s.State != "unlocked" {
		t.Fatal(s)
	}
	f.fail.Store(true)
	if r := i.lock(context.Background(), false); r.Code != 5 {
		t.Fatal(r)
	}
	if !i.root.State.IsLocked() || i.status().State != "cleanup_pending" {
		t.Fatal("revoked session cleanup hidden")
	}
	if err := i.broker.RequestAccess(context.Background()); !errors.Is(err, auth.ErrUnavailable) {
		t.Fatal("admission resumed during failed cleanup")
	}
	f.fail.Store(false)
	if r := i.lock(context.Background(), false); r.Code != 0 {
		t.Fatal(r)
	}
	if err := i.broker.RequestAccess(context.Background()); err != nil {
		t.Fatal("retry did not resume admission", err)
	}
	if r := i.lock(context.Background(), true); r.Code != 0 {
		t.Fatal(r)
	}
	i.broker.Resume()
	if err := i.broker.RequestAccess(context.Background()); !errors.Is(err, auth.ErrUnavailable) {
		t.Fatal("shutdown reopened admission")
	}
}
func TestStatusDoesNotWaitForAuthentication(t *testing.T) {
	i, _ := testInstance(t)
	entered, finish := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	a := agentFunc(func(ctx context.Context, r auth.Request) (auth.Response, error) {
		close(entered)
		select {
		case <-finish:
		case <-ctx.Done():
		}
		return auth.Response{}, auth.ErrCanceled
	})
	go func() { done <- i.broker.RequestAccessWithAgent(context.Background(), a) }()
	<-entered
	if s := i.status(); s.State != "authenticating" {
		t.Fatal(s)
	}
	close(finish)
	<-done
}

type goneServer struct{}

func (goneServer) Unmount() error { return errors.New("already unmounted") }
func (goneServer) Wait()          {}
func TestShutdownAfterExternalVeylUnmount(t *testing.T) {
	i, _ := testInstance(t)
	i.server = goneServer{}
	i.mountpoint = t.TempDir()
	if r := i.lock(context.Background(), true); r.Code != 0 {
		t.Fatal("confirmed external unmount could not finish cleanup", r)
	}
}

func TestStatusDoesNotClaimRevocationBeforePolicyTransition(t *testing.T) {
	i, _ := testInstance(t)
	i.root.State.Unlock()
	i.cleanup.Store(true)
	result := i.status()
	if result.Code != 5 || strings.Contains(strings.ToLower(result.Message), "session locked") {
		t.Fatal("status claimed revocation before it happened", result)
	}
	i.root.State.Lock()
}
