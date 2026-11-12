//go:build linux

package app

import (
	"context"
	"github.com/poizdev/veyl/internal/auth"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestControlProtocolAndChallengeBoundUnlock(t *testing.T) {
	i, _ := testInstance(t)
	// Make the ordinary agent unavailable so terminal credentials must travel
	// through the override and still pass the same broker verifier.
	i.broker = auth.New(&i.root.State, agentFunc(func(context.Context, auth.Request) (auth.Response, error) {
		return auth.Response{}, auth.ErrUnavailable
	}), verifyFunc(func(_ context.Context, _ auth.Request, r auth.Response) (bool, error) {
		return string(r.Proof) == "synthetic", nil
	}), time.Second)
	for _, op := range []string{"status", "lock", "unlock", "status"} {
		server, client := net.Pipe()
		done := make(chan struct{})
		go func() { handleConnection(server, i); close(done) }()
		prompts := 0
		r := exchange(context.Background(), client, op, op == "unlock", func(context.Context) ([]byte, error) { prompts++; return []byte("synthetic"), nil })
		client.Close()
		<-done
		if r.Code != 0 {
			t.Fatal(op, r)
		}
		if op == "unlock" && prompts != 1 {
			t.Fatal("challenge did not prompt exactly once")
		}
	}
	if i.status().State != "unlocked" {
		t.Fatal("no adopted broker authorization")
	}
	i.lock(context.Background(), false)
}
func TestControlRejectsMismatchedCredentialResponse(t *testing.T) {
	i, _ := testInstance(t)
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() { handleConnection(server, i); close(done) }()
	if err := writeFrame(client, frame{Version: 1, Op: "unlock", TTY: true}); err != nil {
		t.Fatal(err)
	}
	challenge, err := readFrame(client)
	if err != nil || !challenge.Challenge || challenge.RequestID == 0 {
		t.Fatal("missing challenge")
	}
	if err := writeFrame(client, frame{Version: 1, RequestID: challenge.RequestID + 1, Proof: []byte("synthetic")}); err != nil {
		t.Fatal(err)
	}
	response, err := readFrame(client)
	if err != nil || response.Code == 0 {
		t.Fatal("stale credential accepted")
	}
	<-done
	if !i.root.State.IsLocked() {
		t.Fatal("response bypassed challenge")
	}
}

func TestTerminalPromptCanceledOnServerDisconnect(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	done := make(chan Result, 1)
	go func() {
		_, _ = readFrame(server)
		_ = writeFrame(server, frame{Challenge: true, RequestID: 1})
		<-entered
		server.Close()
	}()
	go func() {
		done <- exchange(ctx, client, "unlock", true, func(ctx context.Context) ([]byte, error) { close(entered); <-ctx.Done(); return nil, ctx.Err() })
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("terminal prompt survived server disconnect")
	}
}

func TestConcurrentUnmountAcknowledgmentsDrain(t *testing.T) {
	i, _ := testInstance(t)
	firstRaw, clientFirst := net.Pipe()
	first := &observedConn{Conn: firstRaw, observed: make(chan struct{})}
	second, clientSecond := net.Pipe()
	defer clientFirst.Close()
	defer clientSecond.Close()
	s := &controlServer{conns: map[net.Conn]struct{}{first: {}, second: {}}}
	s.wg.Add(2)
	go func() { defer s.wg.Done(); handleConnection(first, i) }()
	go func() { defer s.wg.Done(); handleConnection(second, i) }()
	if err := writeFrame(clientFirst, frame{Op: "unmount"}); err != nil {
		t.Fatal(err)
	}
	// Wait until the first teardown completes, but don't receive its acknowledgment.
	deadline := time.After(time.Second)
	for !i.completed.Load() {
		select {
		case <-deadline:
			t.Fatal("shutdown did not complete")
		default:
			runtime.Gosched()
		}
	}
	if err := writeFrame(clientSecond, frame{Op: "unmount"}); err != nil {
		t.Fatal(err)
	}
	if f, err := readFrame(clientSecond); err != nil || f.Code != 0 {
		t.Fatal("second acknowledgment", err)
	}
	<-i.done
	closed := make(chan struct{})
	go func() { s.close(); close(closed) }()
	// Let shutdown cleanup start before accepting the first response.
	<-first.observed
	if f, err := readFrame(clientFirst); err != nil || f.Code != 0 {
		t.Fatal("first acknowledgment lost", err)
	}
	<-closed
}

type observedConn struct {
	net.Conn
	observed chan struct{}
	once     sync.Once
}

func (c *observedConn) Close() error { c.once.Do(func() { close(c.observed) }); return c.Conn.Close() }
func (c *observedConn) SetReadDeadline(t time.Time) error {
	c.once.Do(func() { close(c.observed) })
	return c.Conn.SetReadDeadline(t)
}
