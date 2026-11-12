//go:build linux

package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/poizdev/veyl/internal/auth"
)

const controlTimeout = 90 * time.Second

// Frames are bounded and never logged; only a challenge response may hold proof.
type frame struct {
	Version   int    `json:"version"`
	Op        string `json:"op,omitempty"`
	TTY       bool   `json:"tty,omitempty"`
	RequestID uint64 `json:"request_id,omitempty"`
	Proof     []byte `json:"proof,omitempty"`
	Challenge bool   `json:"challenge,omitempty"`
	Canceled  bool   `json:"canceled,omitempty"`
	Code      int    `json:"code,omitempty"`
	Message   string `json:"message,omitempty"`
	State     string `json:"state,omitempty"`
}

func readFrame(r io.Reader) (frame, error) {
	var f frame
	// A dedicated buffered reader must be retained by callers when pipelining.
	// Protocol exchanges are sequential and never send a second frame in advance.
	reader, ok := r.(*bufio.Reader)
	if !ok {
		reader = bufio.NewReaderSize(r, 4096)
	}
	data, err := reader.ReadSlice('\n')
	if err != nil || len(data) > 4096 {
		return f, errors.New("invalid control response")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&f) != nil || f.Version != 1 {
		return frame{}, errors.New("invalid control response")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return frame{}, errors.New("invalid control response")
	}
	return f, nil
}
func writeFrame(w io.Writer, f frame) error {
	f.Version = 1
	data, err := json.Marshal(f)
	if err != nil || len(data) >= 4096 {
		return errors.New("invalid control request")
	}
	data = append(data, '\n')
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

type connectionAgent struct {
	conn      net.Conn
	responses <-chan frame
}

func (a connectionAgent) Authenticate(ctx context.Context, r auth.Request) (auth.Response, error) {
	if err := writeFrame(a.conn, frame{Challenge: true, RequestID: r.ID}); err != nil {
		return auth.Response{}, auth.ErrCanceled
	}
	select {
	case <-ctx.Done():
		return auth.Response{}, ctx.Err()
	case response, ok := <-a.responses:
		if !ok {
			return auth.Response{}, auth.ErrCanceled
		}
		if response.RequestID != r.ID || response.Op != "" || response.Challenge || len(response.Proof) > 1024 {
			return auth.Response{}, auth.ErrStale
		}
		if response.Canceled {
			return auth.Response{}, auth.ErrCanceled
		}
		return auth.Response{RequestID: r.ID, Approved: true, Proof: response.Proof}, nil
	}
}
func handleConnection(conn net.Conn, i *instance) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(controlTimeout))
	reader := bufio.NewReaderSize(conn, 4096)
	request, err := readFrame(reader)
	if err != nil || !known(request.Op) || request.Op == "mount" || len(request.Proof) != 0 || request.RequestID != 0 || request.Challenge || request.Canceled || request.Message != "" || request.Code != 0 || request.State != "" || (request.TTY && request.Op != "unlock") {
		_ = writeFrame(conn, frame{Code: 2, Message: "Invalid control request. Use veyl help."})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), controlTimeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { conn.SetReadDeadline(time.Now()) })
	defer stop()
	responses := make(chan frame, 1)
	// A sole reader detects disconnect for all operations and supplies tty replies.
	// No second goroutine competes with the agent for credential frames.
	go func() {
		defer close(responses)
		for {
			f, err := readFrame(reader)
			if err != nil {
				cancel()
				return
			}
			select {
			case responses <- f:
			case <-ctx.Done():
				return
			}
		}
	}()
	var result Result
	switch request.Op {
	case "status":
		result = i.status()
	case "lock":
		result = i.lock(ctx, false)
	case "unmount":
		result = i.lock(ctx, true)
	case "unlock":
		var err error
		if request.TTY {
			err = i.broker.RequestAccessWithAgent(ctx, connectionAgent{conn: conn, responses: responses})
		} else {
			err = i.broker.RequestAccess(ctx)
		}
		result = authResult(err)
		if i.status().Code == 5 {
			result = Result{Code: 5, State: "cleanup_pending", Message: errCleanupPending.Error()}
		}
	}
	_ = writeFrame(conn, frame{Code: result.Code, Message: result.Message, State: result.State})
	if request.Op == "unmount" && result.Code == 0 {
		i.finish()
	}
}
func exchange(ctx context.Context, conn net.Conn, op string, tty bool, prompt func(context.Context) ([]byte, error)) Result {
	deadline := time.Now().Add(controlTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	session, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	promptCtx, cancelPrompt := context.WithCancel(session)
	defer cancelPrompt()
	conn.SetDeadline(deadline)
	stop := context.AfterFunc(session, func() { conn.SetDeadline(time.Now()) })
	defer stop()
	failed := Result{Code: 1, Message: "Connection interrupted. Check veyl status before retrying."}
	if writeFrame(conn, frame{Op: op, TTY: tty}) != nil {
		return failed
	}
	type incoming struct {
		f   frame
		err error
	}
	messages := make(chan incoming, 1)
	reader := bufio.NewReaderSize(conn, 4096)
	// Keep observing the server while the tty reader is active: a remote timeout,
	// cancellation or disconnect must restore the client's terminal promptly.
	go func() {
		for {
			f, err := readFrame(reader)
			select {
			case messages <- incoming{f, err}:
			case <-session.Done():
				return
			}
			if err != nil || !f.Challenge {
				cancelPrompt()
				return
			}
		}
	}()
	result := func(m incoming) Result {
		if m.err != nil {
			return failed
		}
		return Result{Code: m.f.Code, Message: m.f.Message, State: m.f.State}
	}
	prompted := false
	for {
		var m incoming
		select {
		case m = <-messages:
		case <-session.Done():
			return failed
		}
		if m.err != nil {
			return failed
		}
		f := m.f
		if !f.Challenge {
			return result(m)
		}
		if op != "unlock" || !tty || prompted || f.RequestID == 0 || prompt == nil {
			return failed
		}
		prompted = true
		proof, err := prompt(promptCtx)
		// A terminal result may already have arrived while the prompt was open.
		select {
		case terminal := <-messages:
			clear(proof)
			return result(terminal)
		default:
		}
		reply := frame{RequestID: f.RequestID, Proof: proof, Canceled: err != nil}
		sendErr := writeFrame(conn, reply)
		clear(proof)
		if sendErr != nil {
			return failed
		}
	}
}

type controlServer struct {
	listener *net.UnixListener
	instance *instance
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
	stopped  chan struct{}
}

func serveControl(owner *runtimeOwner, i *instance) *controlServer {
	s := &controlServer{listener: owner.listener, instance: i, conns: make(map[net.Conn]struct{}), stopped: make(chan struct{})}
	go func() {
		defer close(s.stopped)
		for {
			conn, err := s.listener.AcceptUnix()
			if err != nil {
				return
			}
			if samePeer(conn) != nil {
				conn.Close()
				continue
			}
			s.mu.Lock()
			if len(s.conns) >= 16 {
				s.mu.Unlock()
				conn.Close()
				continue
			}
			s.conns[conn] = struct{}{}
			s.wg.Add(1)
			s.mu.Unlock()
			go func() {
				defer s.wg.Done()
				defer func() { s.mu.Lock(); delete(s.conns, conn); s.mu.Unlock() }()
				handleConnection(conn, i)
			}()
		}
	}()
	return s
}
func (s *controlServer) close() {
	if s.listener != nil {
		s.listener.Close()
		<-s.stopped
	}
	s.mu.Lock()
	for conn := range s.conns {
		// Stop idle readers, but allow concurrent terminal replies to drain.
		// A bounded write grace also handles a client that never receives.
		conn.SetReadDeadline(time.Now())
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	}
	s.mu.Unlock()
	s.wg.Wait()
}
