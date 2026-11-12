package policy

import (
	"sync"
	"syscall"
	"testing"
)

func TestLookup(t *testing.T) {
	var state State
	for _, tc := range []struct {
		name string
		want syscall.Errno
	}{
		{".troll", syscall.EACCES}, {"visible.txt", 0}, {"missing", syscall.ENOENT},
		{".other", syscall.ENOENT}, {".troll/child", syscall.ENOENT}, {"", syscall.ENOENT},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := state.Lookup(tc.name); got != tc.want {
				t.Fatalf("Lookup(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestStateTransitions(t *testing.T) {
	var state State
	if !state.IsLocked() {
		t.Fatal("zero state must be locked")
	}
	for range 3 {
		state.Lock()
		if !state.IsLocked() {
			t.Fatal("Lock must be idempotent")
		}
	}
	for range 3 {
		state.Unlock()
		if state.IsLocked() {
			t.Fatal("Unlock must be idempotent")
		}
		if got := state.Lookup(".troll"); got != 0 {
			t.Fatalf("unlocked ghost: %v", got)
		}
		if got := state.Lookup("missing"); got != syscall.ENOENT {
			t.Fatalf("unknown: %v", got)
		}
	}
	state.Lock()
	if !state.IsLocked() || state.Lookup(".troll") != syscall.EACCES {
		t.Fatal("relock failed")
	}
}

func TestConcurrentState(t *testing.T) {
	var state State
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Go(func() {
			for range 1000 {
				switch i % 3 {
				case 0:
					state.Lock()
				case 1:
					state.Unlock()
				case 2:
					_ = state.IsLocked()
					if got := state.Lookup(".troll"); got != 0 && got != syscall.EACCES {
						t.Errorf("ghost: %v", got)
					}
					if got := state.Lookup("visible.txt"); got != 0 {
						t.Errorf("visible: %v", got)
					}
					if got := state.Lookup("unknown"); got != syscall.ENOENT {
						t.Errorf("unknown: %v", got)
					}
				}
			}
		})
	}
	wg.Wait()
	state.Lock()
	if !state.IsLocked() {
		t.Fatal("final Lock lost")
	}
	state.Unlock()
	if state.IsLocked() {
		t.Fatal("final Unlock lost")
	}
}

func TestSessionEpoch(t *testing.T) {
	var state State
	if token, ok := state.Session(); ok || token != 0 || state.Valid(token) {
		t.Fatal("locked state issued a session")
	}
	state.Unlock()
	first, ok := state.Session()
	if !ok || first == 0 || !state.Valid(first) {
		t.Fatal("unlock did not create valid session")
	}
	for range 4 {
		state.Unlock()
		token, ok := state.Session()
		if !ok || token != first {
			t.Fatal("repeated Unlock created another session")
		}
	}
	state.Lock()
	state.Lock()
	if state.Valid(first) {
		t.Fatal("Lock did not revoke session")
	}
	if token, ok := state.Session(); ok || token != 0 {
		t.Fatal("locked state exposed active session")
	}
	state.Unlock()
	next, ok := state.Session()
	if !ok || next <= first || state.Valid(first) || !state.Valid(next) {
		t.Fatal("new session revived/reused old epoch")
	}
	if state.Valid(0) {
		t.Fatal("zero session accepted")
	}
}

func TestConcurrentUnlockCreatesOneSession(t *testing.T) {
	var state State
	var last uint64
	for range 20 {
		state.Lock()
		var wg sync.WaitGroup
		tokens := make(chan uint64, 32)
		for range 32 {
			wg.Go(func() {
				state.Unlock()
				token, ok := state.Session()
				if !ok {
					t.Error("unlock remained locked")
				}
				tokens <- token
			})
		}
		wg.Wait()
		close(tokens)
		current, ok := state.Session()
		if !ok || current <= last {
			t.Fatal("session not advanced")
		}
		for token := range tokens {
			if token != current {
				t.Fatalf("concurrent Unlock issued distinct sessions: %d/%d", token, current)
			}
		}
		if last != 0 && state.Valid(last) {
			t.Fatal("old session accepted")
		}
		last = current
	}
}

func TestSessionSpaceExhaustion(t *testing.T) {
	var state State
	// Reach the last supported session without billions of transitions.
	state.version.Store(^uint64(0) - 3)
	state.Unlock()
	last, ok := state.Session()
	if !ok || !state.Valid(last) {
		t.Fatal("last session missing")
	}
	state.Lock()
	state.Unlock()
	if !state.IsLocked() || state.Valid(last) {
		t.Fatal("exhaustion wrapped/revived a session")
	}
	if _, ok := state.Session(); ok {
		t.Fatal("exhausted state issued another session")
	}
}

func TestAuthenticationChallengeCannotSurviveLock(t *testing.T) {
	var state State
	ticket, ok := state.Challenge()
	if !ok {
		t.Fatal("locked state did not issue ticket")
	}
	state.Lock() // Already locked, but this must invalidate pending authentication.
	if state.Authorize(ticket) {
		t.Fatal("old approval survived explicit Lock")
	}
	next, ok := state.Challenge()
	if !ok || !state.Authorize(next) || state.IsLocked() {
		t.Fatal("fresh verified grant failed")
	}
	if state.Authorize(next) {
		t.Fatal("ticket reused")
	}
}

func TestAuthenticationChallengeOwnerAndSession(t *testing.T) {
	var first, second State
	ticket, ok := first.Challenge()
	if !ok {
		t.Fatal("no ticket")
	}
	if second.Authorize(ticket) {
		t.Fatal("ticket accepted by another root")
	}
	first.Unlock()
	if _, ok := first.Challenge(); ok {
		t.Fatal("ticket issued while unlocked")
	}
	first.Lock()
	if first.Authorize(ticket) {
		t.Fatal("old-session approval accepted")
	}
}

func TestAuthenticationRevisionExhaustionFailsClosed(t *testing.T) {
	var state State
	state.authRevision = ^uint64(0) - 1
	ticket, ok := state.Challenge()
	if !ok {
		t.Fatal("last ticket missing")
	}
	state.Lock()
	if state.Authorize(ticket) {
		t.Fatal("exhausted revision accepted old ticket")
	}
	if _, ok := state.Challenge(); ok {
		t.Fatal("revision wrapped")
	}
}

func TestChallengeGuardRejectsStaleProcessStart(t *testing.T) {
	var state State
	c, ok := state.Challenge()
	if !ok {
		t.Fatal("no challenge")
	}
	calls := 0
	valid, err := state.WithChallenge(c, func() error { calls++; return nil })
	if !valid || err != nil || calls != 1 || !state.IsLocked() {
		t.Fatal("start guard authorized a session or skipped launch")
	}
	state.Lock()
	valid, err = state.WithChallenge(c, func() error { calls++; return nil })
	if valid || err != nil || calls != 1 {
		t.Fatal("stale request initiated process")
	}
}
