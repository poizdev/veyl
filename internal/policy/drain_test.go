package policy

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

func awaitRevocation(t *testing.T, state *State) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !state.IsLocked() {
		if time.Now().After(deadline) {
			t.Fatal("Lock did not publish revocation")
		}
		runtime.Gosched()
	}
}

func awaitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("operation did not complete (possible deadlock)")
	}
}

func assertDraining(t *testing.T, state *State, done <-chan struct{}) {
	t.Helper()
	// Publishing revocation must occur while owning the transition mutex, which
	// remains owned until admitted operations finish. This is an observed barrier,
	// not a sleep intended to give the locking goroutine time to run.
	if state.transitions.TryLock() {
		state.transitions.Unlock()
		t.Error("revocation did not hold the transition boundary while work was active")
	}
	select {
	case <-done:
		t.Error("Lock returned while admitted work was active")
	default:
	}
}

func TestLockDrainsAdmittedOperations(t *testing.T) {
	var state State
	state.Unlock()
	session, _ := state.Session()
	release, ok := state.Begin(session)
	if !ok {
		t.Fatal("admission failed")
	}
	var once sync.Once
	finish := func() { once.Do(release) }
	defer finish()
	locked := make(chan struct{})
	go func() { state.Lock(); close(locked) }()
	awaitRevocation(t, &state)
	assertDraining(t, &state, locked)
	if end, ok := state.Begin(session); ok {
		end()
		t.Error("new work admitted during drain")
	}
	finish()
	awaitDone(t, locked)
	state.Unlock()
	if end, ok := state.Begin(session); ok {
		end()
		t.Fatal("revoked session admitted again")
	}
	next, _ := state.Session()
	end, ok := state.Begin(next)
	if !ok {
		t.Fatal("fresh session rejected")
	}
	end()
}

func TestLockDrainsAllConcurrentReaders(t *testing.T) {
	var state State
	state.Unlock()
	session, _ := state.Session()
	const readers = 8
	admitted := make(chan struct{}, readers)
	released := make(chan struct{}, readers)
	finish := make([]chan struct{}, readers)
	for i := range readers {
		finish[i] = make(chan struct{})
		go func() {
			end, ok := state.Begin(session)
			if !ok {
				t.Error("concurrent reader rejected")
				admitted <- struct{}{}
				return
			}
			admitted <- struct{}{}
			<-finish[i]
			end()
			released <- struct{}{}
		}()
	}
	// All readers must be admitted before any is released: shared work is concurrent.
	for range readers {
		select {
		case <-admitted:
		case <-time.After(5 * time.Second):
			t.Fatal("readers serialized/deadlocked")
		}
	}
	locked := make(chan struct{})
	go func() { state.Lock(); close(locked) }()
	awaitRevocation(t, &state)
	for i := range readers - 1 {
		close(finish[i])
		select {
		case <-released:
		case <-time.After(5 * time.Second):
			t.Fatal("reader did not release")
		}
	}
	assertDraining(t, &state, locked)
	close(finish[readers-1])
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("last reader did not release")
	}
	awaitDone(t, locked)
}

func TestUnlockAndRepeatedLockWaitForDrain(t *testing.T) {
	var state State
	state.Unlock()
	session, _ := state.Session()
	release, ok := state.Begin(session)
	if !ok {
		t.Fatal("admission failed")
	}
	var once sync.Once
	finish := func() { once.Do(release) }
	defer finish()
	first := make(chan struct{})
	go func() { state.Lock(); close(first) }()
	awaitRevocation(t, &state)
	assertDraining(t, &state, first)
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() { state.Lock(); state.Unlock() })
	}
	if _, ok := state.Session(); ok {
		t.Error("new session published before drain")
	}
	finish()
	awaitDone(t, first)
	complete := make(chan struct{})
	go func() { wg.Wait(); close(complete) }()
	awaitDone(t, complete)
	state.Unlock()
	next, _ := state.Session()
	state.Unlock()
	repeated, _ := state.Session()
	if next == session || next != repeated || !state.Valid(next) {
		t.Fatal("contention broke session semantics")
	}
	state.Lock()
	state.Lock()
	if !state.IsLocked() {
		t.Fatal("repeated Lock failed")
	}
}
