package policy

import (
	"context"
	"testing"
	"time"
)

// Removing the attached cancellation or epoch check must break these tests.
func TestAdoptedResourceRevokedBeforeDrain(t *testing.T) {
	var s State
	ticket, _ := s.Challenge()
	ctx, cancel := context.WithCancel(context.Background())
	epoch, ok := s.Adopt(ticket, func() bool { return true }, cancel)
	if !ok || !s.Valid(epoch) {
		t.Fatal("resource not adopted")
	}
	release, ok := s.Begin(epoch)
	if !ok {
		t.Fatal("lease denied")
	}
	done := make(chan struct{})
	go func() { s.Lock(); close(done) }()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("revocation waited for drain")
	}
	if s.Valid(epoch) {
		t.Fatal("old epoch valid")
	}
	release()
	<-done
	s.Unlock()
	next, _ := s.Session()
	s.Revoke(epoch)
	if !s.Valid(next) {
		t.Fatal("delayed failure revoked newer session")
	}
}
func TestAdoptRejectsStaleAndCanceled(t *testing.T) {
	for _, stale := range []bool{false, true} {
		var s State
		ticket, _ := s.Challenge()
		if stale {
			s.Lock()
		}
		if _, ok := s.Adopt(ticket, func() bool { return stale }, func() {}); ok {
			t.Fatal("invalid resource adopted")
		}
		if !s.IsLocked() {
			t.Fatal("rejection authorized session")
		}
	}
}
