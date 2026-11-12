// Package policy defines the synthetic namespace's access state.
package policy

import (
	"sync"
	"sync/atomic"
	"syscall"
)

const VisibleName = "visible.txt"
const GhostName = ".troll"

// State is locked by default and must not be copied after first use.
// Odd versions are active sessions; even versions are locked. Snapshots remain
// atomic. Transitions serialize separately from concurrent admitted operations.
type State struct {
	version        atomic.Uint64
	transitions    sync.Mutex
	operations     sync.RWMutex
	revokeResource func() // nonblocking cancellation only; guarded by transitions
	authRevision   uint64 // guarded by transitions; saturates to disable new tickets
}

// Lock first revokes admission, then drains existing leases. Unlock cannot
// create another session until the drain finishes. Never call Lock/Unlock while
// holding a lease from this State: the caller must release it independently.
func (s *State) Lock() {
	s.transitions.Lock()
	defer s.transitions.Unlock()
	s.invalidateAuthentication()
	current := s.version.Load()
	if current&1 != 0 {
		s.version.Store(current + 1)
	}
	s.cancelResource()
	s.operations.Lock()
	s.operations.Unlock()
}

// Unlock creates a session only on a locked-to-unlocked transition, after any
// pending drain. Exhaustion leaves the state locked instead of reusing a token.
func (s *State) Unlock() {
	s.transitions.Lock()
	defer s.transitions.Unlock()
	current := s.version.Load()
	if current&1 == 0 && current != ^uint64(0)-1 {
		s.invalidateAuthentication()
		s.version.Store(current + 1)
	}
}

func (s *State) IsLocked() bool { return s.version.Load()&1 == 0 }

// Session captures a coherent active session, or zero/false while locked.
func (s *State) Session() (uint64, bool) {
	current := s.version.Load()
	if current&1 == 0 {
		return 0, false
	}
	return current, true
}

// Valid checks that this session is still active, using one atomic observation.
func (s *State) Valid(session uint64) bool {
	return session&1 != 0 && s.version.Load() == session
}

// Lookup decides access to names directly under the synthetic root.
func (s *State) Lookup(name string) syscall.Errno {
	switch name {
	case VisibleName:
		return 0
	case GhostName:
		if s.IsLocked() {
			return syscall.EACCES
		}
		return 0
	default:
		return syscall.ENOENT
	}
}

// Begin admits work for one session. The returned release must be called
// exactly once when that work finishes, independently of Lock/Unlock. Do not
// acquire another lease recursively: a pending drain blocks new shared locks.
func (s *State) Begin(session uint64) (release func(), ok bool) {
	// Deny requests promptly once revocation is published.
	if !s.Valid(session) {
		return nil, false
	}
	s.operations.RLock()
	// Close the race between the first check and acquiring the shared gate.
	if !s.Valid(session) {
		s.operations.RUnlock()
		return nil, false
	}
	return s.operations.RUnlock, true
}

// Challenge is an opaque, single-state ticket for a locked authorization epoch.
// Lock invalidates outstanding tickets even when the session was already locked.
type Challenge struct {
	owner    *State
	version  uint64
	revision uint64
}

// Challenge does not wait behind an active Lock drain. The broker must not hold
// filesystem leases while requesting authentication or attempting authorization.
func (s *State) Challenge() (Challenge, bool) {
	if !s.transitions.TryLock() {
		return Challenge{}, false
	}
	defer s.transitions.Unlock()
	version := s.version.Load()
	if version&1 != 0 || version == ^uint64(0)-1 || s.authRevision == ^uint64(0) {
		return Challenge{}, false
	}
	return Challenge{owner: s, version: version, revision: s.authRevision}, true
}

// Authorize conditionally creates a session after successful external verification.
// It is nonblocking so broker cancellation never waits on an operation drain.
// A busy transition or any intervening Lock/Unlock rejects the ticket.
func (s *State) Authorize(ticket Challenge) bool {
	if !s.transitions.TryLock() {
		return false
	}
	defer s.transitions.Unlock()
	if !s.matchesChallenge(ticket) {
		return false
	}
	s.invalidateAuthentication()
	s.version.Store(ticket.version + 1)
	return true
}

// Called only under transitions. Never reuse an authentication revision.
func (s *State) invalidateAuthentication() {
	if s.authRevision != ^uint64(0) {
		s.authRevision++
	}
}

// WithChallenge validates and executes only the short initiation step while
// serialized with Lock/Unlock. It does not grant a session or consume a ticket.
// action must not wait for external authentication or reenter State methods.
func (s *State) WithChallenge(ticket Challenge, action func() error) (bool, error) {
	if !s.transitions.TryLock() {
		return false, nil
	}
	defer s.transitions.Unlock()
	if !s.matchesChallenge(ticket) {
		return false, nil
	}
	return true, action()
}

// Caller holds transitions; shared by initiation and final authorization.
func (s *State) matchesChallenge(ticket Challenge) bool {
	version := s.version.Load()
	return ticket.owner == s && ticket.version == version && version&1 == 0 && version != ^uint64(0)-1 && ticket.revision == s.authRevision && s.authRevision != ^uint64(0)
}
