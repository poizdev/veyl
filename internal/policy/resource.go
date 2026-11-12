package policy

// Adopt conditionally attaches a nonblocking cancellation to a new epoch.
// valid must be short, must not reenter State, and runs under transitions.
// cancel must only signal cancellation; teardown runs outside transition locks.
func (s *State) Adopt(ticket Challenge, valid func() bool, cancel func()) (uint64, bool) {
	if cancel == nil || valid == nil || !s.transitions.TryLock() {
		return 0, false
	}
	defer s.transitions.Unlock()
	if !s.matchesChallenge(ticket) || !valid() {
		return 0, false
	}
	s.invalidateAuthentication()
	s.revokeResource = cancel
	epoch := ticket.version + 1
	s.version.Store(epoch)
	return epoch, true
}

// Revoke invalidates only the supplied epoch, including its admitted I/O drain.
// Resource failure observers must use this instead of an unconditional Lock.
func (s *State) Revoke(epoch uint64) {
	if !s.Valid(epoch) {
		return
	}
	s.transitions.Lock()
	defer s.transitions.Unlock()
	if !s.Valid(epoch) {
		return
	}
	s.invalidateAuthentication()
	s.version.Store(epoch + 1)
	s.cancelResource()
	s.operations.Lock()
	s.operations.Unlock()
}
func (s *State) cancelResource() {
	if s.revokeResource != nil {
		s.revokeResource()
		s.revokeResource = nil
	}
}
