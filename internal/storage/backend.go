//go:build linux

// Package storage owns an isolated foreground gocryptfs mount. It does not
// expose that mount through Veyl or authorize a session on mount success.
package storage

import (
	"context"
	"errors"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/poizdev/veyl/internal/policy"
)

var (
	ErrCredentials = errors.New("gocryptfs rejected credentials")
	ErrBusy        = errors.New("encrypted store or runtime busy")
	ErrClosed      = errors.New("storage backend closed")
	ErrCleanup     = errors.New("decrypted view cleanup incomplete")
	ErrUnsafe      = errors.New("unsafe storage path")
	ErrMount       = errors.New("gocryptfs mount failed")
	ErrStale       = errors.New("stale authentication request")
	ErrUnavailable = errors.New("storage executable unavailable")
	ErrUnmounted   = errors.New("decrypted view unexpectedly unmounted")
)

type Config struct {
	HideFromDesktop                          bool // host has verified fusermount x-* option support
	Store, RuntimeDir, Binary, UnmountBinary string
	StartTimeout, StopTimeout                time.Duration
	BeforeUnmount                            func() error
}
type operations struct {
	start   func(string, []string, []byte) (child, error)
	mounts  func() ([]mountEntry, error)
	unmount func(context.Context, string) error
}

// Backend owns one store. Do not copy or reconfigure it after construction.
type Backend struct {
	cfg      Config
	state    *policy.State
	ops      operations
	gate     chan struct{}
	lifetime context.Context
	shutdown context.CancelFunc
	active   *mount // guarded by gate
}
type mount struct {
	roots    []*os.File // issued session capabilities; closed before external teardown
	owner    *Candidate
	view     *View
	process  child
	store    *os.File
	identity os.FileInfo
	id       uint64
	stop     chan struct{}
	stopOnce sync.Once
}

// View is deliberately outside Veyl's FUSE access policy. Path is private by
// directory permissions, not by session authorization. Done also reports crashes.
type View struct {
	Path string
	done chan struct{}
	once sync.Once
	err  error
}

func (v *View) Done() <-chan struct{} { return v.done }
func (v *View) Err() error {
	select {
	case <-v.done:
		return v.err
	default:
		return nil
	}
}
func (v *View) end(err error) { v.once.Do(func() { v.err = err; close(v.done) }) }

func New(cfg Config, state *policy.State) (*Backend, error) {
	if state == nil {
		return nil, ErrUnsafe
	}
	var err error
	cfg.Binary, err = resolveBinary(cfg.Binary, "gocryptfs")
	if err != nil {
		return nil, err
	}
	cfg.UnmountBinary, err = resolveBinary(cfg.UnmountBinary, "fusermount3")
	if err != nil {
		return nil, err
	}
	if cfg.StartTimeout == 0 {
		cfg.StartTimeout = 10 * time.Second
	}
	if cfg.StopTimeout == 0 {
		cfg.StopTimeout = 3 * time.Second
	}
	if cfg.StartTimeout < 0 || cfg.StopTimeout < 0 {
		return nil, ErrUnsafe
	}
	life, cancel := context.WithCancel(context.Background())
	b := &Backend{cfg: cfg, state: state, gate: make(chan struct{}, 1), lifetime: life, shutdown: cancel,
		ops: operations{start: startCommand, mounts: readMountInfo, unmount: unmountCommand(cfg.UnmountBinary)}}
	b.gate <- struct{}{}
	if err := b.validatePaths(); err != nil {
		cancel()
		return nil, err
	}
	return b, nil
}
func (b *Backend) unlock() { b.gate <- struct{}{} }
func (b *Backend) acquire(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.gate:
		return nil
	}
}

// Mount uses gocryptfs itself as the only credential check. A successful existing
// view is never reused as verification for a second credential. ctx controls the
// entire view lifetime, not only startup. Callers must explicitly adopt/close it.
func (b *Backend) Mount(ctx context.Context, ticket policy.Challenge, password []byte) (*View, error) {
	if err := b.acquire(ctx); err != nil {
		return nil, err
	}
	defer b.unlock()
	return b.mount(ctx, ctx, ticket, password, nil)
}

// Caller holds gate throughout startup.
func (b *Backend) mount(ctx, attempt context.Context, ticket policy.Challenge, password []byte, owner *Candidate) (*View, error) {
	if b.lifetime.Err() != nil {
		return nil, ErrClosed
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if b.active != nil {
		return nil, ErrBusy
	}
	if !validPassword(password) {
		return nil, ErrCredentials
	}
	valid, err := b.state.WithChallenge(ticket, ctx.Err)
	if !valid {
		return nil, ErrStale
	}
	if err != nil {
		return nil, err
	}
	if err := b.validatePaths(); err != nil {
		return nil, err
	}
	store, err := lockStore(b.cfg.Store)
	if err != nil {
		return nil, err
	}
	path, err := os.MkdirTemp(b.cfg.RuntimeDir, "veyl-")
	if err != nil {
		store.Close()
		return nil, ErrUnsafe
	}
	identity, err := os.Lstat(path)
	if err != nil {
		os.Remove(path)
		store.Close()
		return nil, ErrUnsafe
	}
	m := &mount{view: &View{Path: path, done: make(chan struct{})}, store: store, identity: identity, stop: make(chan struct{})}
	m.owner = owner
	if owner != nil {
		owner.mount = m
		owner.owned.Store(true)
	}
	b.active = m
	fail := func(cause error) (*View, error) {
		if err := b.cleanup(m, cause); err != nil {
			return nil, err
		}
		return nil, cause
	}
	startup, cancel := context.WithTimeout(attempt, b.cfg.StartTimeout)
	stopLife := context.AfterFunc(ctx, cancel)
	defer stopLife()
	stop := context.AfterFunc(b.lifetime, cancel)
	defer cancel()
	defer stop()
	args := []string{"-fg", "-q", "-nosyslog"}
	if b.cfg.HideFromDesktop {
		args = append(args, "-ko", "x-gvfs-hide")
	}
	args = append(args, "-passfile", credentialFD, "--", b.cfg.Store, path)
	valid, err = b.state.WithChallenge(ticket, func() error {
		if b.lifetime.Err() != nil {
			return ErrClosed
		}
		if err := startup.Err(); err != nil {
			return err
		}
		p, err := b.ops.start(b.cfg.Binary, args, password)
		m.process = p
		return err
	})
	if !valid {
		return fail(ErrStale)
	}
	if err != nil {
		return fail(err)
	}
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if b.lifetime.Err() != nil {
			return fail(ErrClosed)
		}
		if startup.Err() != nil {
			return fail(startup.Err())
		}
		select {
		case <-m.process.Exited():
			select {
			case <-m.process.Done():
			case <-startup.Done():
				return fail(startup.Err())
			}
			if m.process.ExitCode() == 12 {
				return fail(ErrCredentials)
			}
			return fail(ErrMount)
		default:
		}
		valid, _ := b.state.WithChallenge(ticket, func() error { return nil })
		if !valid {
			return fail(ErrStale)
		}
		entry, mounted, err := b.entry(path)
		if err != nil {
			return fail(ErrUnsafe)
		}
		if mounted {
			if !b.owns(m, entry) {
				return fail(ErrUnsafe)
			}
			m.id = entry.ID
			// Readiness is an observation, not a promise that a process cannot crash
			// next. The watcher owns teardown after this observation is published.
			if b.lifetime.Err() != nil {
				return fail(ErrClosed)
			}
			if startup.Err() != nil {
				return fail(startup.Err())
			}
			valid, err = b.state.WithChallenge(ticket, func() error {
				if b.lifetime.Err() != nil {
					return ErrClosed
				}
				return startup.Err()
			})
			if !valid {
				return fail(ErrStale)
			}
			if err != nil {
				return fail(err)
			}
			select {
			case <-m.process.Exited():
				return fail(ErrMount)
			default:
			}
			go b.watch(m, ctx)
			return m.view, nil
		}
		select {
		case <-startup.Done():
		case <-m.process.Done():
		case <-tick.C:
		}
	}
}
func (b *Backend) Mounted() bool {
	<-b.gate
	defer b.unlock()
	m := b.active
	if m == nil || m.process == nil {
		return false
	}
	select {
	case <-m.process.Exited():
		return false
	default:
	}
	entry, found, err := b.entry(m.view.Path)
	return err == nil && found && b.owns(m, entry)
}
func (b *Backend) Unmount(ctx context.Context) error {
	if err := b.acquire(ctx); err != nil {
		return err
	}
	defer b.unlock()
	if b.active == nil {
		return nil
	}
	return b.cleanup(b.active, nil)
}
func (b *Backend) Close() error {
	b.shutdown() // Interrupt startup before waiting for the serialized lifecycle.
	<-b.gate
	defer b.unlock()
	if b.active == nil {
		return nil
	}
	return b.cleanup(b.active, nil)
}
func (b *Backend) watch(m *mount, ctx context.Context) {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	var cause error
	for cause == nil {
		select {
		case <-m.stop:
			return
		case <-ctx.Done():
			cause = ctx.Err()
		case <-b.lifetime.Done():
			cause = ErrClosed
		case <-m.process.Exited():
			cause = ErrMount
		case <-tick.C:
			entry, found, err := b.entry(m.view.Path)
			if err != nil || !found || !b.owns(m, entry) {
				cause = ErrUnmounted
			}
		}
	}
	b.lost(m) // Revoke admission before waiting for cleanup or the gate.
	<-b.gate
	defer b.unlock()
	if b.active == m {
		_ = b.cleanup(m, cause)
	}
}
func (b *Backend) stopChild(p child) bool {
	if p == nil {
		return true
	}
	select {
	case <-p.Done():
		return true
	default:
	}
	_ = p.Signal(syscall.SIGTERM)
	timer := time.NewTimer(b.cfg.StopTimeout)
	defer timer.Stop()
	select {
	case <-p.Done():
		return true
	case <-timer.C:
	}
	_ = p.Signal(syscall.SIGKILL)
	timer.Reset(b.cfg.StopTimeout)
	select {
	case <-p.Done():
		return true
	case <-timer.C:
		return false
	}
}

// cleanup never recursively deletes paths. On failure it retains the path,
// process record and store lock for an explicit retry, and marks the view ended.
func (b *Backend) cleanup(m *mount, cause error) error {
	b.lost(m)
	if b.cfg.BeforeUnmount != nil {
		if err := b.cfg.BeforeUnmount(); err != nil {
			m.view.end(ErrCleanup)
			return ErrCleanup
		}
	}
	for _, root := range m.roots {
		_ = root.Close()
	}
	m.roots = nil
	m.stopOnce.Do(func() { close(m.stop) })
	entry, mounted, err := b.entry(m.view.Path)
	safe := err == nil && (!mounted || b.owns(m, entry))
	if safe && mounted {
		ctx, cancel := context.WithTimeout(context.Background(), b.cfg.StopTimeout)
		_ = b.ops.unmount(ctx, m.view.Path)
		cancel()
	}
	stopped := b.stopChild(m.process)
	_, mounted, err = b.entry(m.view.Path)
	if !safe || !stopped || err != nil || mounted {
		m.view.end(ErrCleanup)
		return ErrCleanup
	}
	info, err := os.Lstat(m.view.Path)
	if err != nil || !info.IsDir() || !os.SameFile(info, m.identity) {
		m.view.end(ErrCleanup)
		return ErrCleanup
	}
	if err := os.Remove(m.view.Path); err != nil {
		m.view.end(ErrCleanup)
		return ErrCleanup
	}
	if m.store != nil {
		m.store.Close()
	}
	b.active = nil
	if m.owner != nil {
		m.owner.owned.Store(false)
	}
	m.view.end(cause)
	return nil
}
