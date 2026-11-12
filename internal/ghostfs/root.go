// Package ghostfs implements Veyl's concealed FUSE namespace.
// The CLI supplies an authenticated backing; tests can use synthetic content.
package ghostfs

import (
	"context"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/poizdev/veyl/internal/auth"
	"github.com/poizdev/veyl/internal/policy"
)

const VisibleContent = "Hello from Veyl.\n"
const visibleIno = 2
const ghostIno = 3
const helloIno = 4

// Root serves a public namespace and one protected directory. A nil Backing
// selects synthetic protected content for in-process callers.
// State is shared with every protected inode.
// Its zero value is locked. A Root must not be copied after first use.
type Root struct {
	fs.Inode
	State          policy.State
	ExplicitUnlock bool
	Writable       bool
	HiddenName     string         // optional configured name; empty selects policy.GhostName
	Auth           *auth.Broker   // authentication broker; configure before mounting
	Backing        SessionBacking // authenticated session backing; configure before mounting
	backingMu      sync.Mutex
	tree           *backingTree
	parent         *backingNode
	parentPath     string
	parentMount    uint64
	originalMount  atomic.Uint64
	originalParent bool
	originalTarget syscall.Stat_t
}

var (
	_ fs.NodeReaddirer = (*Root)(nil)
	_ fs.NodeLookuper  = (*Root)(nil)
	_ fs.NodeGetattrer = (*Root)(nil)
)

func (r *Root) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	if r.parent != nil {
		if r.NamespaceError() != nil {
			return nil, syscall.ESTALE
		}
		handle, _, e := r.parent.OpendirHandle(ctx, 0)
		if e != 0 {
			return nil, e
		}
		h := handle.(*backingDirHandle)
		defer h.Releasedir(ctx, 0)
		entries := make([]fuse.DirEntry, 0, len(h.entries))
		for _, entry := range h.entries {
			if entry.Name != r.hidden() {
				entries = append(entries, entry)
			}
		}
		return fs.NewListDirStream(entries), 0
	}
	// Never derive this listing from cached children: .troll can be cached there.
	return fs.NewListDirStream([]fuse.DirEntry{{Name: policy.VisibleName, Mode: syscall.S_IFREG, Ino: visibleIno}}), 0
}

func (r *Root) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if r.parent != nil {
		if r.NamespaceError() != nil {
			return nil, syscall.ESTALE
		}
		if name != r.hidden() {
			return r.parent.Lookup(ctx, name, out)
		}
		name = policy.GhostName
	}
	// The configured pathname is an alias for the existing logical resource,
	// never a second policy/session. Do not leave the default name accessible.
	if r.parent == nil && r.HiddenName != "" && r.HiddenName != policy.GhostName {
		if name == policy.GhostName {
			return nil, syscall.ENOENT
		}
		if name == r.HiddenName {
			name = policy.GhostName
		}
	}
	// Authentication happens before acquiring an operation lease. Cached/stale
	// inodes never trigger a new prompt; only direct locked ghost lookup does.
	if name == policy.GhostName && r.State.IsLocked() {
		if r.ExplicitUnlock || r.Auth == nil || r.Auth.RequestAccess(ctx) != nil {
			return nil, syscall.EACCES
		}
	}
	if errno := r.State.Lookup(name); errno != 0 {
		return nil, errno
	}
	if name == policy.GhostName {
		session, ok := r.State.Session()
		if !ok {
			return nil, syscall.EACCES
		}
		if r.Backing != nil {
			return r.lookupBacking(ctx, session, out)
		}
		release, errno := beginOperation(&r.State, session)
		if errno != 0 {
			return nil, errno
		}
		defer release()
		dir := &ghostDirectory{state: &r.State, session: session}
		dir.attr(&out.Attr)
		return r.NewInode(ctx, dir, fs.StableAttr{Mode: syscall.S_IFDIR, Ino: ghostIno, Gen: session}), 0
	}
	file := &textFile{content: VisibleContent, ino: visibleIno}
	file.attr(&out.Attr)
	return r.NewInode(ctx, file, fs.StableAttr{Mode: syscall.S_IFREG, Ino: visibleIno}), 0
}

func (r *Root) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if r.parent != nil {
		return r.parent.Getattr(ctx, fh, out)
	}
	out.Mode = syscall.S_IFDIR | 0555
	out.Nlink = 2
	return 0
}

// Options keeps the entire mount read-only, including unimplemented mutations.
func Options() *fs.Options { return OptionsFor(false) }

func OptionsFor(writable bool) *fs.Options {
	zero := time.Duration(0)
	mode := "ro"
	if writable {
		mode = "rw"
	}
	return &fs.Options{
		MountOptions: fuse.MountOptions{Options: []string{mode}, FsName: "veyl", Name: "veyl"},
		EntryTimeout: &zero, AttrTimeout: &zero, NegativeTimeout: &zero,
		NullPermissions: true,
	}
}

// OptionsForDesktop adds only a userspace visibility hint after helper
// compatibility has been checked by the host. Keep DirectMount disabled: the
// kernel does not accept x-* options. This is not an access-control setting.
func OptionsForDesktop(writable, hide bool) *fs.Options {
	opts := OptionsFor(writable)
	if hide {
		opts.Options = append(opts.Options, "x-gvfs-hide")
	}
	return opts
}
