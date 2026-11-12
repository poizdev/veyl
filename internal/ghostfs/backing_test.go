//go:build linux

package ghostfs

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/poizdev/veyl/internal/policy"
	"golang.org/x/sys/unix"
)

// Only the session-root acquisition boundary is replaced. All resolution,
// metadata, I/O, FUSE node handling and policy draining use real implementations.
type fixtureBacking struct {
	path  string
	state *policy.State
	epoch uint64
	life  context.Context
}

func (b *fixtureBacking) SessionRoot(_ context.Context, s *policy.State, epoch uint64) (*os.File, context.Context, error) {
	if s != b.state || epoch != b.epoch || !s.Valid(epoch) {
		return nil, nil, syscall.EACCES
	}
	fd, err := unix.Open(b.path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fd), "fixture-root"), b.life, nil
}
func backingFixture(t *testing.T) (*Root, *fixtureBacking, string) {
	t.Helper()
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "nested", "payload"), []byte("real synthetic payload"), 0640); err != nil {
		t.Fatal(err)
	}
	r := &Root{}
	b := &fixtureBacking{path: base, state: &r.State}
	r.Backing = b
	fs.NewNodeFS(r, Options())
	adoptFixture(t, r, b)
	t.Cleanup(r.State.Lock)
	return r, b, base
}
func adoptFixture(t *testing.T, r *Root, b *fixtureBacking) {
	t.Helper()
	ticket, ok := r.State.Challenge()
	if !ok {
		t.Fatal("challenge")
	}
	life, cancel := context.WithCancel(context.Background())
	epoch, ok := r.State.Adopt(ticket, func() bool { return true }, cancel)
	if !ok {
		cancel()
		t.Fatal("adopt")
	}
	b.epoch, b.life = epoch, life
}
func backingGhost(t *testing.T, r *Root) *fs.Inode {
	t.Helper()
	n, e := r.Lookup(context.Background(), policy.GhostName, &fuse.EntryOut{})
	if e != 0 {
		t.Fatal(e)
	}
	return n
}
func backingLookup(t *testing.T, parent *fs.Inode, name string) *fs.Inode {
	t.Helper()
	n, e := parent.Operations().(fs.NodeLookuper).Lookup(context.Background(), name, &fuse.EntryOut{})
	if e != 0 {
		t.Fatal(e)
	}
	return n
}
func backingRead(t *testing.T, n *fs.Inode, fh fs.FileHandle, want string) {
	t.Helper()
	result, e := n.Operations().(fs.NodeReader).Read(context.Background(), fh, make([]byte, 128), 0)
	if e != 0 {
		t.Fatal(e)
	}
	defer result.Done()
	data, status := result.Bytes(make([]byte, 128))
	if status != fuse.OK || string(data) != want {
		t.Fatal("incorrect backing contents")
	}
}
func TestBackingNestedReadMetadataAndRevocation(t *testing.T) {
	r, b, _ := backingFixture(t)
	assertRootListing(t, r)
	ghost := backingGhost(t, r)
	dir := backingLookup(t, ghost, "nested")
	file := backingLookup(t, dir, "payload")
	if e := file.Operations().(fs.NodeAccesser).Access(context.Background(), 4); e != 0 {
		t.Fatalf("file read access: %v", e)
	}
	if e := dir.Operations().(fs.NodeAccesser).Access(context.Background(), 1); e != 0 {
		t.Fatalf("directory search access: %v", e)
	}
	var attr fuse.AttrOut
	if e := file.Operations().(fs.NodeGetattrer).Getattr(context.Background(), nil, &attr); e != 0 || attr.Size != 22 || attr.Mode != syscall.S_IFREG|0440 {
		t.Fatalf("metadata: %v %+v", e, attr.Attr)
	}
	fh, flags, e := file.Operations().(fs.NodeOpener).Open(context.Background(), 0)
	if e != 0 || flags&fuse.FOPEN_DIRECT_IO == 0 {
		t.Fatal("protected direct open")
	}
	backingRead(t, file, fh, "real synthetic payload")
	dh, _, e := dir.Operations().(fs.NodeOpendirHandler).OpendirHandle(context.Background(), 0)
	if e != 0 {
		t.Fatal(e)
	}
	entry, e := dh.(fs.FileReaddirenter).Readdirent(context.Background())
	if e != 0 || entry == nil || entry.Name != "payload" {
		t.Fatal("real directory enumeration")
	}
	r.State.Lock()
	for range 2 {
		result, e := file.Operations().(fs.NodeReader).Read(context.Background(), fh, make([]byte, 32), 0)
		if result != nil {
			result.Done()
		}
		if e != syscall.EACCES {
			t.Fatalf("old handle: %v", e)
		}
		if e := file.Operations().(fs.NodeGetattrer).Getattr(context.Background(), nil, &fuse.AttrOut{}); e != syscall.EACCES {
			t.Fatalf("old getattr: %v", e)
		}
		if _, e := dh.(fs.FileReaddirenter).Readdirent(context.Background()); e != syscall.EACCES {
			t.Fatalf("old directory: %v", e)
		}
		if r.State.IsLocked() {
			adoptFixture(t, r, b)
			fresh := backingLookup(t, backingLookup(t, backingGhost(t, r), "nested"), "payload")
			freshHandle, _, e := fresh.Operations().(fs.NodeOpener).Open(context.Background(), 0)
			if e != 0 {
				t.Fatal(e)
			}
			backingRead(t, fresh, freshHandle, "real synthetic payload")
		}
	}
	assertRootListing(t, r)
}
func TestBackingRejectsTraversalSymlinksAndReplacement(t *testing.T) {
	r, _, base := backingFixture(t)
	if err := os.Symlink("nested", filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", filepath.Join(base, "outside")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(base, "pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	ghost := backingGhost(t, r)
	for _, name := range []string{"..", ".", "../escape", "/etc/passwd", "nested/payload", "link", "outside", "pipe", "bad\x00name"} {
		if n, e := ghost.Operations().(fs.NodeLookuper).Lookup(context.Background(), name, &fuse.EntryOut{}); e == 0 || n != nil {
			t.Fatalf("unsafe lookup accepted: %q", name)
		}
	}
	dir := backingLookup(t, ghost, "nested")
	file := backingLookup(t, dir, "payload")
	fh, _, e := file.Operations().(fs.NodeOpener).Open(context.Background(), 0)
	if e != 0 {
		t.Fatal(e)
	}
	if err := os.Rename(filepath.Join(base, "nested"), filepath.Join(base, "old")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("old", filepath.Join(base, "nested")); err != nil {
		t.Fatal(err)
	}
	if result, e := file.Operations().(fs.NodeReader).Read(context.Background(), fh, make([]byte, 32), 0); e == 0 {
		result.Done()
		t.Fatal("replacement symlink followed")
	}
}
func TestBackingReadDrainsAndConcurrentLock(t *testing.T) {
	r, _, _ := backingFixture(t)
	ghost := backingGhost(t, r)
	file := backingLookup(t, backingLookup(t, ghost, "nested"), "payload")
	fh, _, e := file.Operations().(fs.NodeOpener).Open(context.Background(), 0)
	if e != 0 {
		t.Fatal(e)
	}
	result, e := file.Operations().(fs.NodeReader).Read(context.Background(), fh, make([]byte, 32), 0)
	if e != 0 {
		t.Fatal(e)
	}
	defer result.Done()
	locked := pendingLock(t, &r.State)
	requirePending(t, locked)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, e := ghost.Operations().(fs.NodeLookuper).Lookup(context.Background(), "nested", &fuse.EntryOut{}); e != syscall.EACCES {
				t.Errorf("revoked lookup: %v", e)
			}
		})
	}
	wg.Wait()
	result.Done()
	requireCompleted(t, locked)
}
func TestBackingRejectsMutations(t *testing.T) {
	r, _, _ := backingFixture(t)
	ghost := backingGhost(t, r)
	file := backingLookup(t, backingLookup(t, ghost, "nested"), "payload")
	for _, flags := range []uint32{syscall.O_WRONLY, syscall.O_RDWR, syscall.O_TRUNC, syscall.O_APPEND, syscall.O_CREAT} {
		if _, _, e := file.Operations().(fs.NodeOpener).Open(context.Background(), flags); e != syscall.EROFS {
			t.Fatalf("write open: %v", e)
		}
	}
	if e := file.Operations().(fs.NodeAccesser).Access(context.Background(), 2); e != syscall.EROFS {
		t.Fatal(e)
	}
	if e := file.Operations().(fs.NodeSetattrer).Setattr(context.Background(), nil, &fuse.SetAttrIn{}, &fuse.AttrOut{}); e != syscall.EROFS {
		t.Fatal(e)
	}
	if e := ghost.Operations().(fs.NodeUnlinker).Unlink(context.Background(), "nested"); e != syscall.EROFS {
		t.Fatal(e)
	}
	if e := ghost.Operations().(fs.NodeRmdirer).Rmdir(context.Background(), "nested"); e != syscall.EROFS {
		t.Fatal(e)
	}
	if e := ghost.Operations().(fs.NodeRenamer).Rename(context.Background(), "nested", ghost.Operations(), "other", 0); e != syscall.EROFS {
		t.Fatal(e)
	}
}

func TestBackingRawHardlinkAliasesRemainUsable(t *testing.T) {
	r := &Root{}
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "a"), []byte("alias payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(base, "a"), filepath.Join(base, "b")); err != nil {
		t.Fatal(err)
	}
	b := &fixtureBacking{path: base, state: &r.State}
	r.Backing = b
	raw := fs.NewNodeFS(r, Options())
	adoptFixture(t, r, b)
	t.Cleanup(r.State.Lock)
	var ghost, first, second fuse.EntryOut
	if status := raw.Lookup(nil, &fuse.InHeader{NodeId: 1}, policy.GhostName, &ghost); status != fuse.OK {
		t.Fatal(status)
	}
	for _, item := range []struct {
		name string
		out  *fuse.EntryOut
	}{{"a", &first}, {"b", &second}} {
		if status := raw.Lookup(nil, &fuse.InHeader{NodeId: ghost.NodeId}, item.name, item.out); status != fuse.OK {
			t.Fatal(status)
		}
	}
	if err := os.Remove(filepath.Join(base, "a")); err != nil {
		t.Fatal(err)
	}
	var fresh fuse.EntryOut
	if status := raw.Lookup(nil, &fuse.InHeader{NodeId: ghost.NodeId}, "b", &fresh); status != fuse.OK {
		t.Fatal(status)
	}
	var opened fuse.OpenOut
	if status := raw.Open(nil, &fuse.OpenIn{InHeader: fuse.InHeader{NodeId: fresh.NodeId}}, &opened); status != fuse.OK {
		t.Fatalf("surviving alias open: %v", status)
	}
	defer raw.Release(nil, &fuse.ReleaseIn{InHeader: fuse.InHeader{NodeId: fresh.NodeId}, Fh: opened.Fh})
	result, status := raw.Read(nil, &fuse.ReadIn{InHeader: fuse.InHeader{NodeId: fresh.NodeId}, Fh: opened.Fh, Size: 32}, make([]byte, 32))
	if status != fuse.OK {
		t.Fatal(status)
	}
	defer result.Done()
	data, status := result.Bytes(make([]byte, 32))
	if status != fuse.OK || string(data) != "alias payload" {
		t.Fatal("alias contents")
	}
}
