package ghostfs

import (
	"context"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/poizdev/veyl/internal/policy"
)

func pendingLock(t *testing.T, state *policy.State) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() { state.Lock(); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for !state.IsLocked() {
		if time.Now().After(deadline) {
			t.Fatal("Lock did not publish revocation")
		}
		runtime.Gosched()
	}
	return done
}

func requirePending(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
		t.Error("Lock returned before protected read finished")
	default:
	}
}

func requireCompleted(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Lock did not drain; possible deadlock")
	}
}

func TestLockDrainsProtectedReadResults(t *testing.T) {
	root := testRoot()
	file := ghostFile(t, unlockedGhost(t, root))
	fh, _, e := file.Open(context.Background(), 0)
	if e != 0 {
		t.Fatal(e)
	}
	var results []fuse.ReadResult
	defer func() {
		for _, result := range results {
			result.Done()
		}
	}()
	for range 3 {
		result, e := file.Read(context.Background(), fh, make([]byte, 4096), 0)
		if e != 0 {
			t.Fatal(e)
		}
		results = append(results, result)
	}
	locked := pendingLock(t, &root.State)
	requirePending(t, locked)
	if result, e := file.Read(context.Background(), fh, make([]byte, 32), 0); e != syscall.EACCES {
		if result != nil {
			result.Done()
		}
		t.Fatalf("new read while revoking: %v", e)
	}
	// Copy returned plaintext; draining does not erase the caller's own copy.
	data, status := results[0].Bytes(make([]byte, 4096))
	plaintext := append([]byte(nil), data...)
	if status != fuse.OK || string(plaintext) != HelloContent {
		t.Fatal("admitted read corrupted")
	}
	results[0].Done()
	results[1].Done()
	requirePending(t, locked)
	results[2].Done()
	requireCompleted(t, locked)
	if string(plaintext) != HelloContent {
		t.Fatal("already returned data changed")
	}
	root.State.Unlock()
	if result, e := file.Read(context.Background(), fh, make([]byte, 32), 0); e != syscall.EACCES {
		if result != nil {
			result.Done()
		}
		t.Fatalf("old handle revived: %v", e)
	}
	fresh := ghostFile(t, unlockedGhost(t, root))
	freshHandle, _, e := fresh.Open(context.Background(), 0)
	if e != 0 {
		t.Fatal(e)
	}
	readContent(t, fresh, freshHandle, HelloContent)
}

func TestConcurrentReadResultCompletion(t *testing.T) {
	root := testRoot()
	file := ghostFile(t, unlockedGhost(t, root))
	fh, _, e := file.Open(context.Background(), 0)
	if e != 0 {
		t.Fatal(e)
	}
	result, e := file.Read(context.Background(), fh, make([]byte, 32), 0)
	if e != 0 {
		t.Fatal(e)
	}
	locked := pendingLock(t, &root.State)
	requirePending(t, locked)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(result.Done)
	}
	wg.Wait()
	requireCompleted(t, locked)
}

func TestReadErrorsDoNotLeakAdmission(t *testing.T) {
	root := testRoot()
	file := ghostFile(t, unlockedGhost(t, root))
	fh, _, e := file.Open(context.Background(), 0)
	if e != 0 {
		t.Fatal(e)
	}
	if result, e := file.Read(context.Background(), fh, make([]byte, 32), -1); e != syscall.EINVAL || result != nil {
		t.Fatalf("negative read: %v", e)
	}
	result, e := file.Read(context.Background(), fh, make([]byte, 32), int64(len(HelloContent)))
	if e != 0 {
		t.Fatal(e)
	}
	result.Done()
	if _, _, e := file.Open(context.Background(), syscall.O_WRONLY); e != syscall.EROFS {
		t.Fatal(e)
	}
	requireCompleted(t, pendingLock(t, &root.State))
}

func TestEmptyReadCompletesWithoutDone(t *testing.T) {
	for _, eof := range []bool{false, true} {
		t.Run(map[bool]string{false: "zero length", true: "EOF"}[eof], func(t *testing.T) {
			root := testRoot()
			file := ghostFile(t, unlockedGhost(t, root))
			fh, _, e := file.Open(context.Background(), 0)
			if e != 0 {
				t.Fatal(e)
			}
			var off int64
			dest := make([]byte, 0)
			if eof {
				off = int64(len(HelloContent))
				dest = make([]byte, 32)
			}
			result, e := file.Read(context.Background(), fh, dest, off)
			if e != 0 {
				t.Fatal(e)
			}
			defer result.Done()
			if result.Size() != 0 {
				t.Fatal("expected empty result")
			}
			// go-fuse v2.12.0's Linux zero-payload write path does not call Done.
			// With no plaintext payload left to deliver, callback completion must drain.
			requireCompleted(t, pendingLock(t, &root.State))
		})
	}
}

// A revoked directory request must not wait behind a cursor mutex; admission
// precedes that mutex. Holding a read result keeps Lock observably in its drain.
func TestRevokedDirectoryRequestsDoNotWaitForCursor(t *testing.T) {
	root := testRoot()
	dir := unlockedGhost(t, root)
	file := ghostFile(t, dir)
	fh, _, e := file.Open(context.Background(), 0)
	if e != 0 {
		t.Fatal(e)
	}
	result, e := file.Read(context.Background(), fh, make([]byte, 32), 0)
	if e != 0 {
		t.Fatal(e)
	}
	defer result.Done()
	handle, _, e := dir.OpendirHandle(context.Background(), 0)
	if e != 0 {
		t.Fatal(e)
	}
	dh := handle.(*ghostDirectoryHandle)
	dh.mu.Lock()
	defer dh.mu.Unlock()
	locked := pendingLock(t, &root.State)
	requirePending(t, locked)
	complete := make(chan struct{})
	go func() {
		defer close(complete)
		if _, e := dh.Readdirent(context.Background()); e != syscall.EACCES {
			t.Errorf("revoked directory read: %v", e)
		}
		if e := dh.Seekdir(context.Background(), 0); e != syscall.EACCES {
			t.Errorf("revoked directory seek: %v", e)
		}
	}()
	requireCompleted(t, complete)
	result.Done()
	requireCompleted(t, locked)
}

type completionBarrier struct {
	fuse.ReadResult
	entered chan struct{}
	resume  chan struct{}
}

func (r *completionBarrier) Done() {
	close(r.entered)
	<-r.resume
	r.ReadResult.Done()
}

func TestLockWaitsForReadCompletionCleanup(t *testing.T) {
	root := testRoot()
	file := ghostFile(t, unlockedGhost(t, root))
	fh, _, e := file.Open(context.Background(), 0)
	if e != 0 {
		t.Fatal(e)
	}
	result, e := file.Read(context.Background(), fh, make([]byte, 32), 0)
	if e != 0 {
		t.Fatal(e)
	}
	leased := result.(*leasedReadResult)
	barrier := &completionBarrier{ReadResult: leased.ReadResult, entered: make(chan struct{}), resume: make(chan struct{})}
	leased.ReadResult = barrier
	var once sync.Once
	resume := func() { once.Do(func() { close(barrier.resume) }) }
	defer resume()
	completed := make(chan struct{})
	go func() { result.Done(); close(completed) }()
	requireCompleted(t, barrier.entered)
	locked := pendingLock(t, &root.State)
	requirePending(t, locked)
	resume()
	requireCompleted(t, completed)
	requireCompleted(t, locked)
}

func TestBridgeReadResultDrainsBeforeLockReturns(t *testing.T) {
	root := &Root{}
	raw := fs.NewNodeFS(root, Options())
	root.State.Unlock()
	var ghost, hello fuse.EntryOut
	if status := raw.Lookup(nil, &fuse.InHeader{NodeId: 1}, ".troll", &ghost); status != fuse.OK {
		t.Fatal(status)
	}
	if status := raw.Lookup(nil, &fuse.InHeader{NodeId: ghost.NodeId}, "hello.txt", &hello); status != fuse.OK {
		t.Fatal(status)
	}
	open := fuse.OpenIn{InHeader: fuse.InHeader{NodeId: hello.NodeId}}
	var handle fuse.OpenOut
	if status := raw.Open(nil, &open, &handle); status != fuse.OK {
		t.Fatal(status)
	}
	defer raw.Release(nil, &fuse.ReleaseIn{InHeader: open.InHeader, Fh: handle.Fh})
	input := fuse.ReadIn{InHeader: open.InHeader, Fh: handle.Fh, Size: 4096}
	result, status := raw.Read(nil, &input, make([]byte, 4096))
	if status != fuse.OK {
		t.Fatal(status)
	}
	defer result.Done()
	locked := pendingLock(t, &root.State)
	requirePending(t, locked)
	denied, status := raw.Read(nil, &input, make([]byte, 4096))
	if denied != nil {
		denied.Done()
	}
	if status != fuse.EACCES {
		t.Fatalf("raw read while revoking: %v", status)
	}
	data, status := result.Bytes(make([]byte, 4096))
	if status != fuse.OK || string(data) != HelloContent {
		t.Fatalf("admitted raw read: %q, %v", data, status)
	}
	result.Done()
	requireCompleted(t, locked)
	root.State.Unlock()
	denied, status = raw.Read(nil, &input, make([]byte, 4096))
	if denied != nil {
		denied.Done()
	}
	if status != fuse.EACCES {
		t.Fatalf("raw stale handle revived: %v", status)
	}
}
