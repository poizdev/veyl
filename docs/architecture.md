# Architecture

This describes the v0.1.0-rc.1 development candidate. Default initialization uses
original-path v2 presentation; the synthetic root described below is the legacy
v1 layout without a managed parent.

Veyl runs one foreground Go process per configured mount, either manually or
supervised by its opt-in systemd user service. It exposes a synthetic
root containing public `visible.txt` and a protected virtual directory, `.troll`
by default. Root enumeration deliberately omits the protected name. Successful
authentication connects that path to a managed gocryptfs plaintext mount; Veyl's
FUSE interface supports authenticated writes when configured. An optional managed
parent replaces the synthetic public file with ordinary sibling contents from a
pinned backing directory. Default original-path v2 instead overlays the original parent, using its pre-mount descriptor and an identified empty target. Legacy v1 retains the separate empty mountpoint.

## Packages

| Package | Responsibility |
| --- | --- |
| `cmd/veyl` | Process entry point and signal context. |
| `internal/app` | CLI, v1/v2 configuration/discovery, first-run setup, user-service integration, instance ownership, Unix control and shutdown. |
| `internal/credential` | Graphical pinentry protocol and explicit controlling-terminal password input. |
| `internal/auth` | Shared authentication requests, cancellation and transactional resource adoption. |
| `internal/policy` | Authorization challenges, session epochs, operation admission and revocation/draining. |
| `internal/storage` | gocryptfs initialization, process supervision, mount identity, backing descriptors and cleanup. |
| `internal/ghostfs` | Concealed root enumeration, session-bound inodes/handles and descriptor-relative backing traversal and mutations. |
| `internal/mountpoint` | Empty mountpoint and path-safety validation. |

The CLI owns operational resources; policy owns authorization. There is no
independent session state machine in the control server. Status combines policy,
broker activity and retained storage ownership, with cleanup pending taking
precedence over ordinary locked/unlocked states.

## Authentication and adoption

A direct locked lookup of the protected name requests authentication before
acquiring an I/O lease. Listings and unknown names never prompt. Concurrent
requesters join one broker flight; the first requester selects graphical or
explicit terminal input. Canceling one waiter does not cancel the others;
canceling the last waiter retires the request.

An agent response is not authorization. The storage backend prepares a fresh
gocryptfs mount using a bounded password passed through an anonymous inherited
pipe at `/proc/self/fd/3`. It returns a candidate owning the process, mount and
store lock. The final commit checks the policy challenge, live waiters,
cancellation, backend lifetime and observed process health before adopting the
resource into a new session. Stale or rejected candidates roll back. Failed
rollback retains ownership and blocks new authentication until cleanup succeeds.

A challenge is bound to one policy instance, locked version and authentication
revision. Every lock invalidates pending challenges, even if already locked.
Session identifiers and revisions are never reused after exhaustion. The
broker bounds outstanding workers; a noncooperative backend cannot create an
unbounded set of abandoned workers. Go cannot forcibly terminate such a worker.

Authentication code must not synchronously access the Veyl mount. Context-based
recursion detection does not survive a fresh kernel FUSE request. Credential
executables, GUI assets, configuration and encrypted stores must remain outside
the protected mount to avoid recursive authentication and deadlocks.

## Revocation and lock ordering

Protected nodes and handles retain their original epoch. An operation validates
that epoch before and after acquiring a shared policy lease. Lock serializes
transitions, publishes revocation, cancels the associated resource lifetime,
then exclusively acquires the operation gate to drain admitted work. Fresh
sessions cannot be published during that drain. Old handles never acquire a
later session; callers must reopen paths after unlocking.

Maintain these ordering rules when modifying the filesystem:

- Do not hold a policy I/O lease while authenticating or acquiring a backend
  session-root descriptor. Backend cleanup can hold its lifecycle gate while
  revoking/draining; reversing this order can deadlock.
- A lease holder must not call Lock/Unlock, acquire a lease recursively, or wait
  for another transition. Release every admitted operation exactly once.
- Acquire directory cursor locks after operation admission. Release cursor
  locks before releasing admission; Lock does not acquire cursor locks.
- Candidate commit is a short ownership decision. External authentication,
  process waits, rollback and unmount must run outside broker/policy transition
  locks. Candidate methods release their mutex before acquiring the backend
  lifecycle gate for cleanup.

Nonempty protected reads transfer their lease to a `ReadResult` wrapper until
`Done`. With the configured Linux go-fuse transport, completion follows the
reply-write attempt; it is not a guarantee of kernel receipt or client visibility.
Empty reads/EOF release their lease in the callback because go-fuse skips `Done`
on zero-payload replies. Tests calling raw callbacks must complete nonempty
results themselves. A blocked result or I/O can delay lock without a timeout
bypass. Root listings and the public file do not require protected leases.

## Backing traversal and metadata

Only an adopted matching policy/epoch can obtain a session-root descriptor.
Linux procfs must be mounted. The backend binds that descriptor to the verified gocryptfs mount ID using
`statx`. Ghostfs resolves relative paths with `openat2` beneath the pinned root,
rejecting symlinks, magic links and mount crossings. There is no weaker fallback
for kernels lacking these facilities. Descriptor-relative syscalls synchronize
with descriptor closure through `SyscallConn.Control`.

Writable directories reuse one pinned node/virtual identity per object for the
tree lifetime, preserving getcwd across repeated lookups and renames. These pins
close at tree teardown. Unlinked, forgotten directory pins retire sooner; linked
directory pins remain stable even after Forget to prevent concurrent revival
from invalidating shell working directories. Files retain
separate virtual aliases. Writable nodes pin classified objects with O_PATH descriptors; file handles own
actual opened descriptors. Renames and editor replacement preserve open-object
semantics. Relative child opens use openat2 with the same no-symlink/no-crossing
constraints. Mutations serialize namespace changes, hold an epoch operation lease,
and recheck revocation after queueing. The service's private umask does not replace
the caller-masked create permissions. Set-id bits are rejected/stripped.

Old configurations retain read-only path/device/inode/type validation unless
explicitly opted into writes. Virtual inode IDs remain independent of backing
IDs, including hardlink aliases. Entry/attribute timeouts are zero and regular
files use direct I/O without writeback caching or direct-I/O mmap. Directory
snapshots may retain names in memory until release.

Tree lifetime cleanup drains operations, synchronizes still-linked writable
files, and closes all node/file/directory descriptors before backing unmount.
An already-unlinked object has no persistent name and is closed without requiring
gocryptfs fsync on that orphan. Sync failure retains the descriptor for retry;
the storage BeforeUnmount hook must succeed before cleanup can report success.
Read results keep their operation lease until reply completion.

The managed parent's separate tree uses no protected epoch. It remains usable
while protected access is locked and closes only on full shutdown. Root delegates
ordinary children to that tree but always reserves the protected anchor, filters
its name from enumeration, and forbids renaming/removing it. Cross-tree moves
return EXDEV. Parent path, inode/device and statx mount identity are checked;
replacement or a physical reserved-name collision fails closed. Relative opens
reject nested mount crossings. Config rejects nested parent/store/runtime/mount
paths, mounted parent subtrees and nonempty v1 mountpoints. Version 2 explicitly selects original-parent presentation: a pre-mount O_PATH parent descriptor and the identified empty target are retained. All backing operations and health checks remain descriptor-relative after cutover; mountinfo validates the exact outer mount identity without recursive pathname reopening. The physical parent and target are never renamed. This is empty-target cutover, not populated-data migration. External source changes require
cooperation; there is no snapshot or hostile same-UID boundary.

Regular files/directories support the documented write operations, not arbitrary
POSIX operations. Original-mode public symlinks are supported; protected symlinks, special nodes, hardlink creation, ACL/xattr passthrough,
file locking and mmap remain unsupported. See [CLI reference](cli.md) and
[security](security.md).

## Runtime and cleanup

The runtime directory is owned by the caller with mode 0700. A 0600 instance
lock held with `flock` serializes owners; the owned 0600 Unix socket uses Linux
peer credentials on both ends. Control messages, connections and credential
exchanges are bounded. Startup removes only a verified owned stale socket under
the instance lock and refuses unrelated files or leftover backing views/mounts.
The store-directory lock is advisory and coordinates cooperating instances only.

The backend supervises a foreground gocryptfs process group, retaining its leader
until helpers drain so a recycled process ID is not signaled. Mount-table identity
checks prevent cleanup from selecting an unrelated or ambiguous stacked mount.
Backend loss revokes the matching epoch before waiting for cleanup; observation
uses a 10 ms poll interval, subject to scheduling.

Lock suspends admission, cancels pending authentication, revokes/drains, waits for
workers and cleans backing resources before resuming admission. Unmount,
Ctrl+C/SIGTERM and unexpected Veyl mount exit permanently suspend admission and
also remove the Veyl mount/control endpoint. Failed cleanup retains ownership
and the locked control process for retry. A closed view or locked status alone
is not confirmation of unmount. Cleanup removes only identified empty mountpoint
directories, never a plaintext tree recursively. SIGKILL/crash recovery is manual.

Default init selects an existing empty directory and derives its hidden name
from the basename. It records parent/target identities in a version 2 config
under XDG config, initializes the encrypted store under XDG data with a random
identifier, and puts temporary resources under private XDG runtime. Configuration
is written exclusively and last. A deterministic path registration prevents
reinitializing an existing setup. Populated targets and old workspaces are
refused, never silently migrated. Explicit `--legacy-workspace` preserves v1
bundle initialization and existing v1 configuration behavior.

Activation requires leaving old cwd/parent handles and re-entering the absolute
original path. The mount owner guards the empty physical target mode 0500;
this remains after stopping so old directory handles cannot accidentally create
plaintext there. Existing same-UID permissions remain outside the threat model.
Mount setup pins the original parent before cutover and confirms outer mount
identity before resuming authentication and notifying readiness. No bind mount,
parent rename, or path reopening through the new FUSE mount is required.

The optional `explicit_unlock` setting prevents locked lookups from invoking
the broker. It leaves explicit IPC unlock unchanged and avoids trying to infer
user intent from shell/process identity. Inside the registered protected path,
configuration discovery uses the shell's PWD hint to select the external config
without probing a local document named veyl.json; this grants no authorization.

For the user-facing boundaries, including cache replay and privileged access,
read the [security model](security.md) and [troubleshooting](troubleshooting.md).

## Desktop supervision

The optional user service runs the same mount command and uses the existing
control socket, policy, transactions and resource owners. It adds no separate
authorization state or daemonization framework. Readiness is sent through
`NOTIFY_SOCKET` only after FUSE/control are serving. Notification failure requests
the existing cleanup path and cannot report successful service startup.

An owned private registration points to the v1 or v2 config. The generated
unit is wanted by/part of the graphical session, inherits its environment, starts
locked, and never automatically restarts after a crash. Mixed kill mode signals
only the main owner initially; forced SIGKILL is disabled and stop has no timeout
bypass. Cleanup failures retain the control owner, and outer/backing mount residue
blocks later startup. See [service lifecycle](service.md) for operational details.
