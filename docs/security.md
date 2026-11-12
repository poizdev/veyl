# Security model and limitations

Veyl v0.1.0-rc.1 is a development candidate for Linux. It is not
production-ready or independently security-audited, and is not a
production-grade security boundary. Its scope is encryption at rest through
installed gocryptfs, concealment from enumeration inside its own virtual mount,
and session authorization through Veyl's callbacks.

## What Veyl does

- Omits the configured hidden name from root listings, including `ls -a`, in
  both locked and unlocked states. Direct lookup of the known name can prompt.
- Uses gocryptfs to verify credentials by preparing an encrypted backing mount.
  Only a current broker transaction can adopt that view into a session.
- Checks session epochs for protected operations and handles. Lock revokes the
  epoch, drains admitted work, and cleans up the managed backing mount. Old
  handles remain revoked after a later unlock; reopen paths for the new session.
- Supports authenticated regular-file/directory writes, including rename and
  persistence across sessions. Older configs remain read-only until explicitly
  enabled. Protected symlinks, special nodes, hardlink creation, xattrs/ACLs, file locking
  and mmap are unsupported; full POSIX compatibility is not claimed.
- Holds operation leases during writes and synchronizes/closes owned descriptors
  before backing unmount. Revocation rejects new writes; already admitted work
  may finish while lock drains it. Sync failures retain cleanup ownership.
- Uses private runtime directories (0700), a private Unix socket (0600), peer UID
  checks, bounded control messages, and an exclusive instance lock.
- Passes passwords to gocryptfs through an anonymous inherited FD, never argv,
  environment, logs, or regular plaintext files. Terminal entry is an explicit
  fallback; graphical pinentry is normal. Setup confirms a password twice.

## What Veyl cannot protect

**Processes running as your UID and root can access the plaintext backing mount
outside Veyl's policy and inspect process memory.** Directory permissions and
Unix peer credentials do not create hostile same-UID isolation. No privileged
service, mount namespace boundary, or custom cryptography is claimed. Do not
allow untrusted code to run as your user and expect Veyl to contain it.

Concealment is not invisibility: anyone who knows or guesses the hidden name can
attempt direct lookup. Configuration and mount metadata reveal paths. Veyl does
not hide an arbitrary populated physical directory. Default setup accepts only
an empty target and mounts a synthetic namespace over its original owned parent.
The physical target stays empty, with a mode 0500 guard during and after
activation. A parent descriptor pinned before mounting supplies ordinary public
siblings; no parent rename or data migration occurs. Legacy separate-parent
views remain supported. Those files stay unencrypted and are writable while the
protected branch is locked. No existing-file migration is performed. Existing
cwd and parent descriptors keep the old physical namespace; leave and re-enter
by absolute pathname. They may enumerate the physical empty target and are
outside the new mount view. Guard permissions block accidental old-cwd writes,
but same-UID owners can change permissions and bypass them. Never put sensitive
plaintext among public siblings expecting password protection. Cross-tree rename
returns EXDEV; application copy/delete fallbacks may expose plaintext in a
public destination.

Lock/unmount cannot retract plaintext already returned, application copies,
screenshots, backups, swap, core dumps, or kernel buffers. Direct I/O and short
metadata timeouts reduce normal Veyl caching, but do not guarantee secure memory
erasure, eliminate underlying gocryptfs page caching, or revoke mmap copies.
Directory response buffers may replay names after lock; file opens/reads still
require a current session. Zeroing owned password buffers is best effort, not
proof of erasure. No memory-locking or core-dump hardening is provided.

Lock waits for admitted I/O/results to drain. Blocked I/O may delay it. Backend
crash detection is polling-based (10 ms, subject to scheduling), not instantaneous
kernel revocation. Cancellation and stale grants fail closed, but external
resource cleanup can fail. `cleanup pending` means a plaintext mount may remain;
only confirmed cleanup means managed mounts were removed.

## Operational assumptions

Run as a normal user, without `allow_other`. Keep executables, configuration,
store, mountpoint, and runtime under trusted ownership and permissions. Do not
replace or edit them while Veyl runs. Do not concurrently mount the same store
for writing. Any standalone gocryptfs use requires Veyl to be stopped. Back up
encrypted data and all gocryptfs metadata. There is no password recovery or
automatic data migration.

SIGKILL, power loss and process crashes cannot run userspace cleanup. Startup
refuses leftover views/mounts; automatic orphan adoption and durable crash
recovery are not implemented. Follow [manual recovery](troubleshooting.md).
Dependencies and target kernel behavior remain part of the security boundary.

Backing content is assumed to be trusted while mounted. Writable nodes pin
objects; legacy read-only nodes check path/device/inode/type, where inode reuse
can defeat identity checks. Managed-parent path/mount replacement or a reserved
name collision fails closed for new operations. External sibling edits appear
on fresh lookup/directory opens; existing descriptors keep their objects. This
is not a snapshot, transparent arbitrary passthrough, or defense against hostile
same-UID changes. The advisory store lock cannot stop external programs that
ignore it. See [architecture](architecture.md) for contributor-facing contracts
and [SECURITY.md](../SECURITY.md) for reporting vulnerabilities.


The opt-in [desktop user service](service.md) preserves these boundaries. It runs
under the same UID with no root service or lingering, starts locked, and reuses
the existing peer-validated control socket and cleanup path. It does not strengthen
same-UID isolation. Crash restart is disabled; an unlimited stop timeout can delay
logout when I/O or cleanup is blocked. Forced session termination can still prevent
cleanup and requires the documented manual recovery.

Application fsync and normal gocryptfs durability apply. Lock is not an atomic
filesystem transaction, rollback, backup, or guarantee against power-loss data
loss. Failed writes may have partially changed files; failures are returned to
callers and must not be interpreted as a clean rollback.

Original-path configuration records physical parent/target device/inode identity.
Backing operations and health checks use the pre-mount descriptor, with statx
mount-ID checks. Outer mount identity is checked via `/proc/self/mountinfo`,
never a path open that could recurse into the server. Unexpected mounts or
physical target contents fail closed. The original parent is preserved after
unmount/crash; no decrypted files are stored in the physical target. A dead
outer mount is not successful cleanup. Manual recovery must positively identify
and unmount every remaining gocryptfs view and the original-parent FUSE mount.

Authentication-on-lookup cannot distinguish typing, completion, indexing and
intentional access. Default mode can therefore prompt on speculative probes.
`explicit_unlock` suppresses all filesystem-triggered dialogs while locked;
explicit IPC unlock still authenticates. Interactive fish 4.9.3 synthetic checks
did not reproduce a typing-only flood, but repeated path probes caused repeated
canceled requests; explicit-unlock mode suppressed those prompts. The reported
Fish root cause remains unresolved and has not been conclusively reproduced.
Explicit-unlock mode mitigates prompts without identifying their source. No
inference from shell names, process names, or ls/cd command lines is used.

Original-parent activation preflights sibling names/types recursively without
following symlinks or reading file contents. Parents with FIFO, socket, device,
or uninspectable sibling subtrees are refused before mounting, rather than
silently breaking those objects. Such a parent needs a different layout; Veyl
never moves or deletes the unsupported sibling. If a pre-existing directory
handle introduces a special node after activation, opening that listing returns
an unsupported-operation error instead of silently omitting it.

`x-gvfs-hide` requests desktop-sidebar suppression only where the mount helper
and volume monitor support it. It grants no access, changes no filesystem
identity or path, and cannot conceal mount metadata. Some hosts still show a
drive/eject button. Successful external eject triggers the existing shutdown
and backing-cleanup path; failed busy eject does not establish a locked state.
Do not equate a disappearing sidebar entry with confirmed encrypted-view cleanup.
