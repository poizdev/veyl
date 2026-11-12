# Veyl

A Linux FUSE filesystem for authenticated, writable access to a concealed
gocryptfs directory.

**Development status: v0.1.0-rc.1.** This is a source-only development candidate,
not a stable release. Veyl is not production-ready or independently
security-audited. Start with disposable data and read the security model.

Default setup protects the selected **empty directory itself** at its original
pathname. Private XDG locations hold configuration, encrypted data and runtime
resources. The protected basename is omitted from parent enumeration even when
unlocked. Explicit access requests graphical pinentry; lock revokes session
handles and cleans up the managed plaintext mount.

```text
$ mkdir -m 700 /tmp/veyl-example-parent
$ mkdir -m 700 /tmp/veyl-example-parent/test
$ mkdir -m 700 /tmp/veyl-example-parent/neighbor
$ cd /tmp/veyl-example-parent/test
$ veyl init
[confirm a new password twice; configuration path is printed]
$ cd /tmp
$ veyl service enable --config CONFIG
$ veyl status --config CONFIG
[confirm locked readiness before continuing]
$ ls -a /tmp/veyl-example-parent
.  ..  neighbor
$ cd /tmp/veyl-example-parent/test
[pinentry asks for the store password]
$ echo hello > hello.txt
$ veyl lock --config CONFIG
```

Use a new example parent; stop if any command fails. Replace `CONFIG` with the
external filename printed by init.

Setup cannot redirect your running shell. Leave the original parent before
activation and re-enter by absolute pathname after confirmed locked readiness.
The physical target stays empty and becomes mode 0500, including after stop.
See the [complete walkthrough](docs/quick-start.md) before running these commands.

## Features

- Concealed virtual directory with password authentication on direct access.
- Graphical pinentry and an explicit `/dev/tty` fallback.
- Writable protected files/directories; old handles stay revoked after locking.
- Optional managed-parent view with ordinary unencrypted siblings at a separate mountpoint.
- Optional systemd user service: automatic locked startup with your desktop.
- Status, lock, unlock and controlled unmount; manual foreground/debug mode.
- First-run empty-directory protection with external version 2 configuration; v1 compatibility.
- Private Unix control socket and explicit reporting of incomplete cleanup.

### Why not just mount gocryptfs?

gocryptfs provides encryption at rest and an ordinary plaintext mount. Veyl adds
a concealed virtual entry, authentication on demand and session control over
that view. It uses gocryptfs for encryption and password verification; it does
not implement another encryption format. The extra FUSE layer does not isolate
the plaintext backing mount from other processes running as your user or root.

## Requirements

- Linux with FUSE, a usable `/dev/fuse`, and `openat2`/`statx` mount-ID support.
- Go 1.27.3 or newer, as specified in [go.mod](go.mod).
- `gocryptfs`, `fusermount3` (fuse3), and a graphical pinentry such as pinentry-qt.
- For automatic startup: a systemd user manager and a desktop managing
  `graphical-session.target` (including session-integrated Niri).

On CachyOS/Arch, the packages are `gocryptfs`, `fuse3` and `pinentry`.
Run Veyl as your normal desktop user, without sudo or `allow_other`.

## Install

From the repository root:

```sh
go install -buildvcs=false ./cmd/veyl/
veyl version
```

The executable goes to `GOBIN`, or normally `$(go env GOPATH)/bin`. Add that
location to your shell's PATH; see [installation and first run](docs/quick-start.md).
After source changes, rerun `go install -buildvcs=false ./cmd/veyl/`. Building a local binary does
not update the installed command.

For a local build without installing:

```sh
go build -buildvcs=false -o bin/veyl ./cmd/veyl
./bin/veyl version
```

No prebuilt binary, package, or GitHub Release is provided for this publication.

## Quick start

Create an empty directory in a dedicated owned parent, enter it, and run
`veyl init`. Setup prints an external configuration path. Leave the original
parent in all shells, close old directory handles, then enable the background
owner with `veyl service enable --config CONFIG`. Run `veyl status --config CONFIG` before
re-entering the original absolute pathname. Parent listings omit the protected
name; unrelated regular-file/directory siblings remain writable while locked.

Populated targets are refused. No existing files are moved, imported, or deleted.
`--autostart` is allowed only from outside the original parent. Never mount over
HOME or root. See [first run](docs/quick-start.md) for safe synthetic commands.

Use `--explicit-unlock` at init to prevent filesystem probes (including shell
highlighting) from opening dialogs. Then run `veyl unlock --config CONFIG` before entering.
Explicit `veyl unlock --config CONFIG --tty` provides terminal authentication. Config selection
is `--config FILE`, then local `veyl.json`, then the registered service default.

`veyl lock --config CONFIG`, `veyl service stop`, `veyl service start`, and
`veyl service disable` control the registered owner. Stops preserve encrypted
data. Crash restart is disabled; stale mounts block startup and require
[manual recovery](docs/troubleshooting.md). Version 1 configs remain supported;
`init --legacy-workspace` explicitly selects the old bundle layout.

## Limits

The v0.1.0-rc.1 development candidate supports regular files and directories, including
create/write/append/truncate, rename, removal, permissions and fsync. Older v1
configs stay read-only unless `"read_only": false` is explicitly set. Protected symlinks,
hardlink creation, special nodes, xattrs/ACLs, file locking and mmap are unsupported;
this is not full POSIX compatibility. Moves across public/protected trees return
`EXDEV`.

Original-path presentation mounts the managed namespace over its owned parent,
using a descriptor pinned before mounting for public siblings. It never moves
the parent or physical target. Existing directory descriptors are not redirected.
The target must be empty; no migration workflow is implemented. Public sibling
symlinks are supported in original mode; other documented POSIX limits apply to
that view. Legacy separate managed-parent views remain supported.
Knowing a protected name defeats concealment, not authentication.

**Same-UID processes and root can access the plaintext backing mount and inspect
process memory.** Lock cannot erase plaintext already copied or guarantee cache
erasure. Cleanup failures require retry; crashes may need manual recovery.
Veyl does not claim production-grade isolation. Read the
[security model](docs/security.md) before using it for sensitive data.

Original-parent activation preflights sibling names/types recursively without
following symlinks or reading file contents. Parents with FIFO, socket, device,
or uninspectable sibling subtrees are refused before mounting, rather than
silently breaking those objects. Such a parent needs a different layout; Veyl
never moves or deletes the unsupported sibling. If a pre-existing directory
handle introduces a special node after activation, opening that listing returns
an unsupported-operation error instead of silently omitting it.

## Open issues

- Bare `veyl lock` and `veyl status` may fail to discover an active v2 service;
  select the external configuration with `--config FILE`.
- GNOME Files may show managed FUSE mounts as separate drives despite
  best-effort `x-gvfs-hide`.
- Fish speculative lookups may cause repeated authentication prompts. The
  reported root cause has not been conclusively reproduced or resolved.
  Explicit-unlock mode suppresses locked filesystem-triggered prompts; it
  requires explicit authentication before access.
- Same-UID/root access and filesystem caching limits remain.
- Populated-directory migration is not implemented.

See [troubleshooting](docs/troubleshooting.md) for workarounds and recovery,
including [desktop visibility and eject behavior](docs/troubleshooting.md#drivesidebar-entry-in-gnome-files).

## Project documentation

- [Installation and first run](docs/quick-start.md)
- [Desktop service and automatic startup](docs/service.md)
- [CLI and configuration](docs/cli.md)
- [Architecture](docs/architecture.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Contributing](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)
- [Changelog](CHANGELOG.md)

## License

[MIT](LICENSE). Copyright (c) 2026 poizdev.
