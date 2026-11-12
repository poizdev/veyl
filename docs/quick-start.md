# Installation and first run

Use Linux with `/dev/fuse`, `openat2` and `statx` mount IDs, Go as specified in
[go.mod](../go.mod), gocryptfs, fuse3, and graphical pinentry. Run as your normal
desktop user. Background activation requires systemd --user and an active
`graphical-session.target`. Never use sudo or `allow_other`.

```sh
go install -buildvcs=false ./cmd/veyl/
veyl version
```

Go normally installs into `$HOME/go/bin`. POSIX shells can use
`export PATH="$HOME/go/bin:$PATH"`; fish can use `fish_add_path "$HOME/go/bin"`.
Rerun installation after source changes. Development remains `0.1.0-rc.1`.

This guide describes v0.1.0-rc.1, a development candidate that is not
production-ready or independently security-audited. Use disposable data first.

## Initialize the directory itself

Use a dedicated synthetic parent first. These commands work in fish and POSIX
shells. Stop if any command fails; never reuse an existing example directory.

```sh
mkdir -m 700 /tmp/veyl-example-parent
mkdir -m 700 /tmp/veyl-example-parent/test
mkdir -m 700 /tmp/veyl-example-parent/neighbor
cd /tmp/veyl-example-parent/test
veyl init
```

The selected directory must already exist and be empty. `veyl init --dir PATH`
selects that directory instead. Populated directories and old Veyl bundles are
refused. There is no migration workflow. Setup confirms the new password twice
through graphical pinentry; `--tty` explicitly uses `/dev/tty` instead.

No `store/`, `mount/`, `runtime/`, or `veyl.json` appears in `test`. Setup writes:

- Configuration/registration: `$XDG_CONFIG_HOME/veyl/directories/` (default `~/.config`).
- Encrypted store: `$XDG_DATA_HOME/veyl/<random-id>/store` (default `~/.local/share`).
- Temporary control/views: `$XDG_RUNTIME_DIR/veyl/<random-id>/`.

Config is 0600; management directories are 0700. Runtime must be a private,
owned directory, separate from persistent data/config. Short Linux socket paths
are required. Paths with symlinks or unsafe ownership/permissions are refused.
Back up the encrypted store and all its gocryptfs metadata. There is no password
recovery. Partial output is retained for inspection, never automatically erased.

## Leave before activation

Setup prints the exact external configuration filename. Replace `CONFIG` below
with that filename. It has not mounted anything yet.

```sh
cd /tmp
veyl service enable --config CONFIG
veyl status --config CONFIG
```

Leave the original parent in **all** shells and close old directory handles in
applications first. A mount does not redirect an existing working-directory or
parent descriptor. Old parent handles still describe the physical backing
namespace and can enumerate its empty target; they are outside the new view.
Activation makes the physical empty target mode 0500 to block accidental writes
through old cwd handles. That guard remains after stop/crash. Never chmod it to
write files there: those would be unencrypted and block subsequent activation.

Enablement starts Veyl now in an active desktop and on later graphical logins,
always locked. Without an active desktop it only schedules future activation;
do not assume the directory is protected until `veyl status --config CONFIG` confirms readiness.
`--autostart` during init is accepted only when the caller is already outside the
original parent. No root service or lingering is enabled. The service needs no
terminal. Manual foreground mode remains `veyl mount --config CONFIG`.

## Use the original pathname

```sh
ls /tmp/veyl-example-parent
ls -a /tmp/veyl-example-parent
cd /tmp/veyl-example-parent/test
touch hello.txt
echo hello > hello.txt
mkdir projects
mv hello.txt projects/notes.txt
cat projects/notes.txt
veyl lock --config CONFIG
```

Both listings omit `test`, locked or unlocked. `neighbor` stays unencrypted,
readable and writable while locked. Explicit lookup of `test` requests pinentry.
After authentication the supported file/directory operations work, including
editor replacement saves. Reopen paths after lock/unlock: old handles stay
revoked. Use `nvim projects/notes.txt` with an editor that uses supported operations.

Fish and other programs can probe paths without executing a command. The
filesystem cannot identify intentional access. To prevent these probes from
opening dialogs, initialize with `--explicit-unlock`, or set
`"explicit_unlock": true` in the configuration while Veyl is stopped. Then:

```sh
veyl unlock --config CONFIG
cd /tmp/veyl-example-parent/test
```

The reported Fish typing-only prompt flood has not been conclusively reproduced
or resolved. Explicit-unlock mode is a mitigation, not a diagnosis of shell
behavior, and does not add same-UID isolation.

Graphical authentication occurs only on explicit unlock in that mode. Terminal
fallback is `veyl unlock --config CONFIG --tty`. Cancel an existing GUI flight before trying the
TTY fallback. A canceled prompt never grants access.

```sh
cd /tmp
veyl service stop
veyl service start
veyl service disable
```

Stop/unmount preserves encrypted data. The physical target is still empty and
read-only while stopped; the hidden encrypted view is unavailable. There is no
automatic restoration of write permission. To abandon an empty registration,
first disable/stop its service, confirm all mounts are gone, preserve the store
and configuration, and explicitly restore the known empty target's permissions
if desired. Never treat that physical directory as the encrypted contents.

## Compatibility and limits

Version 1 configurations still work without conversion. Explicit
`veyl init --legacy-workspace --dir PATH` creates the old `store/`, `mount/`,
`runtime/`, `veyl.json` bundle and virtual `mount/.troll`; it never reinterprets an
existing bundle. Version 1 configs omitting `read_only` remain read-only.

The managed view supports documented regular-file/directory operations and
public sibling symlinks. It does not provide every POSIX operation. Protected
symlinks, special nodes, hardlink creation, xattrs/ACLs, locking and mmap remain
unsupported. See [CLI limits](cli.md) before choosing applications/parents.
Same-UID/root access and caching limits remain: read the [security model](security.md).
For crashes or stale mounts, follow [manual recovery](troubleshooting.md).

Original-parent activation preflights sibling names/types recursively without
following symlinks or reading file contents. Parents with FIFO, socket, device,
or uninspectable sibling subtrees are refused before mounting, rather than
silently breaking those objects. Such a parent needs a different layout; Veyl
never moves or deletes the unsupported sibling. If a pre-existing directory
handle introduces a special node after activation, opening that listing returns
an unsupported-operation error instead of silently omitting it.

File-manager drive/sidebar hiding is best effort. Compatible helpers receive
`x-gvfs-hide`; some desktops or missing userspace mount metadata leave the drive
visible. Original-path navigation and authentication are unchanged. Prefer
Veyl's stop/unmount commands to a file-manager eject button; a failed busy eject
can leave the session unlocked. See [visibility and eject
diagnostics](troubleshooting.md#drivesidebar-entry-in-gnome-files). If bare
`status`/`lock` cannot discover a running v2 service, use its printed external
configuration filename with `--config FILE`; that report remains open.

## Manual foreground mode

After initialization, leave the original parent and close old directory handles
as above. If a service owns this setup, stop it first and confirm cleanup. In a
terminal outside the parent, run:

```sh
veyl mount --config CONFIG
```

Keep that terminal open for diagnostics. In a second terminal outside the parent,
run `veyl status --config CONFIG` and confirm locked readiness before re-entering
the protected absolute pathname. Use `veyl unlock --config CONFIG --tty` for
terminal authentication. Ctrl+C requests cleanup; keep the owner alive if cleanup
fails and follow the recovery guide. Foreground mode has the same security and
filesystem limitations as the service; it is not a separate debug implementation.
