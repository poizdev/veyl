# CLI reference

```text
veyl help [command]
veyl --help
veyl version
veyl service enable [--config FILE]
veyl service disable|start|stop|status
veyl init [--dir PATH] [--tty] [--autostart] [--explicit-unlock]
veyl init --legacy-workspace [--dir PATH] [--tty] [--autostart]
veyl mount [--config FILE]
veyl status [--config FILE]
veyl lock [--config FILE]
veyl unlock [--config FILE] [--tty]
veyl unmount [--config FILE]
```

Flags follow the command (or service operation). No password flags, environment
password inputs or stdin password inputs are supported. The user service
supervises the foreground process; Veyl does not fork into a custom daemon.
`help COMMAND` and `COMMAND --help` show usage. `version` reports the release
version, short commit, UTC build time, runtime platform, Go toolchain and source
module. Ordinary installs retain `0.1.0-rc.1`; unavailable metadata is `unknown`.
The commit timestamp is not substituted for the build time.

| Command | Behavior |
| --- | --- |
| init | Protect the selected existing empty directory at its original pathname; external XDG store/config; prompt twice. |
| service | Manage explicit desktop autostart and the registered background owner; see [service lifecycle](service.md). |
| mount | Start locked, stay in the foreground, own socket and FUSE lifecycle. Requires a normal user; v1 needs an empty mountpoint; v2 validates its identified original parent and empty target. |
| status | Report not running, starting/stopping, locked, authenticating, unlocked, cleanup pending, or an unavailable managed namespace. Does not prompt. |
| lock | Cancel authentication, revoke/drain the session and clean up backing mounts. Retry after cleanup failure. Mount remains running. |
| unlock | Request the shared authentication flight. Default graphical pinentry; explicit `--tty` reads the caller's controlling terminal after peer validation. |
| unmount | Permanently stop authentication, revoke/drain, clean storage, unmount Veyl, release runtime resources. Success requires confirmed cleanup. |

Status remains responsive during external authentication and cleanup. Cleanup
pending takes precedence over ordinary locked/unlocked reporting. A blocked I/O
operation can delay draining; do not infer that revocation has completed before
the lock operation confirms it. After failed shutdown, a successful retry of
`lock` also completes the already requested shutdown.

| Exit | Meaning |
| --- | --- |
| 0 | Command succeeded; status may report any healthy running state. |
| 1 | Operational error, unavailable dependency/agent, startup transition, or incomplete first-run setup. |
| 2 | Invalid command, options, config, or setup destination. |
| 3 | No instance running for this config. |
| 4 | Password rejected, canceled, expired, or setup confirmation failed before creating files. |
| 5 | Cleanup pending/failed; do not assume plaintext mounts are gone. |

## Configuration discovery

For mount/status/lock/unlock/unmount and service enable, selection is explicit
`--config FILE`, then `./veyl.json`, then the default registered by service
enable. The default registration is an owned pointer under the user's private
Veyl configuration directory; the target remains an owned v1 or v2 config.
Inside the registered original protected path, the shell PWD hint selects its
external registration without probing protected documents for a local config.
PWD grants no authorization. Invalid/conflicting local configs are reported
rather than silently bypassed. Service start/stop/status/disable always manage
the registered service config. Only one default service is supported per user.

Bare `veyl lock` and `veyl status` may fail to discover a running v2 service.
Use `--config FILE` with the external filename printed by init; this
[open report](troubleshooting.md#known-report-default-cli-discovery-with-an-active-v2-service)
is not evidence that the service is stopped.

## Initialization directory

```sh
veyl init
veyl init --dir PATH
veyl init --tty
veyl init --dir PATH --tty
```

These are alternatives. The target must already exist and be empty, owned by
you, with no symlinks or unsafe permissions. The parent must be owned, controlled,
without existing mounts, and separate from config/store/runtime. HOME and root
cannot be covered. The original basename becomes the protected name. Populated
targets are refused before prompting. No migration is implemented.

Default init creates an external **version 2** config under
`$XDG_CONFIG_HOME/veyl/directories/<path-hash>.json`, an encrypted store under
`$XDG_DATA_HOME/veyl/<random-id>/store`, and runtime resources under
`$XDG_RUNTIME_DIR/veyl/<random-id>`. Standard config/data defaults apply;
XDG_RUNTIME_DIR must be explicitly available and private mode 0700. Persistent
data is never placed inside it. Management directories are 0700, config 0600.
The deterministic registration prevents accidental repeated init; random IDs
separate store/control resources. Nothing is created in the selected directory.

Setup records the parent and empty target device/inode identities. It never
mounts over the caller's cwd automatically. Leave the parent in every shell,
close old directory handles, then run the printed `service enable --config FILE`.
Re-enter using the absolute original pathname after confirmed locked readiness.
The physical target is guarded mode 0500 on activation and remains empty and
read-only after stopping. Existing descriptors are not redirected. Do not restore
write permission and use that directory for plaintext while retaining Veyl setup.

`--autostart` explicitly enables the service after setup, only if init's cwd is
already outside the original parent. No active desktop means activation is only
scheduled for later login. Readiness must be confirmed before relying on hiding.
`--explicit-unlock` sets `"explicit_unlock": true`: all locked filesystem probes
return access denied without prompting; explicit `veyl unlock` still prompts.
This suppresses prompts from shell highlighting/completion probes; the reported
Fish root cause remains unresolved and has not been conclusively reproduced. It
also works in existing configs when set while stopped. No process-name or
command-line heuristics are used. Default mode still authenticates on lookup.

Config version 2 uses `mountpoint` for the original parent, `hidden_name` for the
selected basename, and `original` for the four device/inode identity fields.
It never has the legacy `parent` field. Do not fabricate identity values or
convert v1 by editing its version: preserve existing configurations unchanged.
Only one Veyl namespace can cover a parent, and one default user service is
supported. There is no transparent support for arbitrary sibling POSIX features;
the supported regular-file/directory operations and public symlinks are described
below. Choose a dedicated parent before relying on application compatibility.

`--legacy-workspace` explicitly retains the v1 setup behavior. Its selected path
may be new or existing; `store`, `mount`, `runtime` and `veyl.json` must all be
absent. It creates private paths inside the workspace and exposes `mount/.troll`.
Unrelated files/permissions are preserved. Existing bundles are never adopted or
reinitialized implicitly. Passwords are confirmed twice in either mode.
Cancellation before creation adds no data; later partial output is preserved.

## Existing version 1 configurations

Existing v1 configs remain supported; `init` is optional. A config is a regular,
owned file, without group/world write permission, at most 16 KiB. Symlinks,
unknown fields and trailing JSON are rejected. A generated example:

```json
{
  "version": 1,
  "read_only": false,
  "store": "/home/alice/veyl-demo/store",
  "mountpoint": "/home/alice/veyl-demo/mount",
  "hidden_name": ".troll",
  "runtime_dir": "/home/alice/veyl-demo/runtime",
  "credential_agent": "auto"
}
```

Paths must be absolute and clean, with store, mountpoint and runtime separate
and non-nested. Directory paths must have no symlink components and safe
ownership/permissions. Runtime must be owned by the caller with mode 0700;
mountpoint must be empty and owned/controlled by the caller. The config and
credential executable must be outside the Veyl mount. Existing mounts or view
residue block startup. Keep runtime paths short (Linux socket path limit).

`hidden_name` defaults to `.troll`; it must be a single filename other than
`.`, `..`, or `visible.txt`. `credential_agent` defaults to `auto`, which searches
for installed graphical pinentry variants. An absolute path can select a trusted
pinentry executable; `none` disables GUI authentication while allowing explicit
`unlock --tty`. Executable and ancestors must pass ownership/permission checks.
The configuration contains no password.

## Writable access

`read_only` is optional. Omitted or `true` preserves read-only protected access;
`false` enables writes. New `init` configurations set it to `false`. No store
conversion occurs. Stop Veyl before changing config; the next process reads it.

Regular files and directories support creation, read/write, append, truncate,
rename/replacement, removal, permission/time metadata, flush and fsync. Handles
continue to refer to opened objects after rename or unlink, until revocation.
Lock closes/synchronizes session-owned handles before backing unmount; sync or
cleanup failure retains ownership and is reported. Reopen files after unlock;
old handles never regain authorization. Already admitted I/O can finish while
lock drains it. Read-only legacy handles retain their stricter path-identity checks.

Protected symlink traversal/creation, hardlink creation, special nodes, xattrs/ACLs,
allocation, advisory file locking, and mmap are unsupported. Existing hardlink
aliases receive separate virtual inode identities. No full POSIX or power-loss
transaction guarantee is claimed; use application fsync for durability.
The synthetic `visible.txt` and namespace anchor are immutable. Linked directories
retain one pinned descriptor per visited object for the tree lifetime, including
after kernel Forget; large trees can approach the process descriptor limit.
Protected pins close on lock; public sibling pins close on unmount. Deleted,
forgotten directory pins retire earlier. If resources are exhausted, stop cleanly
and restart; do not bypass failed cleanup.

## Managed-parent namespace

An optional `parent` string adds an ordinary, **unencrypted** sibling backing
directory. Example fields added to a v1 config while stopped:

```json
{
  "parent": "/home/alice/veyl-siblings",
  "read_only": false
}
```

Merge these fields into the full config above; this fragment is not a complete
config. Create a new separate source for a synthetic example:

```sh
mkdir -m 700 "$HOME/veyl-siblings"
mkdir "$HOME/veyl-siblings/projects"
```

After starting the configured Veyl mount, `mount/projects` maps to the physical
`veyl-siblings/projects`, while `mount/.troll` authenticates into the encrypted
store. The source remains visible at its original location. The hidden name is
never enumerated, whether locked or unlocked; enumeration never authenticates.
The default synthetic `visible.txt` is replaced by actual sibling contents.

The parent, store, mountpoint and runtime must all be absolute, separate,
non-nested, owned/controlled directories without symlinks. The mountpoint must
remain empty before mounting. The parent must have no nested mounts and no
entry at `hidden_name` (including symlinks or empty directories). Startup refuses
conflicts rather than adopting, concealing or moving physical data. Public
siblings support ordinary regular-file/directory operations while the encrypted
branch is locked, even when `read_only` protects that branch. They are not
protected by its password. Public/protected renames fail with `EXDEV`; tools may
then choose a copy/delete fallback, which can create plaintext outside protection.

External sibling changes are reflected on fresh lookups/open-directory snapshots.
Open descriptors retain their objects. Replacing/removing the parent, changing
its mount identity, or creating a reserved-name collision makes new operations
fail closed (`ESTALE`); status reports `namespace_unavailable`. Stop Veyl, inspect
the backing directory, resolve the conflict and start again. Veyl does not delete
the collision. Symlinks, special files and mount crossings are omitted/rejected.
This constrained view is not transparent passthrough for every application.

Original-path v2 uses the same tree and policy at the original parent mountpoint.
It pins the physical parent before mounting and never reopens that pathname in
FUSE callbacks. Descriptor device/inode and statx mount IDs, the original empty
target, and the exact outer FUSE mount ID are checked. Mount-table checks reject
stacked or unexpected child mounts. Public sibling symlinks are read/created in
original mode; the kernel resolves them in the visible namespace. Direct
metadata changes to symlink objects are unsupported. Legacy separate-parent
symlink restrictions remain unchanged. Special nodes are omitted/rejected;
hardlink creation, xattrs/ACLs, file locking and mmap remain unsupported in both
trees. The namespace anchor in original mode supports safe metadata changes;
renaming/removing it and shared-write permission changes remain forbidden.

Old cwd/parent handles retain the backing namespace. They cannot be transparently
redirected. The mode 0500 guard prevents ordinary writes into the physical empty
target, but same-UID owners can undo it; that is outside the threat model.
Unexpected target contents, object replacement, or mount identity changes fail
closed. Stop, preserve the data, and inspect rather than deleting the conflict.
No populated-directory migration or automatic crash recovery is provided.

Original-parent activation preflights sibling names/types recursively without
following symlinks or reading file contents. Parents with FIFO, socket, device,
or uninspectable sibling subtrees are refused before mounting, rather than
silently breaking those objects. Such a parent needs a different layout; Veyl
never moves or deletes the unsupported sibling. If a pre-existing directory
handle introduces a special node after activation, opening that listing returns
an unsupported-operation error instead of silently omitting it.
