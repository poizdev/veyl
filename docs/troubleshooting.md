# Troubleshooting

Always check `veyl status` (or select `--config FILE`). For a user service, also
check `veyl service status` and `journalctl --user -u veyl.service -b`; for manual
mode, read the foreground mount terminal.
Do not delete runtime directories or kill the owner to bypass cleanup errors.

| Symptom | Action |
| --- | --- |
| `veyl` not found or old version | Check PATH and `command -v veyl`; rerun `go install ./cmd/veyl/` after source changes. A local build updates only `bin/veyl`. |
| Go VCS stamping error | For a checkout without a commit, use `go install -buildvcs=false ./cmd/veyl/`. No Git initialization is needed. |
| Setup path conflict | Use `veyl init --help`. Default setup requires an existing empty target and no prior registration. Populated targets are refused. With explicit --legacy-workspace, `store`, `mount`, `runtime` and `veyl.json` must all be absent. Existing empty directories and dangling symlinks at these reserved names also conflict. Unrelated files are preserved. |
| Setup incomplete | Inspect the reported partial bundle. It may contain initialized encrypted metadata; keep it. Choose another new directory for a retry. No automatic deletion or resume is provided. |
| Invalid config | Use the generated external v2 config (or legacy `veyl.json`); check version and fields, absolute separate paths, ownership and no group/world write permission. Do not store config inside the mountpoint. |
| Unsafe parent/path | Use owned directories with no symlink components and no untrusted writable ancestors. Runtime must be exactly 0700. Choose a short private XDG runtime path for the control socket. |
| Missing dependencies | Install gocryptfs, fuse3 and a graphical pinentry. Check `command -v gocryptfs fusermount3` and access to `/dev/fuse`. |
| Service startup fails | Check `veyl service status`, `systemctl --user status veyl.service` and `journalctl --user -u veyl.service -b`. The service does not restart blindly or delete residue. See the [service guide](service.md). |
| No desktop autostart | Check the service is enabled and the desktop manages `graphical-session.target`. Use Niri session integration where applicable; do not enable lingering as a workaround. |
| No config outside the workspace | Use `--config FILE` or explicitly register a default with `veyl service enable --config FILE`. A local `veyl.json` takes precedence over the registered default. |
| Mount fails | Run as your normal user. Check the mountpoint is empty and not already mounted. Check `/dev/fuse`, fusermount3 and existing residue. Avoid sudo and `allow_other`. |
| No graphical prompt | Start from the desktop session; check DISPLAY or WAYLAND_DISPLAY and private XDG_RUNTIME_DIR. Install a supported graphical pinentry. Explicitly use `unlock --tty`; init also supports `--tty`. |
| `/dev/tty` unavailable | Run the command from an interactive terminal. Piped stdin and noninteractive jobs cannot provide this fallback. |
| Wrong password / canceled prompt | The directory remains locked. Retry `unlock` or a fresh direct lookup; check status. Avoid guessing at passwords from command arguments. |
| `--tty` still waits for GUI | An existing shared GUI flight is active. Cancel it first, then retry terminal unlock. |
| `.troll` missing from `ls -a` | Expected: access its known full path. In original mode the selected basename has this behavior at its original path; .troll is only the legacy default. |
| Typing causes repeated prompts/canceled logs | Stop Veyl and set `"explicit_unlock": true` in its configuration, then restart and run `veyl unlock` before entering. New setup accepts `--explicit-unlock`. The filesystem cannot distinguish speculative probes from intentional access; no shell-name heuristics are used. |
| Empty hidden directory | A newly initialized store is empty. Create files through the known hidden path after authentication; see the walkthrough. |
| Old handle denied after unlock | Expected revocation. Reopen the file/path; old handles never acquire the new session. |
| Writes fail with EROFS | Existing v1 configs stay read-only. Stop Veyl, explicitly set `"read_only": false`, then start again. New init configs enable writes. |
| Symlinks, hardlinks or special operations fail | Only the documented regular-file/directory operations are supported. Symlinks, special nodes, hardlink creation, xattrs/ACLs, file locking and mmap are unsupported. |
| Cross-tree move fails with EXDEV | Public/protected moves are separate filesystem boundaries. Copy explicitly if intended, considering plaintext exposure; Veyl does not migrate data. |
| Managed namespace unavailable / ESTALE | Stop Veyl and inspect the separate backing parent for path/mount replacement or a reserved hidden-name collision. Preserve physical files; resolve the conflict before restart. |
| Too many open files | Directory identity pins live until protected lock or full unmount for public siblings. Close applications and cleanly lock/unmount, then restart. Deleted forgotten directories retire earlier. Large trees may require a higher process descriptor limit. |
| Already running / starting or stopping | Keep the owner terminal open, wait and retry status. Do not start another instance over it. |
| Status says not running (exit 3) | Expected after successful unmount. Start `mount` with the same configuration to run again. |

## Cleanup pending while the owner is alive

Close applications and shells using the protected view; move their working
directories outside all Veyl and backing mountpoints. Retry:

```sh
veyl lock --config FILE
veyl status --config FILE
veyl unmount --config FILE
```

Keep the owner running (including a supervised owner) until it confirms cleanup.
Do not force-stop the service to bypass a pending drain. Ctrl+C/SIGTERM
requests cleanup; failed cleanup keeps the locked owner and control endpoint
alive for retries. A previous unmount request is permanent: a later successful
lock retry can finish shutdown. Do not interpret locked status alone as proof
that an underlying plaintext mount is gone. During revocation, status may say
cleanup is in progress before the policy transition has completed.

## After SIGKILL or a crash

Veyl refuses to start over a nonempty `runtime/views` or leftover mount. It does
not silently adopt a view, recursively inspect decrypted data, or erase residue.
Recovery is manual and requires checking the exact configured paths:

1. Confirm the old owner is gone, including any systemd service process. If it is alive, use its control
   commands instead of manual recovery.
2. Inspect mount metadata with `findmnt` (all mounts) or `findmnt --mountpoint
   /absolute/path`. Identify any exact Veyl mount and any managed gocryptfs view
   below the configured `runtime/views`. Do not inspect file contents to guess
   which mount it is.
3. Close users of those mounts. Unmount each positively identified leftover
   backing view with `fusermount3 -u -- /exact/view/path`, then the Veyl mountpoint
   with `fusermount3 -u -- /exact/veyl/mountpoint`. If a helper remains alive,
   identify and stop that exact owned helper; do not kill all gocryptfs processes.
4. Recheck mount metadata. Only after confirming no mounts remain, remove empty
   leftover view directories with `rmdir -- /exact/view/path`. Never use `rm -rf`
   on runtime/view paths. Unknown nonempty residue needs investigation.
5. Retry `veyl service start` or manual `veyl mount --config FILE`. Under its exclusive instance lock, startup
   removes only an owned, non-live stale control socket. It preserves ordinary
   files and unknown residue. The private `instance.lock` file can remain.

Do not use lazy unmount to claim cleanup: it may leave live references and
plaintext resources. If you cannot positively identify residue, stop recovery
and investigate rather than deleting it. Never remove the encrypted `store` as
part of runtime recovery.

## Original-path setup and recovery

Default setup writes management files to XDG config/data/runtime, not into the
target. Use its printed external config filename. Populated targets are refused;
there is no migration. Never point original-parent mode at HOME, root, or a
personal parent to experiment. Use dedicated synthetic fixtures.

A shell inside the target or parent before activation keeps its old directory
descriptor. Leave the parent in every shell and close old handles, then activate
and re-enter by absolute pathname after locked readiness. The physical target
stays empty and mode 0500 after activation, stop and crash. Permission denied
through an old cwd is expected; do not chmod the guard away to work around it.
While stopped, that physical directory is not the encrypted contents.

After a crash, the generic recovery procedure above applies to the **original
parent** as the Veyl mountpoint. Identify it from the external config and mount
metadata. Recover backing gocryptfs views first, then that exact original-parent
FUSE mount. Confirm no mounts remain; remove only positively identified empty
view directories. Preserve the physical parent, empty target, configuration,
encrypted store and unknown residue. Do not rename or delete the parent to
recover, and never use lazy unmount as evidence of cleanup. A target identity
change or unexpected physical contents requires investigation, not adoption.

## Drive/sidebar entry in GNOME Files

Veyl requests `x-gvfs-hide` on the outer FUSE mount and on its managed gocryptfs
view (`-ko x-gvfs-hide`). This is a per-mount desktop visibility hint. It changes
neither authenticated access through the original pathname nor mount identity,
permissions, revocation, or cleanup. Existing mounts need a clean stop/start to
pick up the option. Veyl does not modify fstab, desktop preferences, or other
mounts, and never creates or edits global userspace mount tables itself.

There is **no reliable cross-desktop hiding guarantee**. go-fuse passes its
options to fusermount; direct kernel mounting cannot accept `x-*` options.
Veyl conservatively requests the hint only when both the outer go-fuse helper
and the helper on gocryptfs's sanitized PATH report a recognized version of at
least 3.17.4, an upstream release verified to extract userspace `x-*` options.
Older, patched/unrecognized, missing, or unqueryable helpers omit the cosmetic
hint; filesystem startup and legacy configurations retain their prior behavior.
No new minimum FUSE version or user configuration switch is required. Native
compatibility tests use a wrapper reporting 3.16.2 that rejects this hint and
still complete original-path encrypted I/O. A helper accepting the option does
not establish that GNOME received it. Do not enable direct mounting or bypass
Veyl as a visibility workaround.

GVfs's UDisks2 monitor honors `x-gvfs-hide` when it can read the userspace mount
options, normally via GLib built with libmount and helper-maintained mtab/utab
metadata. The hint is not a kernel FUSE option and does not appear in kernel
mountinfo. Check merged metadata with `findmnt -o TARGET,FSTYPE,OPTIONS
--mountpoint /exact/veyl/parent`, and the desktop monitor with `gio mount -li`.
Do not unmount other entries while diagnosing this.

Native synthetic testing on fusermount3 3.18.3 and GIO/GLib 2.90.1 found that the
hint was accepted but not retained: `/run/mount/utab` did not exist, the helper
skipped userspace metadata updates, and GIO still listed the mount. This remains
an environment-dependent UX limitation, not a confirmed sidebar fix on that
host. Veyl does not create a global utab, disguise its filesystem identity, rename
the original parent, or move the mount to a different pathname to hide it.
Other volume monitors and desktops may ignore the hint as well. Sidebar hiding
is not a security feature: mount metadata remains discoverable.

References: [GVfs visibility policy](https://github.com/GNOME/gvfs/blob/master/monitor/udisks2/what-is-shown.txt),
[GVfs option handling](https://github.com/GNOME/gvfs/blob/master/monitor/udisks2/gvfsudisks2volumemonitor.c),
[libfuse 3.18.3 userspace metadata gate](https://github.com/libfuse/libfuse/blob/fuse-3.18.3/lib/mount_util.c),
and [go-fuse mounting paths](https://github.com/hanwen/go-fuse/blob/v2.12.0/fuse/mount_linux.go).

### Eject is an external unmount

The sidebar eject action can unmount the outer Veyl filesystem without using
Veyl's control socket. Successful removal wakes the owner's FUSE-exit watcher;
it permanently suspends authentication, revokes/drains protected operations,
cleans the gocryptfs view, and retires control resources. The supervised run
ends and is not automatically restarted. With original-path presentation, the
unchanged physical parent returns and its empty target remains mode 0500; its
encrypted contents never become files in that physical target. The target name
can reappear once Veyl is no longer mounted.

An eject dialog closing is not confirmation that backing cleanup has finished.
Use `veyl status --config FILE` and `veyl service status`. If cleanup fails, the
locked owner/control endpoint remains available for retries and reports cleanup
pending. Do not delete residues or use lazy/forced unmount as proof of cleanup.
A busy eject may fail and leave Veyl **unlocked**; eject is not a replacement for
`veyl lock`. Native tests cover both a refused busy GIO unmount and successful
GIO unmount while unlocked, followed by confirmed backing/control cleanup.
Prefer Veyl's service stop/unmount commands for ordinary shutdown.

## Known report: default CLI discovery with an active v2 service

The report remains open: `veyl lock` and `veyl status` without `--config` may
fail configuration discovery even though `veyl service status` reports the v2
service running. This is separate from desktop mount visibility and is not
claimed fixed by the GVfs hint. Service commands use the registered service
configuration directly; ordinary commands also consider cwd/local configuration
and the shell PWD hint. The exact failing caller environment is not yet
established. Do not assume the service is stopped because discovery failed.
Use the external configuration filename printed by init:

```sh
veyl status --config /absolute/path/to/configuration.json
veyl lock --config /absolute/path/to/configuration.json
```

Retain the error text, cwd/PWD and XDG_CONFIG_HOME (no passwords) for diagnosis.
Do not replace registrations, search/decrypt stores, or change desktop settings
to work around a discovery failure.

## Fish speculative authentication prompts

Fish highlighting/completion and other programs can look up a protected path
without an intentional access command. Those lookups may trigger repeated
authentication prompts in default mode. The reported Fish root cause is not
conclusively reproduced or resolved: synthetic tests exercise repeated probes,
but do not establish a fix for the reported typing-only flood.

For new setup, use `veyl init --explicit-unlock`. For an existing setup, stop
Veyl cleanly, set `"explicit_unlock": true` in its external configuration, and
restart. Run `veyl unlock --config FILE` before accessing the protected path;
use `--tty` if graphical pinentry is unavailable. Locked filesystem probes then
fail without opening dialogs. Explicit unlock still authenticates, and does
not prevent clients from reading data during an authorized session or change
same-UID/root and caching limitations. No shell-name heuristics are used.
