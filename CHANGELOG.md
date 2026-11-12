# Changelog

## v0.1.0-rc.1 (development candidate)

Source-only publication; no stable release or independent security audit.

- Writable Linux FUSE access to gocryptfs stores through a concealed virtual
  directory that remains absent from parent listings when unlocked.
- Graphical pinentry authentication and explicit controlling-terminal fallback,
  with concurrent requests sharing one authentication attempt.
- Session-bound handles, revocation/draining and transactional backing-mount
  adoption with retained ownership on cleanup failure.
- Opt-in systemd user service, automatic locked desktop startup, first-run
  `--autostart`, registered default configuration discovery, readiness reporting
  and cleanup-preserving stop/restart with no automatic crash restart.
- Foreground mount lifecycle, private Unix control socket, status, lock, unlock
  and controlled unmount, including signal-driven cleanup and retry support.
- Default `init [--dir PATH] [--tty]` protects an existing empty directory at its
  original pathname, with private external XDG configuration/data/runtime and
  descriptor-pinned original-parent presentation. Explicit `--legacy-workspace`
  retains v1 setup; existing v1 configurations remain supported.
- Explicit leave/activate/re-enter transition, physical empty-target write guard,
  confirmed mount identity/readiness, and manual stale-mount recovery.
- `--explicit-unlock` mitigation for speculative filesystem authentication probes.
- Read/write/append/truncate, file/directory creation, rename/replacement,
  removal, permissions/times and fsync with epoch-bound opened objects.
- Optional managed-parent namespace mapping ordinary siblings from a separate
  physical source beside the concealed path; conflict and loop prevention.
- Explicit `read_only` compatibility: existing v1 configs remain read-only;
  newly initialized stores enable protected writes.
- User, contributor, architecture, security and troubleshooting documentation.

Known limits: existing empty targets only, with supported sibling trees;
incompatible special-node parents are refused. No populated-data migration, full
POSIX compatibility, protected symlinks, hardlink creation, ACL/xattrs, file locking
or mmap. Public original-mode symlinks work. Existing directory handles are not
redirected. No hostile same-UID/root isolation, plaintext-erasure guarantee,
password recovery or automatic orphan recovery.

Open reports: bare lock/status may fail v2 service configuration discovery;
GNOME Files may show managed mounts despite x-gvfs-hide; Fish speculative probes
may repeatedly prompt, with the reported root cause not conclusively reproduced
or resolved. See [troubleshooting](docs/troubleshooting.md).
