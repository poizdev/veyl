# Desktop user service

Veyl can start automatically with your systemd-managed Linux desktop. The service
runs the same foreground mount implementation independently of a terminal. Every
new process starts locked; startup never asks for a password. Access the known
hidden path or run `veyl unlock` to authenticate.

## Enable explicitly

Install Veyl to a stable executable location first. Create the fresh, dedicated
empty example target using the [quick start](quick-start.md); stop on any error.
Replace `CONFIG` with the external configuration filename printed by init:

```sh
go install -buildvcs=false ./cmd/veyl/
# Initialize only a new empty target in a dedicated parent; see quick start.
veyl init --dir /tmp/veyl-example-parent/test
# Leave the original parent in every shell before activation.
cd /tmp
veyl service enable --config CONFIG
```

`--autostart` is explicit consent to install and enable the user service. You
can combine it with `--dir PATH` and/or `--tty`, but original-mode init accepts
activation only from outside the original parent. Without the flag,
initialization creates only the store/config and prints an optional enable
command. If service setup fails after initialization, the store and config
remain intact.

For an initialized directory (use the external filename printed by init):

```sh
veyl service enable --config /absolute/path/to/configuration.json
```

`veyl service enable` can also discover `./veyl.json`. It registers one default
configuration per user, installs an owned `veyl.service`, enables it for future
graphical sessions, and starts it now if a graphical session is active. With no
active desktop, enablement is saved for the next graphical login. It never starts
a desktop, enables user lingering, or installs a system-wide root service.

The registration is an owned symlink at `$XDG_CONFIG_HOME/veyl/default-config`
(or `~/.config/veyl/default-config`) pointing to the owned v1 or v2 config.
The unit is `$XDG_CONFIG_HOME/systemd/user/veyl.service`. The config, encrypted
store, mountpoint and runtime remain in their existing locations. Unknown unit
files and conflicting registrations are preserved and refused. Keep the workspace
and executable at stable paths. Reinstalling to the same binary path updates the
next run; stop/start the service to use the new binary.

Normal command discovery is `--config FILE`, then `./veyl.json`, then the
registered default. Service management always uses its registered config. Bare
lock/status discovery may fail for an active v2 service. Use the external
filename printed by init in place of `CONFIG`, from outside the original parent:

```sh
veyl status --config CONFIG
veyl unlock --config CONFIG
veyl lock --config CONFIG
veyl unmount --config CONFIG
```

An explicit `--config` selects any existing v1 or v2 configuration. To avoid
accidentally controlling another local workspace, use it when the distinction
matters. Do not move or edit the registered config while an instance is running.

## Commands

| Command | Behavior |
| --- | --- |
| `veyl service enable [--config FILE]` | Opt in to desktop autostart; register/install; start now when a desktop is active. |
| `veyl service start` | Start the registered service in an active desktop session; wait for mount/control readiness. |
| `veyl service status` | Show systemd enablement/process state plus Veyl lock/authentication/cleanup state. |
| `veyl service stop` | Request Veyl's authenticated local cleanup and stop this run; autostart stays enabled. |
| `veyl service disable` | Disable future autostart and request cleanup/stop. Failed cleanup is reported and remains retryable. |

`veyl unmount` also stops the current background mount without disabling the next
login's autostart. Use `veyl service start` to start it again during this session.
Stopping while unlocked revokes/drains handles and cleans up the backing mount.
No terminal must remain open. Explicit `veyl unlock --tty` still reads only the
calling terminal over the peer-validated control socket.

Manual/debug operation is unchanged:

```sh
veyl service stop
veyl mount --config /absolute/path/to/configuration.json
```

Do not run foreground and supervised owners for the same configuration together.
The existing runtime/store locks and mount safety checks reject duplicate owners.
The service CLI also refuses to replace an already running foreground instance.

## Desktop environment

The unit is wanted by and part of `graphical-session.target`, ordered after
`graphical-session-pre.target`. It inherits the user manager's graphical session
environment. Niri should be launched through its session integration, such as
`niri-session` or a display manager; X11 desktops must likewise manage the target
and export their session environment. Veyl does not rewrite compositor config or
import an entire shell environment into unrelated services.

Pinentry needs the appropriate `WAYLAND_DISPLAY` or `DISPLAY`, private
`XDG_RUNTIME_DIR`, and, where applicable, `XAUTHORITY`/session D-Bus address. Veyl's
existing credential adapter filters what the pinentry child receives. If the
manager lacks desktop variables, use your desktop's documented systemd session
setup. Do not enable lingering as a workaround. An explicit terminal unlock is
available while diagnosing GUI integration.

References: [systemd graphical session
targets](https://www.freedesktop.org/software/systemd/man/latest/systemd.special.html#graphical-session.target),
[Niri systemd setup](https://niri-wm.github.io/niri/Example-systemd-Setup.html).

## Logout, restart and failure

The unit uses readiness notification, `Restart=no`, `KillMode=mixed`,
`SendSIGKILL=no` and an unlimited stop timeout. Logout or a systemd stop/restart
signals the main owner, allowing its existing policy drain and storage cleanup
to finish before children are torn down. A restart cannot start a fresh owner
until the previous run exits. A cleanup failure keeps the locked owner/control
endpoint alive for retry; a blocked I/O or failed cleanup can delay stopping or
logout. Veyl deliberately does not force-kill an owner to claim cleanup succeeded.

Power loss, SIGKILL or an external manager forcibly terminating the user session
can still prevent cleanup. No process can guarantee cleanup after those events.
Veyl does not blindly restart after a crash. A stale outer FUSE mount, backing
mount or nonempty views directory blocks startup and is reported as cleanup
pending. Never delete residue to make a restart appear successful; follow
[manual recovery](troubleshooting.md).

For diagnostics:

```sh
veyl service status
systemctl --user status veyl.service
journalctl --user -u veyl.service -b
```

After resolving a startup problem and confirming cleanup:

```sh
veyl service start
```

If stopping reports cleanup pending, keep the owner alive, close clients using
the mount, and retry `veyl unmount` or `veyl service stop`. Disabling autostart
still removes future login activation even when cleanup needs a retry. Disabling
does not delete the config, store, registration or unit, so discovery and later
re-enablement remain available. Replacing an existing registration/unit with a
different setup is intentionally refused; inspect and stop the old service first.

The service does not change Veyl's [security model](security.md): same-UID
processes/root can still bypass the virtual view through the plaintext backing
mount, and lock cannot erase previously copied plaintext or caches.

The service also supports writable protected access and the optional separate
managed parent from v1 or v2 configuration. Every start still locks the
protected branch; ordinary siblings remain public. Lock synchronizes/closes
protected descriptors before backing unmount, while stop also retires the public
tree. Sync failures retain the owner for cleanup retry. Never run a second
standalone gocryptfs writer against the store. Original-path v2 starts the same
managed parent view at its original pathname, with a descriptor pinned before
mounting. Populated-target migration is refused. Its persistent store/config
stay in XDG data/config; private runtime resources can be recreated after login,
but existing mounts or view residue block startup. The empty physical target
remains mode 0500 after stop/crash. Leave and re-enter the original path; old
cwd/parent descriptors cannot be redirected.

## File-manager visibility and eject

Managed mounts request the per-mount `x-gvfs-hide` hint. This only hides sidebar
entries on compatible helper/GLib/GVfs combinations; navigation still uses the
original pathname. Some environments discard the userspace option, so a drive
and eject button may remain. See [visibility
diagnostics](troubleshooting.md#drivesidebar-entry-in-gnome-files).

Successful file-manager eject is an external unmount: the existing FUSE-exit
watcher revokes access, performs backing cleanup and ends this supervised run.
A busy eject may fail while the session stays unlocked. Check Veyl status using
its explicit config; an eject dialog is not cleanup confirmation. If cleanup
fails, keep the owner alive and retry through its control socket. No automatic
restart, fstab edit, global desktop preference, or alternate plaintext path is
introduced. The empty guarded physical target returns after original-parent
unmount; encrypted contents remain in the store.

The reported difference between `service status` and configuration discovery by
bare `lock`/`status` is retained as an [open CLI
report](troubleshooting.md#known-report-default-cli-discovery-with-an-active-v2-service).