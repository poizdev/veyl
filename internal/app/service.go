//go:build linux

package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/poizdev/veyl/internal/storage"
	"golang.org/x/sys/unix"
)

const serviceName = "veyl.service"
const serviceHeader = "# Managed by Veyl. Keep custom changes in systemd drop-ins.\n"
const serviceHelp = `Veyl desktop user service (one default configuration per user)

Usage:
  veyl service enable [--config FILE]
  veyl service disable
  veyl service start
  veyl service stop
  veyl service status

Enable explicitly opts into automatic startup on graphical desktop login and
starts the mount now when a graphical session is active. It always starts locked.
Disable removes automatic startup and requests confirmed cleanup before stopping.
Stop ends this run; enablement is unchanged. Start never starts your desktop.

Configuration discovery: --config FILE, ./veyl.json, then the registered default.
Version 1 and original-path version 2 configs and encrypted stores are preserved.
Original-path setup requires leaving the original parent before activation.
Use the external configuration filename printed by init.
Foreground/debug mode remains: veyl mount [--config FILE].

No root service, lingering, automatic crash restart, or automatic residue removal.
If cleanup fails, keep the owner alive and retry veyl unmount or veyl service stop.
Diagnostics: systemctl --user status veyl.service
             journalctl --user -u veyl.service -b
`

func serviceCommand(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(out, serviceHelp)
		return 0
	}
	op := args[0]
	if op != "enable" && op != "disable" && op != "start" && op != "stop" && op != "status" {
		fmt.Fprint(errOut, serviceHelp)
		return 2
	}
	flags := flag.NewFlagSet("service "+op, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	config := ""
	if op == "enable" {
		flags.StringVar(&config, "config", "", "version 1 or 2 configuration")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprint(out, serviceHelp)
			return 0
		}
		fmt.Fprint(errOut, serviceHelp)
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprint(errOut, serviceHelp)
		return 2
	}
	var result Result
	if os.Geteuid() == 0 {
		result = Result{Code: 1, Message: "Use Veyl's user service as your normal desktop user, not root."}
	} else {
		switch op {
		case "enable":
			result = enableService(ctx, config)
		case "start":
			result = startService(ctx)
		case "stop":
			result = stopService(ctx)
		case "disable":
			if _, err := managedService(); err != nil {
				result = Result{Code: 2, Message: err.Error()}
				break
			}
			if _, err := systemctl(ctx, "disable", serviceName); err != nil {
				result = serviceError("Cannot disable automatic startup")
				break
			}
			result = stopService(ctx)
			result.Message = "Automatic startup disabled. " + result.Message
		case "status":
			result = serviceStatus(ctx)
		}
	}
	writer := out
	if result.Code != 0 {
		writer = errOut
	}
	fmt.Fprintln(writer, result.Message)
	return result.Code
}

func systemctl(parent context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 40*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "systemctl", append([]string{"--user"}, args...)...)
	data, err := command.Output()
	return strings.TrimSpace(string(data)), err
}
func serviceError(reason string) Result {
	return Result{Code: 1, Message: reason + ". Check systemctl --user status veyl.service and journalctl --user -u veyl.service -b. No cleanup residue is removed automatically."}
}
func graphicalSession(ctx context.Context) (bool, error) {
	state, err := systemctl(ctx, "show", "graphical-session.target", "--property=ActiveState", "--value")
	return state == "active", err
}

// Quote systemd command words, not shell words. Disable both kinds of expansion.
func unitWord(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "%", "%%", "$", "$$")
	return "\"" + replacer.Replace(value) + "\""
}
func serviceUnit(binary, config string) (string, error) {
	for _, value := range []string{binary, config} {
		if !filepath.IsAbs(value) {
			return "", errConfig
		}
		for _, c := range value {
			if c < 32 || c == 127 {
				return "", errors.New("Service paths must not contain control characters.")
			}
		}
	}
	return serviceHeader + fmt.Sprintf(`[Unit]
Description=Veyl encrypted filesystem
Documentation=https://github.com/poizdev/veyl
PartOf=graphical-session.target
After=graphical-session-pre.target

[Service]
Type=notify
NotifyAccess=main
ExecStart=%s mount --config %s
Restart=no
KillMode=mixed
KillSignal=SIGTERM
SendSIGKILL=no
TimeoutStartSec=30s
TimeoutStopSec=infinity
UMask=0077
Environment=PATH=/usr/local/bin:/usr/bin:/bin
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=graphical-session.target
`, unitWord(binary), unitWord(config)), nil
}

func ensureServiceDirectory(path string, private bool) error {
	if storage.ValidateDirectory(path, private) == nil {
		return nil
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return errors.New("User service paths must be owned directories without symlinks or unsafe permissions.")
	}
	parent := filepath.Dir(path)
	if parent == path {
		return errConfig
	}
	if err := ensureServiceDirectory(parent, false); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	return storage.ValidateDirectory(path, private)
}
func readServiceUnit(path string) (string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), "veyl-user-service")
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !owned(info, 0600) || info.Size() > 16384 || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return "", errors.New("Refusing to replace an unrecognized or unsafe veyl.service file.")
	}
	data, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || !strings.HasPrefix(string(data), serviceHeader) {
		return "", errors.New("Refusing to replace an unrecognized veyl.service file.")
	}
	return string(data), nil
}
func managedService() (serviceFiles, error) {
	files, err := userServiceFiles()
	if err != nil {
		return files, err
	}
	if storage.ValidateDirectory(filepath.Dir(files.unit), false) != nil {
		return files, errors.New("Veyl user service is not installed in a safe directory. Run veyl service enable first.")
	}
	if _, err = readServiceUnit(files.unit); err != nil {
		return files, errors.New("Veyl user service is not installed or is not managed by Veyl. Inspect it before running service commands.")
	}
	return files, nil
}

func enableService(ctx context.Context, selected string) Result {
	path, err := discoverConfig(selected)
	if err != nil {
		return Result{Code: 2, Message: err.Error()}
	}
	c, err := LoadConfig(path)
	if err != nil {
		return Result{Code: 2, Message: err.Error()}
	}
	files, err := userServiceFiles()
	if err != nil {
		return Result{Code: 2, Message: err.Error()}
	}
	desktop, err := graphicalSession(ctx)
	if err != nil {
		return serviceError("Cannot contact the systemd user manager")
	}
	active, _ := systemctl(ctx, "is-active", serviceName)
	state := clientCommand(ctx, c, "status", false)
	if state.Code == 5 {
		return state
	}
	if state.Code == 0 && active != "active" {
		return Result{Code: 1, Message: "A foreground Veyl instance is already running. Unmount it before enabling the user service."}
	}
	if state.Code != 0 && state.Code != 3 {
		return state
	}
	binary, err := os.Executable()
	if err != nil || beneath(c.Mountpoint, binary) {
		return Result{Code: 2, Message: "Install Veyl outside its mount before enabling automatic startup."}
	}
	unit, err := serviceUnit(binary, path)
	if err != nil {
		return Result{Code: 2, Message: err.Error()}
	}
	// Preflight existing files before writing anything. Never adopt another unit.
	existing, err := readServiceUnit(files.unit)
	if err != nil && !os.IsNotExist(err) {
		return Result{Code: 2, Message: err.Error()}
	}
	if err == nil && existing != unit {
		return Result{Code: 2, Message: "Existing veyl.service differs from this setup. It was preserved; disable and inspect it before changing the registered service."}
	}
	if target, err := registeredConfig(); err == nil && target != path {
		return Result{Code: 2, Message: "Another default configuration is registered. It was preserved; stop and inspect the existing service before changing it."}
	} else if err != nil && !os.IsNotExist(err) {
		return Result{Code: 2, Message: err.Error()}
	}
	if err := ensureServiceDirectory(files.directory, true); err != nil {
		return Result{Code: 2, Message: err.Error()}
	}
	if err := ensureServiceDirectory(filepath.Dir(files.unit), false); err != nil {
		return Result{Code: 2, Message: err.Error()}
	}
	if _, err := os.Lstat(files.registration); os.IsNotExist(err) {
		if err := os.Symlink(path, files.registration); err != nil {
			return serviceError("Cannot register the default configuration; generated files were retained for inspection")
		}
	}
	if existing == "" {
		f, err := os.OpenFile(files.unit, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return serviceError("Cannot create the user service; existing files were preserved")
		}
		_, err = f.WriteString(unit)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			return serviceError("Cannot finish writing the user service; partial output was retained")
		}
	}
	if _, err := systemctl(ctx, "daemon-reload"); err != nil {
		return serviceError("User service files were created, but daemon-reload failed")
	}
	if _, err := systemctl(ctx, "enable", serviceName); err != nil {
		return serviceError("Cannot enable automatic startup; generated service files were retained")
	}
	if !desktop {
		return Result{Message: "Automatic startup enabled for the next graphical desktop session. It will start locked. No lingering or root service was enabled."}
	}
	result := startService(ctx)
	result.Message = "Automatic startup enabled. " + result.Message
	return result
}

func serviceConfig() (Config, error) {
	if _, err := managedService(); err != nil {
		return Config{}, err
	}
	path, err := registeredConfig()
	if err != nil {
		return Config{}, errors.New("No safe default configuration registration. Run veyl service enable --config FILE.")
	}
	return LoadConfig(path)
}
func startService(ctx context.Context) Result {
	c, err := serviceConfig()
	if err != nil {
		return Result{Code: 2, Message: err.Error()}
	}
	desktop, err := graphicalSession(ctx)
	if err != nil {
		return serviceError("Cannot contact the systemd user manager")
	}
	if !desktop {
		return Result{Code: 1, Message: "No active graphical desktop session. Automatic startup waits for desktop login; Veyl will not start your desktop or enable lingering."}
	}
	active, _ := systemctl(ctx, "is-active", serviceName)
	state := clientCommand(ctx, c, "status", false)
	if state.Code == 5 {
		return state
	}
	if state.Code == 0 && active == "active" {
		state.Message = "Veyl service is already running. " + state.Message
		return state
	}
	if state.Code == 0 {
		return Result{Code: 1, Message: "Another Veyl owner is running. Unmount the foreground instance before starting the service."}
	}
	if state.Code != 3 {
		return state
	}
	if _, err := systemctl(ctx, "start", serviceName); err != nil {
		return serviceError("Veyl service failed to start")
	}
	result := clientCommand(ctx, c, "status", false)
	if result.Code == 0 {
		result.Message = "Veyl service started. " + result.Message
	}
	return result
}
func stopService(ctx context.Context) Result {
	c, err := serviceConfig()
	if err != nil {
		return Result{Code: 2, Message: err.Error()}
	}
	result := clientCommand(ctx, c, "unmount", false)
	if result.Code != 0 && result.Code != 3 {
		return result
	}
	if _, err := systemctl(ctx, "stop", "--no-block", serviceName); err != nil {
		return serviceError("Cleanup completed, but systemd stop could not be requested")
	}
	return Result{Message: "Veyl stopped; managed mount cleanup confirmed."}
}
func serviceStatus(ctx context.Context) Result {
	c, err := serviceConfig()
	if err != nil {
		return Result{Code: 2, Message: err.Error()}
	}
	properties, err := systemctl(ctx, "show", serviceName, "--property=ActiveState,SubState,Result,UnitFileState")
	if err != nil {
		return serviceError("Cannot query the Veyl user service")
	}
	result := clientCommand(ctx, c, "status", false)
	if result.Code == 3 && strings.Contains(properties, "ActiveState=failed") {
		return serviceError("Veyl user service failed. " + strings.ReplaceAll(properties, "\n", "; "))
	}
	result.Message = properties + "\n" + result.Message
	return result
}
