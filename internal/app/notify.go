//go:build linux

package app

import (
	"errors"
	"net"
	"os"
	"strings"
	"time"
)

// Readiness is sent only after FUSE and control are serving. There is no
// dependency on systemd or its libraries for ordinary foreground operation.
func notifyReady() error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return nil
	}
	if !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "@") {
		return errors.New("invalid service notification endpoint")
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	_, err = conn.Write([]byte("READY=1\nSTATUS=Veyl mount ready; use veyl status for lock and cleanup state.\n"))
	return err
}
