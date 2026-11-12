// Veyl runs one read-only encrypted filesystem instance in the foreground.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/poizdev/veyl/internal/app"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := app.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
