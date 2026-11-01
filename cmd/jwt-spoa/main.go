package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/andrewheberle/jwt-spoa/internal/cmd/jwtspoa"
)

func main() {
	os.Exit(run())
}

// run executes jwt-spoa until it fails or receives SIGINT or SIGTERM, and
// returns the exit status.
func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// restore default signal handling once shutdown starts, so a second
	// signal stops the process immediately
	go func() {
		<-ctx.Done()
		stop()
	}()

	if err := jwtspoa.Execute(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		return 1
	}

	return 0
}
