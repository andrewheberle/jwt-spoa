package main

import (
	"context"
	"os"

	"github.com/andrewheberle/jwt-spoa/internal/cmd/jwtspoa"
)

func main() {
	if err := jwtspoa.Execute(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		os.Exit(1)
	}
}
