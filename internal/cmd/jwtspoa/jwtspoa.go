// Package jwtspoa runs the jwt-spoa command.
package jwtspoa

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/andrewheberle/configger"
	"github.com/andrewheberle/jwt-spoa/internal/pkg/spoa"
	"github.com/andrewheberle/jwt-spoa/internal/version"
	"github.com/andrewheberle/slogger"
	"github.com/oklog/run"
	"github.com/spf13/pflag"
)

// Execute runs jwt-spoa with the command line arguments args (excluding the
// program name) until ctx is cancelled or a listener fails. It reports every
// error itself, to stderr before logging is set up and through the logger
// after, and also returns it.
func Execute(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	lt := new(slogger.LoggerTypeVar)

	f := pflag.NewFlagSet("jwt-spoa", pflag.ContinueOnError)
	f.SetOutput(stderr)
	f.String("config", "", "Path to configuration file")
	f.String("listen", "127.0.0.1:3000", "SPOA listen address")
	f.String("metrics.path", "/metrics", "Path for Prometheus metrics")
	f.String("metrics.listen", "", "Listen address for Prometheus metrics")
	f.StringSlice("jwt.methods", []string{"RS256"}, "Accepted methods for verifying the JWT's")
	f.String("jwt.aud", "", "Audience (aud) claim of the JWT's")
	f.String("jwt.iss", "", "Issuer (iss) claim of the JWT's (required)")
	f.String("jwt.jwks", "", "URL of JSON Web Key Set (JWKS) used to verify the JWT's (required)")
	f.StringSlice("jwt.claims", []string{"email"}, "Claims to extract (if present) from JWT's")
	f.StringSlice("jwt.requiredclaims", []string{}, "Required claims to extract (if present) from JWT's")
	f.Bool("debug", false, "Enable debug logging")
	f.Bool("version", false, "Show version and exit")
	f.Var(lt, "logger.type", "Logger type (auto, discard, json, systemd or text)")

	// parse command line
	if err := f.Parse(args); err != nil {
		_, _ = fmt.Fprintf(stderr, "error parsing command line flags: %s\n", err)
		return fmt.Errorf("parsing command line flags: %w", err)
	}

	// handle if version was requested
	if v, err := f.GetBool("version"); err == nil && v {
		_, _ = fmt.Fprintf(stdout, "%s %s\n", f.Name(), version.Version)
		return nil
	}

	// load config
	k, err := configger.LoadConfig(f, configger.WithEnvPrefix("JWT"))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error setting up config: %s\n", err)
		return fmt.Errorf("setting up config: %w", err)
	}

	// set up logger
	logLevel := new(slog.LevelVar)
	logger, err := slogger.NewLogger(logLevel, lt.LoggerTypeOption())
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error setting up logger: %s\n", err)
		return fmt.Errorf("setting up logger: %w", err)
	}
	if k.Bool("debug") {
		logLevel.Set(slog.LevelDebug)
	}

	// set up service
	cfg := spoa.Config{
		Listen:         k.String("listen"),
		Issuer:         k.String("jwt.iss"),
		JWKS:           k.String("jwt.jwks"),
		Audience:       k.String("jwt.aud"),
		Methods:        k.Strings("jwt.methods"),
		Claims:         k.Strings("jwt.claims"),
		RequiredClaims: k.Strings("jwt.requiredclaims"),
	}
	srv, err := spoa.NewServer(cfg, spoa.WithLogger(logger))
	if err != nil {
		logger.Error("there was a problem setting up the server", "error", err, "listen", cfg.Listen)
		return fmt.Errorf("setting up server: %w", err)
	}

	g := run.Group{}

	ctx, cancel := context.WithCancel(ctx)
	g.Add(func() error {
		<-ctx.Done()
		return nil
	}, func(error) {
		cancel()
	})

	g.Add(func() error {
		return srv.ListenAndServe()
	}, func(err error) {
		if err != nil {
			logger.Error("got error from server", "error", err, "listen", cfg.Listen)
		}
		_ = srv.Shutdown()
	})

	if metricsListen := k.String("metrics.listen"); metricsListen != "" {
		// set up metrics
		metricsPath := k.String("metrics.path")
		h := http.NewServeMux()
		h.Handle(metricsPath, srv.MetricsHandler())

		metrics := &http.Server{
			Addr:         metricsListen,
			Handler:      h,
			ReadTimeout:  time.Second * 2,
			WriteTimeout: time.Second * 2,
		}

		g.Add(func() error {
			logger.Info("starting metrics listener", "listen", metricsListen, "path", metricsPath)
			return metrics.ListenAndServe()
		}, func(err error) {
			if err != nil {
				logger.Error("got error from metrics listener", "error", err, "listen", metricsListen, "path", metricsPath)
			}
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
				defer cancel()

				if err := metrics.Shutdown(ctx); err != nil {
					logger.Error("got error while shutting down metrics listener", "error", err, "listen", metricsListen, "path", metricsPath)
				}
			}()
		})
	}

	if err := g.Run(); err != nil {
		logger.Error("got an error", "error", err)
		return fmt.Errorf("running: %w", err)
	}

	return nil
}
