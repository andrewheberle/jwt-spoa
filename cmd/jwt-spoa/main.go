package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/andrewheberle/jwt-spoa/internal/pkg/logger"
	"github.com/andrewheberle/jwt-spoa/internal/pkg/spoa"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/v2"
	"github.com/oklog/run"
	"github.com/spf13/pflag"
)

var Version = "dev"

func main() {
	lt := new(logger.LoggerTypeVar)

	f := pflag.NewFlagSet("jwt-spoa", pflag.ContinueOnError)
	f.String("config", "", "Path to configuration file")
	f.String("listen", "127.0.0.1:3000", "SPOA listen address")
	f.String("metrics.path", "/metrics", "Path for Prometheus metrics")
	f.String("metrics.listen", "", "Listen address for Prometheus metrics")
	f.StringSlice("jwt.methods", []string{"RS256"}, "Accepted methods for verifying the JWT's")
	f.String("jwt.aud", "", "Audience (aud) claim of the JWT's")
	f.String("jwt.iss", "", "Issuer (iss) claim of the JWT's (required)")
	f.String("jwt.jwks", "", "URL of JSON Web Key Set (JWKS) used to verify the JWT's (required)")
	f.StringSlice("jwt.claims", []string{"email"}, "Claims to extract (if present) from JWT's")
	f.Bool("debug", false, "Enable debug logging")
	f.Bool("version", false, "Show version and exit")
	f.Var(lt, "logger.type", "Logger type (auto, discard, json, systemd or text)")

	// parse command line
	if err := f.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing command line flags: %s\n", err)
		os.Exit(1)
	}

	// handle if version was requested
	if version, err := f.GetBool("version"); err == nil && version {
		fmt.Printf("%s %s\n", f.Name(), Version)
		os.Exit(0)
	}

	k := koanf.New(".")

	// load any config file
	if config, err := f.GetString("config"); err != nil {
		fmt.Fprintf(os.Stderr, "error getting flag value: %s\n", err)
		os.Exit(1)
	} else if config != "" {
		if err := k.Load(file.Provider(config), yaml.Parser()); err != nil {
			fmt.Fprintf(os.Stderr, "error loading configuration: %s\n", err)
			os.Exit(1)
		}
	}

	// Load env vars
	if err := k.Load(env.Provider(".", env.Opt{
		Prefix: "JWT_",
		TransformFunc: func(k, v string) (string, any) {
			// Transform the key.
			k = strings.ReplaceAll(strings.ToLower(strings.TrimPrefix(k, "JWT_")), "_", ".")

			// Transform values with commas into slices
			if strings.Contains(v, ",") {
				return k, strings.Split(v, ",")
			}

			return k, v
		},
	}), nil); err != nil {
		fmt.Fprintf(os.Stderr, "error reading env vars: %s\n", err)
		os.Exit(1)
	}

	// Load command line options
	if err := k.Load(posflag.Provider(f, ".", k), nil); err != nil {
		fmt.Fprintf(os.Stderr, "error reading command line: %s\n", err)
		os.Exit(1)
	}

	// set up logger
	logLevel := new(slog.LevelVar)
	ltString := k.String("logger.type")
	logger, err := logger.NewLogger(logLevel, logger.WithLoggerType(logger.LoggerType(ltString)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error setting up logger: %s\n", err)
		os.Exit(1)
	}
	if k.Bool("debug") {
		logLevel.Set(slog.LevelDebug)
	}

	listenString := k.String("listen")
	iss := k.String("jwt.iss")
	if iss == "" {
		logger.Error("issuer must be provided for verifying JWT's")
		os.Exit(1)
	}
	jwksUrl := k.String("jwt.jwks")
	if jwksUrl == "" {
		// try to create from ISSUER/.well-known/jwks.json
		u, err := url.JoinPath(iss, ".well-known/jwks.json")
		if err != nil {
			logger.Error("could not parse issuer as a URL to create JWKS URL", "error", err)
			os.Exit(1)
		}
		jwksUrl = u
	}
	methods := k.Strings("jwt.methods")
	if len(methods) == 0 {
		logger.Error("at least one method must be set for verifying JWT's")
		os.Exit(1)
	}
	opts := []spoa.ServerOption{
		spoa.WithLogger(logger),
		spoa.WithClaims(k.Strings("jwt.claims")),
	}
	if aud := k.String("jwt.aud"); aud != "" {
		opts = append(opts, spoa.WithAudience(aud))
	}
	opts = append(opts, spoa.WithValidMethods(methods))
	srv, err := spoa.NewServer(listenString, jwksUrl, iss, opts...)
	if err != nil {
		logger.Error("there was a problem setting up the server", "error", err, "listen", listenString, "jwks", jwksUrl)
		os.Exit(1)
	}

	g := run.Group{}
	g.Add(func() error {
		return srv.ListenAndServe()
	}, func(err error) {
		if err != nil {
			logger.Error("got error from server", "error", err, "listen", listenString)
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
		os.Exit(1)
	}
}
