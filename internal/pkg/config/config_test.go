package config_test

import (
	"testing"

	"github.com/andrewheberle/jwt-spoa/internal/pkg/config"
	"github.com/spf13/pflag"
)

// newFlagSet builds the flag set shared by the table tests below and parses
// args against it, mimicking a real command line invocation.
func newFlagSet(t *testing.T, args []string) *pflag.FlagSet {
	t.Helper()

	f := pflag.NewFlagSet("test", pflag.ContinueOnError)
	f.String("config", "", "path to configuration file")
	f.String("otherconfig", "", "path to configuration file (custom key)")
	f.String("foo", "default-foo", "foo value")
	f.String("bar", "default-bar", "bar value")

	if err := f.Parse(args); err != nil {
		t.Fatalf("failed to parse flags: %v", err)
	}

	return f
}

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		env     map[string]string
		opts    []config.ConfigOption
		want    map[string]string
		wantErr bool
	}{
		{
			name: "defaults only",
			want: map[string]string{"foo": "default-foo", "bar": "default-bar"},
		},
		{
			name: "config file overrides defaults",
			args: []string{"--config=testdata/config.yml"},
			want: map[string]string{"foo": "file-foo", "bar": "file-bar"},
		},
		{
			name: "explicitly blank config flag uses defaults",
			args: []string{"--config="},
			want: map[string]string{"foo": "default-foo", "bar": "default-bar"},
		},
		{
			name:    "nonexistent config file returns error",
			args:    []string{"--config=testdata/does-not-exist.yml"},
			wantErr: true,
		},
		{
			name: "custom config key name loads file",
			args: []string{"--otherconfig=testdata/config.yml"},
			opts: []config.ConfigOption{config.WithConfigKeyName("otherconfig")},
			want: map[string]string{"foo": "file-foo", "bar": "file-bar"},
		},
		{
			name: "env var overrides default when no config file",
			env:  map[string]string{"TEST_BAR": "env-bar"},
			opts: []config.ConfigOption{config.WithEnvPrefix("TEST")},
			want: map[string]string{"foo": "default-foo", "bar": "env-bar"},
		},
		{
			name: "env var without matching prefix option is ignored",
			env:  map[string]string{"TEST_FOO": "env-foo"},
			want: map[string]string{"foo": "default-foo"},
		},
		{
			name: "env var overrides config file value",
			args: []string{"--config=testdata/config.yml"},
			env:  map[string]string{"TEST_FOO": "env-foo"},
			opts: []config.ConfigOption{config.WithEnvPrefix("TEST")},
			want: map[string]string{"foo": "env-foo", "bar": "file-bar"},
		},
		{
			name: "flag overrides default when no config or env",
			args: []string{"--bar=flag-bar"},
			want: map[string]string{"foo": "default-foo", "bar": "flag-bar"},
		},
		{
			name: "flag overrides env var and config file",
			args: []string{"--config=testdata/config.yml", "--foo=flag-foo"},
			env:  map[string]string{"TEST_FOO": "env-foo", "TEST_BAR": "env-bar"},
			opts: []config.ConfigOption{config.WithEnvPrefix("TEST")},
			want: map[string]string{"foo": "flag-foo", "bar": "env-bar"},
		},
		{
			name: "full precedence chain resolved independently per key",
			args: []string{"--config=testdata/config.yml", "--bar=flag-bar"},
			env:  map[string]string{"TEST_FOO": "env-foo"},
			opts: []config.ConfigOption{config.WithEnvPrefix("TEST")},
			want: map[string]string{"foo": "env-foo", "bar": "flag-bar"},
		},
		{
			name: "WithoutConfigurationFile skips loading even when config flag is set",
			args: []string{"--config=testdata/config.yml"},
			opts: []config.ConfigOption{config.WithoutConfigurationFile()},
			want: map[string]string{"foo": "default-foo", "bar": "default-bar"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			f := newFlagSet(t, tt.args)

			got, gotErr := config.LoadConfig(f, tt.opts...)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("LoadConfig() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("LoadConfig() succeeded unexpectedly")
			}

			for key, want := range tt.want {
				if got := got.String(key); got != want {
					t.Errorf("LoadConfig() key %q = %q, want %q", key, got, want)
				}
			}
		})
	}
}
