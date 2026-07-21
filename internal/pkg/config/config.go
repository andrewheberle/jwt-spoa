package config

import (
	"fmt"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/v2"
	"github.com/spf13/pflag"
)

const (
	DefaultConfigKeyName = "config"
)

type Config interface {
	String(key string) string
	Strings(key string) []string
	Bool(key string) bool
	Bools(key string) []bool
	Int(key string) int
	Ints(key string) []int
}

// Returns a [Config] by reading a YAML based configuration file,
// environment variables and command line flags.
//
// The configuration file is loaded based on the [WithConfigKeyName]
// or the default of [DefaultConfigKeyName] being set in the provided
// [pflag.FlagSet]. Loading of a configuration file can be disabled by
//
// If [WithEnvPrefix] is provided then enviroment variables prefixed with
// "PREFIX_" will be included in the configuration.
func LoadConfig(f *pflag.FlagSet, opts ...ConfigOption) (Config, error) {
	config := &ConfigSettings{
		key: DefaultConfigKeyName,
	}

	for _, o := range opts {
		o(config)
	}

	k := koanf.New(".")

	// load any config file (unless key is set to blank or disabled)
	if config.key != "" && !config.disabled {
		if config, err := f.GetString(config.key); err != nil {
			return nil, fmt.Errorf("error getting flag value: %w", err)
		} else if config != "" {
			if err := k.Load(file.Provider(config), yaml.Parser()); err != nil {
				return nil, fmt.Errorf("error loading configuration: %w", err)
			}
		}
	}

	// Load env vars (unless env prefix is blank)
	if config.envprefix != "" {
		prefix := fmt.Sprintf("%s_", config.envprefix)
		if err := k.Load(env.Provider(".", env.Opt{
			Prefix: prefix,
			TransformFunc: func(k, v string) (string, any) {
				// Transform the key.
				k = strings.ReplaceAll(strings.ToLower(strings.TrimPrefix(k, prefix)), "_", ".")

				// Transform values with commas into slices
				if strings.Contains(v, ",") {
					return k, strings.Split(v, ",")
				}

				return k, v
			},
		}), nil); err != nil {
			return nil, fmt.Errorf("error reading env vars: %w", err)
		}
	}

	// Load command line options
	if err := k.Load(posflag.Provider(f, ".", k), nil); err != nil {
		return nil, fmt.Errorf("error reading command line: %w", err)
	}

	return k, nil
}

type ConfigSettings struct {
	envprefix string
	key       string
	disabled  bool
}

type ConfigOption func(*ConfigSettings)

// Sets a specific key name to lookup the configuration file from
func WithConfigKeyName(key string) ConfigOption {
	return func(c *ConfigSettings) {
		c.key = key
	}
}

// Explicitly disable configuration file loading
func WithoutConfigurationFile() ConfigOption {
	return func(c *ConfigSettings) {
		c.disabled = true
	}
}

// Set the prefix for environment variable loading
func WithEnvPrefix(prefix string) ConfigOption {
	return func(c *ConfigSettings) {
		// trim any undescore as we add it back later
		c.envprefix = strings.TrimSuffix(prefix, "_")
	}
}
