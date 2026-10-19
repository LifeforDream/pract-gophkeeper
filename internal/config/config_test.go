package config_test

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/LifeforDream/pract-gophkeeper/internal/config"
)

// testOptions — набор настроек, на котором проверяется приоритет источников.
type testOptions struct {
	Addr    string `env:"TEST_ADDR"`
	Level   string `env:"TEST_LEVEL"`
	Retries int    `env:"TEST_RETRIES"`
	Verbose bool   `env:"TEST_VERBOSE"`
}

// newTestFlagSet привязывает флаги к opts; значения по умолчанию заданы только здесь (без envDefault).
func newTestFlagSet(opts *testOptions) *flag.FlagSet {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.StringVar(&opts.Addr, "a", "default-addr", "address")
	fs.StringVar(&opts.Level, "l", "info", "log level")
	fs.IntVar(&opts.Retries, "r", 3, "retries")
	fs.BoolVar(&opts.Verbose, "v", false, "verbose")
	return fs
}

// TestParse_Precedence проверяет порядок: значение по умолчанию < флаг < переменная окружения.
func TestParse_Precedence(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		env      map[string]string
		expected testOptions
	}{
		{
			name:     "defaults only",
			expected: testOptions{Addr: "default-addr", Level: "info", Retries: 3},
		},
		{
			name:     "flag overrides default",
			args:     []string{"-a", "flag-addr", "-l", "debug", "-r", "5", "-v"},
			expected: testOptions{Addr: "flag-addr", Level: "debug", Retries: 5, Verbose: true},
		},
		{
			name:     "env overrides default",
			env:      map[string]string{"TEST_ADDR": "env-addr", "TEST_RETRIES": "7", "TEST_VERBOSE": "true"},
			expected: testOptions{Addr: "env-addr", Level: "info", Retries: 7, Verbose: true},
		},
		{
			name:     "env overrides flag",
			args:     []string{"-a", "flag-addr", "-l", "debug", "-r", "5"},
			env:      map[string]string{"TEST_ADDR": "env-addr", "TEST_LEVEL": "warn", "TEST_RETRIES": "9"},
			expected: testOptions{Addr: "env-addr", Level: "warn", Retries: 9},
		},
		{
			name:     "env overrides only the fields it sets",
			args:     []string{"-a", "flag-addr", "-l", "debug"},
			env:      map[string]string{"TEST_LEVEL": "warn"},
			expected: testOptions{Addr: "flag-addr", Level: "warn", Retries: 3},
		},
		{
			name:     "empty env value does not override flag",
			args:     []string{"-a", "flag-addr"},
			env:      map[string]string{},
			expected: testOptions{Addr: "flag-addr", Level: "info", Retries: 3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			var opts testOptions
			err := config.Parse(newTestFlagSet(&opts), tt.args, &opts)

			require.NoError(t, err)
			assert.Equal(t, tt.expected, opts)
		})
	}
}

// TestParseErrors проверяет, что ошибки разбора флагов и окружения возвращаются, а не теряются.
func TestParseErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		env  map[string]string
	}{
		{name: "unknown flag", args: []string{"-unknown"}},
		{name: "invalid flag value", args: []string{"-r", "abc"}},
		{name: "invalid env value", env: map[string]string{"TEST_RETRIES": "abc"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			var opts testOptions
			fs := newTestFlagSet(&opts)
			fs.SetOutput(discard{})

			err := config.Parse(fs, tt.args, &opts)

			require.Error(t, err)
		})
	}
}

// discard подавляет вывод usage из FlagSet в тестах.
type discard struct{}

// Write отбрасывает данные.
func (discard) Write(p []byte) (int, error) { return len(p), nil }
