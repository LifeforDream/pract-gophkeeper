package main

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseOptions проверяет значения по умолчанию и привязку флагов и env-тегов к полям.
func TestParseOptions(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		env      map[string]string
		expected clientOptions
	}{
		{
			name: "defaults",
			expected: clientOptions{
				ServerAddress: "localhost:50001",
				LogLevel:      "info",
			},
		},
		{
			name: "flags are bound to fields",
			args: []string{
				"-a", "127.0.0.1",
				"-l", "debug",
				"-cert", "/tmp/cert",
				"-session", "/tmp/file",
			},
			expected: clientOptions{
				ServerAddress: "127.0.0.1",
				LogLevel:      "debug",
				CaCert:        "/tmp/cert",
				SessionFile:   "/tmp/file",
			},
		},
		{
			name: "env tags are bound to fields",
			env: map[string]string{
				"ADDRESS":      "localhost:50005",
				"LOG_LEVEL":    "WARN",
				"CA_CERT":      "/cert",
				"SESSION_FILE": "/file",
			},
			expected: clientOptions{
				ServerAddress: "localhost:50005",
				LogLevel:      "WARN",
				CaCert:        "/cert",
				SessionFile:   "/file",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			got, _, err := parseOptions(tt.args)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, *got)
		})
	}
}

// TestParseOptions_Remainder проверяет, что аргументы после глобальных флагов (команда и её флаги)
// возвращаются без изменений, а -h даёт flag.ErrHelp.
func TestParseOptions_Remainder(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{"no command", nil, []string{}},
		{"command only", []string{"list"}, []string{"list"}},
		{"global flags before command", []string{"-l", "debug", "get", "--show", "x"}, []string{"get", "--show", "x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, rest, err := parseOptions(tt.args)
			require.NoError(t, err)
			assert.ElementsMatch(t, tt.want, rest)
		})
	}
}

func TestParseOptions_Errors(t *testing.T) {
	_, _, err := parseOptions([]string{"-h"})
	assert.ErrorIs(t, err, flag.ErrHelp)

	_, _, err = parseOptions([]string{"-zzz"})
	assert.Error(t, err)
}
