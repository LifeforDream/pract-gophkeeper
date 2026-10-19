package main

import (
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
				"-file", "/tmp/file",
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
			got, err := parseOptions(tt.args)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, *got)
		})
	}
}
