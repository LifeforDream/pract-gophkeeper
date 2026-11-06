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
		expected serverOptions
	}{
		{
			name: "defaults",
			expected: serverOptions{
				RunAddr:  "localhost:50001",
				LogLevel: "info",
				JWTTTL:   24 * 60,
			},
		},
		{
			name: "flags are bound to fields",
			args: []string{
				"-a", "127.0.0.1",
				"-l", "debug",
				"-d", "postgresql://localhost:5432",
				"-skip-migrate",
				"-tls-cert", "/tmp/cert",
				"-tls-key", "/tmp/key",
				"-s", "secret",
				"-t", "15",
				"-f", "asd",
			},
			expected: serverOptions{
				RunAddr:        "127.0.0.1",
				LogLevel:       "debug",
				DatabaseDsn:    "postgresql://localhost:5432",
				SkipMigrate:    true,
				TLSCertPath:    "/tmp/cert",
				TLSKeyPath:     "/tmp/key",
				JWTSecret:      "secret",
				JWTTTL:         15,
				FakeSaltSecret: "asd",
			},
		},
		{
			name: "env tags are bound to fields",
			env: map[string]string{
				"ADDRESS":         "localhost:50005",
				"LOG_LEVEL":       "WARN",
				"DATABASE_DSN":    "postgresql://127.0.0.1:2345",
				"SKIP_MIGRATIONS": "true",
				"TLS_CERT":        "/cert",
				"TLS_KEY":         "/key",
				"JWT_SECRET":      "not_secret",
				"JWT_TTL":         "60",
				"FAKE_SALT":       "123",
			},
			expected: serverOptions{
				RunAddr:        "localhost:50005",
				LogLevel:       "WARN",
				DatabaseDsn:    "postgresql://127.0.0.1:2345",
				SkipMigrate:    true,
				TLSCertPath:    "/cert",
				TLSKeyPath:     "/key",
				JWTSecret:      "not_secret",
				JWTTTL:         60,
				FakeSaltSecret: "123",
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
