package app

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewDbRepos_Errors — ошибки подключения возвращаются с пометкой того шага, на котором они случились.
// Адрес с портом 1 отказывает в соединении сразу, поэтому тест не требует работающего Postgres.
func TestNewDbRepos_Errors(t *testing.T) {
	const dsn = "postgres://nobody:nopass@127.0.0.1:1/none?sslmode=disable"

	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"migrations are applied first", Config{DatabaseDsn: dsn}, "error performing migrations"},
		{"skip-migrate goes straight to the pool", Config{DatabaseDsn: dsn, SkipMigrate: true}, "error connecting to db"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
			defer cancel()

			repos, err := newDbRepos(ctx, tt.cfg, discardLogger())

			require.Error(t, err)
			assert.ErrorContains(t, err, tt.wantErr)
			assert.Nil(t, repos, "при ошибке набор репозиториев не возвращается")
			assert.NotContains(t, err.Error(), "nopass", "пароль из DSN не должен попадать в текст ошибки")
		})
	}
}
