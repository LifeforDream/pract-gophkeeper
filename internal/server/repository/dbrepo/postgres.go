// Package dbrepo хранит реализацию репозиториев для работы приложения с Postgresql.
package dbrepo

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/LifeforDream/pract-gophkeeper/migrations"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"

	_ "github.com/golang-migrate/migrate/v4/database/postgres"
)

// NewPool создаёт пул postgres из dsn.
func NewPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}
	return pool, nil
}

// Migrate применяет миграции, упакованные в бинарь.
func Migrate(ctx context.Context, dsn string, logger *slog.Logger) error {
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("load migrations: %w", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", src, dsn)
	if err != nil {
		return fmt.Errorf("init migrator: %w", err)
	}

	defer func() {
		if srcErr, dbErr := m.Close(); srcErr != nil || dbErr != nil {
			logger.Warn("close errors: ", "src", srcErr, "db", dbErr)
		}
	}()

	finished := make(chan struct{}) // закрывается, когда Up вернул управление.
	stopped := make(chan struct{})  // закрывается, когда горутина завершилась.
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			m.GracefulStop <- true // отправка не блокируется.
		case <-finished:
		}
	}()
	defer func() {
		close(finished)
		<-stopped
	}()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("apply migrations: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("migrations interrupted: %w", err)
	}

	return nil
}
