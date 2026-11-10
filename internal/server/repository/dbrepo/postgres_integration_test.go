//go:build integration

package dbrepo

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/LifeforDream/pract-gophkeeper/internal/server/domain"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/repository/repotest"
)

// testDSN — адрес Postgres, поднятого в TestMain. Задаётся один раз до запуска тестов и далее только читается.
var testDSN string

// TestMain поднимает один контейнер Postgres на весь пакет и применяет миграции.
func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	ctx := context.Background()
	ctr, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("gophkeeper"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start postgres container:", err)
		return 1
	}
	defer func() {
		if err := testcontainers.TerminateContainer(ctr); err != nil {
			fmt.Fprintln(os.Stderr, "terminate postgres container:", err)
		}
	}()

	testDSN, err = ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Fprintln(os.Stderr, "connection string:", err)
		return 1
	}

	if err := Migrate(ctx, testDSN, slog.Default()); err != nil {
		fmt.Fprintln(os.Stderr, "migrate:", err)
		return 1
	}
	return m.Run()
}

// newCleanPool возвращает пул к базе, из которой удалены все данные.
func newCleanPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	pool, err := NewPool(ctx, testDSN)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	_, err = pool.Exec(ctx, `TRUNCATE record_meta, records, users`)
	require.NoError(t, err)
	return pool
}

// recordsWithUsers дополняет RecordsRepository созданием пользователя "на лету".
//
// Контрактный набор оперирует произвольными user_id ("u1", "u2"), а в Postgres у записи
// обязан быть пользователь (внешний ключ и счётчик ревизий в users).
type recordsWithUsers struct {
	*RecordsRepository
	pool *pgxpool.Pool
}

func (r recordsWithUsers) ensureUser(ctx context.Context, userID string) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO users(id, login, auth_hash, kdf_salt, kdf_memory_kib, kdf_iterations, kdf_parallelism)
		VALUES ($1, $1, '\x00', '\x00', 64, 1, 1)
		ON CONFLICT DO NOTHING`, userID)
	return err
}

func (r recordsWithUsers) Create(ctx context.Context, rec domain.Record) (domain.Record, error) {
	if err := r.ensureUser(ctx, rec.UserID); err != nil {
		return domain.Record{}, err
	}
	return r.RecordsRepository.Create(ctx, rec)
}

func (r recordsWithUsers) Update(ctx context.Context, rec domain.Record) (domain.Record, error) {
	if err := r.ensureUser(ctx, rec.UserID); err != nil {
		return domain.Record{}, err
	}
	return r.RecordsRepository.Update(ctx, rec)
}

func (r recordsWithUsers) Delete(ctx context.Context, userID, recordID string, expectedVersion int64) (int64, error) {
	if err := r.ensureUser(ctx, userID); err != nil {
		return 0, err
	}
	return r.RecordsRepository.Delete(ctx, userID, recordID, expectedVersion)
}

func (r recordsWithUsers) Get(ctx context.Context, userID, recordID string) (domain.Record, error) {
	if err := r.ensureUser(ctx, userID); err != nil {
		return domain.Record{}, err
	}
	return r.RecordsRepository.Get(ctx, userID, recordID)
}

func (r recordsWithUsers) ListChanges(ctx context.Context, userID string, sinceRevision int64) ([]domain.Record, int64, error) {
	if err := r.ensureUser(ctx, userID); err != nil {
		return nil, 0, err
	}
	return r.RecordsRepository.ListChanges(ctx, userID, sinceRevision)
}

func (r recordsWithUsers) List(ctx context.Context, userID string, filter domain.Filter) ([]domain.Record, error) {
	if err := r.ensureUser(ctx, userID); err != nil {
		return nil, err
	}
	return r.RecordsRepository.List(ctx, userID, filter)
}

func TestUsersRepository_Contract(t *testing.T) {
	repotest.RunUsers(t, func(t *testing.T) repotest.UsersRepo {
		return NewUsersRepository(newCleanPool(t))
	})
}

func TestRecordsRepository_Contract(t *testing.T) {
	repotest.RunRecords(t, func(t *testing.T) repotest.RecordsRepo {
		pool := newCleanPool(t)
		return recordsWithUsers{RecordsRepository: NewRecordsRepository(pool, slog.Default()), pool: pool}
	})
}

func TestMigrate_Idempotent(t *testing.T) {
	// Повторный запуск на уже мигрированной базе — не ошибка (migrate.ErrNoChange).
	require.NoError(t, Migrate(t.Context(), testDSN, slog.Default()))
}

func TestNewPool_BadDSN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := NewPool(ctx, "postgres://nobody:nopass@127.0.0.1:1/none?sslmode=disable")
	assert.Error(t, err)
}

// freshDSN создаёт пустую базу и возвращает DSN к ней: к ней ещё не применены миграции.
func freshDSN(t *testing.T, name string) string {
	t.Helper()
	pool := newCleanPool(t)
	_, err := pool.Exec(context.Background(), `CREATE DATABASE `+name)
	require.NoError(t, err)
	return strings.Replace(testDSN, "/gophkeeper", "/"+name, 1)
}

// TestMigrate_CancelledContext — отменённый контекст (как при SIGINT) приводит к ошибке контекста,
// а не к молчаливому успеху; повторный запуск с живым контекстом при этом доводит схему до конца.
func TestMigrate_CancelledContext(t *testing.T) {
	dsn := freshDSN(t, "mig_cancelled")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := Migrate(ctx, dsn, slog.Default())

	require.ErrorIs(t, err, context.Canceled)
	require.NoError(t, Migrate(context.Background(), dsn, slog.Default()), "после прерванного запуска миграции применяются полностью")
}

// TestMigrate_NoGoroutineLeak — Migrate дожидается своей горутины, поэтому повторные вызовы не накапливают горутины.
//
// Прогревочный вызов нужен, потому что часть фоновых горутин драйвера и пулов предыдущих тестов завершается
// не мгновенно. Ожидание сделано циклом, а не assert.Eventually: тот выполняет условие в своих горутинах и
// искажает подсчёт.
func TestMigrate_NoGoroutineLeak(t *testing.T) {
	require.NoError(t, Migrate(context.Background(), testDSN, slog.Default()))
	before := runtime.NumGoroutine()

	for range 10 {
		require.NoError(t, Migrate(context.Background(), testDSN, slog.Default()))
	}

	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	assert.LessOrEqual(t, runtime.NumGoroutine(), before, "горутины Migrate не должны переживать вызов")
}
