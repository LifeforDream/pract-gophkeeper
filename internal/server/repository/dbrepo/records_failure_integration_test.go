//go:build integration

package dbrepo

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/LifeforDream/pract-gophkeeper/internal/server/domain"
)

// failureTimeout — предел ожидания операций, которые должны завершиться сразу.
// Если соединение не вернулось в пул, операция зависает, и тест падает по этому пределу.
const failureTimeout = 5 * time.Second

// cancelOnQuery — трассировщик pgx, который отменяет контекст в момент старта запроса с заданным SQL.
// Так ошибка воспроизводится детерминированно посередине транзакции, после предыдущих запросов.
type cancelOnQuery struct {
	trigger string
	cancel  context.CancelFunc
}

func (c *cancelOnQuery) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, c.trigger) {
		c.cancel()
	}
	return ctx
}

func (c *cancelOnQuery) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// testRecord возвращает запись с заполненными полями, достаточными для Create.
func testRecord(userID, id string) domain.Record {
	return domain.Record{
		UserID:      userID,
		ID:          id,
		Header:      []byte("header-" + id),
		HeaderNonce: []byte("hn-" + id),
		Body:        []byte("body-" + id),
		BodyNonce:   []byte("bn-" + id),
	}
}

// syncLog возвращает логгер, пишущий в буфер, и сам буфер. Репозиторий пишет в лог только из вызывающей горутины.
func syncLog() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return slog.New(slog.NewTextHandler(buf, nil)), buf
}

// TestRecordsRepository_FailureRollsBack — ошибка посередине транзакции откатывает её целиком:
// ни запись, ни ревизия пользователя не меняются, соединение возвращается в пул, а сам откат проходит без ошибки.
//
// Контекст отменяется в момент старта «последнего» запроса операции, уже после того, как ревизия пользователя
// была увеличена. Пул ограничен одним соединением, поэтому незавершённая транзакция заблокировала бы следующую операцию.
// Откат при уже отменённом контексте (context.WithoutCancel в rollback) подтверждается отсутствием
// предупреждения "error on txn rollback" в логе.
func TestRecordsRepository_FailureRollsBack(t *testing.T) {
	const userID = "u1"

	tests := []struct {
		name       string
		trigger    string // фрагмент SQL, на старте которого отменяется контекст
		seedRecord bool   // создать запись r1 до вызова
		call       func(ctx context.Context, repo *RecordsRepository) error
	}{
		{
			name:    "create fails on insert",
			trigger: "INSERT INTO records",
			call: func(ctx context.Context, repo *RecordsRepository) error {
				_, err := repo.Create(ctx, testRecord(userID, "r1"))
				return err
			},
		},
		{
			name:       "update fails on write",
			trigger:    "UPDATE records SET",
			seedRecord: true,
			call: func(ctx context.Context, repo *RecordsRepository) error {
				changed := testRecord(userID, "r1")
				changed.Version = 1
				changed.Header = []byte("changed")
				_, err := repo.Update(ctx, changed)
				return err
			},
		},
		{
			name:       "delete fails on tombstone write",
			trigger:    "UPDATE records SET deleted",
			seedRecord: true,
			call: func(ctx context.Context, repo *RecordsRepository) error {
				_, err := repo.Delete(ctx, userID, "r1", 1)
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Подготовка состояния отдельным пулом без трассировщика.
			seedPool := newCleanPool(t)
			seed := recordsWithUsers{RecordsRepository: NewRecordsRepository(seedPool, slog.Default()), pool: seedPool}
			require.NoError(t, seed.ensureUser(context.Background(), userID))
			wantRevision := int64(0)
			if tt.seedRecord {
				_, err := seed.RecordsRepository.Create(context.Background(), testRecord(userID, "r1"))
				require.NoError(t, err)
				wantRevision = 1
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cfg, err := pgxpool.ParseConfig(testDSN)
			require.NoError(t, err)
			cfg.MaxConns = 1
			cfg.ConnConfig.Tracer = &cancelOnQuery{trigger: tt.trigger, cancel: cancel}
			pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
			require.NoError(t, err)
			t.Cleanup(pool.Close)
			logger, logs := syncLog()
			repo := NewRecordsRepository(pool, logger)

			err = tt.call(ctx, repo)

			require.ErrorIs(t, err, context.Canceled)
			assert.NotContains(t, logs.String(), "error on txn rollback", "откат должен проходить даже при отменённом контексте")

			// Ничего не изменилось: ни ревизия пользователя, ни запись.
			got, revision, err := seed.RecordsRepository.List(context.Background(), userID, 0)
			require.NoError(t, err)
			assert.Equal(t, wantRevision, revision, "ревизия пользователя не должна расходоваться")
			if tt.seedRecord {
				require.Len(t, got, 1)
				assert.Equal(t, int64(1), got[0].Version)
				assert.False(t, got[0].Deleted)
				assert.Equal(t, []byte("header-r1"), got[0].Header)
			} else {
				assert.Empty(t, got)
			}

			// Единственное соединение пула свободно, и следующая запись получает следующую ревизию без пропусков.
			followCtx, followCancel := context.WithTimeout(context.Background(), failureTimeout)
			defer followCancel()
			next, err := repo.Create(followCtx, testRecord(userID, "next"))
			require.NoError(t, err)
			assert.Equal(t, wantRevision+1, next.Revision)
		})
	}
}

// TestRecordsRepository_CancelledBeforeBegin — при уже отменённом контексте транзакция не открывается,
// операция возвращает ошибку контекста и ничего не меняет.
func TestRecordsRepository_CancelledBeforeBegin(t *testing.T) {
	const userID = "u1"

	tests := []struct {
		name string
		call func(ctx context.Context, repo *RecordsRepository) error
	}{
		{"create", func(ctx context.Context, repo *RecordsRepository) error {
			_, err := repo.Create(ctx, testRecord(userID, "new"))
			return err
		}},
		{"update", func(ctx context.Context, repo *RecordsRepository) error {
			changed := testRecord(userID, "r1")
			changed.Version = 1
			_, err := repo.Update(ctx, changed)
			return err
		}},
		{"delete", func(ctx context.Context, repo *RecordsRepository) error {
			_, err := repo.Delete(ctx, userID, "r1", 1)
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := newCleanPool(t)
			seed := recordsWithUsers{RecordsRepository: NewRecordsRepository(pool, slog.Default()), pool: pool}
			require.NoError(t, seed.ensureUser(context.Background(), userID))
			_, err := seed.RecordsRepository.Create(context.Background(), testRecord(userID, "r1"))
			require.NoError(t, err)

			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			err = tt.call(ctx, seed.RecordsRepository)

			require.ErrorIs(t, err, context.Canceled)
			got, revision, err := seed.RecordsRepository.List(context.Background(), userID, 0)
			require.NoError(t, err)
			assert.Equal(t, int64(1), revision)
			require.Len(t, got, 1)
			assert.Equal(t, "r1", got[0].ID)
			assert.False(t, got[0].Deleted)
		})
	}
}

// TestRecordsRepository_UnknownUser — у записей в Postgres обязан быть пользователь (счётчик ревизий в users),
// поэтому Create и List для неизвестного user_id возвращают ErrNotFound и ничего не создают.
// Memory-бэкенд здесь ведёт себя иначе, поэтому случай не входит в общий контрактный набор.
func TestRecordsRepository_UnknownUser(t *testing.T) {
	pool := newCleanPool(t)
	repo := NewRecordsRepository(pool, slog.Default())
	ctx := context.Background()

	t.Run("create", func(t *testing.T) {
		_, err := repo.Create(ctx, testRecord("ghost", "r1"))

		assert.ErrorIs(t, err, domain.ErrNotFound)
		var count int
		require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM records`).Scan(&count))
		assert.Zero(t, count, "запись для неизвестного пользователя не должна появиться")
	})

	t.Run("list", func(t *testing.T) {
		got, revision, err := repo.List(ctx, "ghost", 0)

		assert.ErrorIs(t, err, domain.ErrNotFound)
		assert.Empty(t, got)
		assert.Zero(t, revision)
	})
}

// TestRecordsRepository_Create_ConstraintMapping — только нарушение первичного ключа (повторный id)
// превращается в ErrConflict. Нарушение UNIQUE (user_id, revision) означает рассинхронизацию
// счётчика users.revision с записями; это внутренняя ошибка, а не конфликт клиента, и повторять её бессмысленно.
func TestRecordsRepository_Create_ConstraintMapping(t *testing.T) {
	pool := newCleanPool(t)
	repo := recordsWithUsers{RecordsRepository: NewRecordsRepository(pool, slog.Default()), pool: pool}
	ctx := context.Background()

	_, err := repo.Create(ctx, testRecord("u1", "r1"))
	require.NoError(t, err)

	t.Run("duplicate id is conflict", func(t *testing.T) {
		_, err := repo.Create(ctx, testRecord("u1", "r1"))

		assert.ErrorIs(t, err, domain.ErrConflict)
	})

	t.Run("diverged revision counter is not conflict", func(t *testing.T) {
		// Счётчик откатывается назад: следующая ревизия совпадёт с ревизией уже существующей записи.
		_, err := pool.Exec(ctx, `UPDATE users SET revision = 0 WHERE id = 'u1'`)
		require.NoError(t, err)

		_, err = repo.Create(ctx, testRecord("u1", "r2"))

		require.Error(t, err)
		assert.NotErrorIs(t, err, domain.ErrConflict)
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		assert.Equal(t, "uq_records_user_revision", pgErr.ConstraintName)
	})
}
