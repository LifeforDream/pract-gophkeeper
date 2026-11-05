//go:build integration

package app

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/LifeforDream/pract-gophkeeper/api/gophkeeper/v1"
	"github.com/LifeforDream/pract-gophkeeper/internal/kdfparams"
)

// startPostgres поднимает контейнер Postgres на время теста и возвращает DSN к пустой базе.
func startPostgres(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	ctr, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("gophkeeper"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
		tcpostgres.BasicWaitStrategies(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, testcontainers.TerminateContainer(ctr)) })

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	return dsn
}

// TestRun_Postgres — проводка Run → newDbRepos → Postgres: флаг --skip-migrate, применение миграций
// и то, что данные переживают перезапуск сервера (в отличие от memory-бэкенда).
//
// Подтесты зависят друг от друга по порядку: первый работает с ещё не мигрированной базой.
func TestRun_Postgres(t *testing.T) {
	dsn := startPostgres(t)

	t.Run("skip-migrate leaves the schema absent", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
		defer cancel()

		repos, err := newDbRepos(ctx, Config{DatabaseDsn: dsn, SkipMigrate: true}, discardLogger())
		require.NoError(t, err, "подключение к пустой базе должно удаться")
		defer repos.close()

		_, err = repos.auth.GetUserByLogin(ctx, "alice")
		assert.ErrorContains(t, err, "users", "без миграций таблицы users нет")
	})

	cfg := memoryConfig("")
	cfg.DatabaseDsn = dsn
	register := func(t *testing.T, addr string) {
		t.Helper()
		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
		defer cancel()

		_, err = pb.NewAuthServiceClient(conn).Register(ctx, pb.RegisterRequest_builder{
			Login:   "alice",
			AuthKey: []byte("auth-key"),
			Salt:    []byte("0123456789abcdef"),
			Params:  pb.Argon2Params_builder{MemoryKib: kdfparams.MemoryLowerLimitKiB, Iterations: 1, Parallelism: 1}.Build(),
		}.Build())
		require.NoError(t, err)
	}
	kdfSalt := func(t *testing.T, addr string) []byte {
		t.Helper()
		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
		defer cancel()

		resp, err := pb.NewAuthServiceClient(conn).GetKDFParams(ctx, pb.GetKDFParamsRequest_builder{Login: "alice"}.Build())
		require.NoError(t, err)
		return resp.GetSalt()
	}

	t.Run("migrates on start and keeps data across restarts", func(t *testing.T) {
		first := cfg
		first.RunAddr = freeAddr(t)
		r := startRun(t, first)
		waitListening(t, first.RunAddr, r)
		register(t, first.RunAddr)
		require.NoError(t, shutdown(t, r))

		// Второй запуск пропускает миграции: схема уже есть, а пользователь должен найтись в БД.
		second := cfg
		second.SkipMigrate = true
		second.RunAddr = freeAddr(t)
		r = startRun(t, second)
		waitListening(t, second.RunAddr, r)
		assert.Equal(t, []byte("0123456789abcdef"), kdfSalt(t, second.RunAddr),
			"вернулась настоящая соль, а не фейковая: пользователь сохранился в Postgres")
		require.NoError(t, shutdown(t, r))
	})

	t.Run("close releases the pool and is idempotent", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
		defer cancel()

		repos, err := newDbRepos(ctx, Config{DatabaseDsn: dsn, SkipMigrate: true}, discardLogger())
		require.NoError(t, err)
		_, err = repos.auth.GetUserByLogin(ctx, "alice")
		require.NoError(t, err, "до close репозитории работают")

		repos.close()

		_, err = repos.auth.GetUserByLogin(ctx, "alice")
		assert.Error(t, err, "после close пул закрыт и обращения к БД невозможны")
		assert.NotPanics(t, repos.close, "повторный close безопасен")
	})
}
