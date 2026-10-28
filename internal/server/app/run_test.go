package app

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	pb "github.com/LifeforDream/pract-gophkeeper/api/gophkeeper/v1"
	"github.com/LifeforDream/pract-gophkeeper/internal/auth"
	"github.com/LifeforDream/pract-gophkeeper/internal/kdfparams"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/domain"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/repository/memory"
)

// spyAuthRepo считает вызовы Close у репозитория пользователей.
type spyAuthRepo struct {
	*memory.UsersRepo
	closed atomic.Int32
}

func (r *spyAuthRepo) Close() error {
	r.closed.Add(1)
	return r.UsersRepo.Close()
}

// spyVaultRepo считает вызовы Close у репозитория записей, а List может блокировать до release.
type spyVaultRepo struct {
	*memory.RecordsRepo
	closed  atomic.Int32
	entered chan struct{} // закрывается при первом входе в List; nil — не блокировать
	release chan struct{} // List ждёт закрытия канала
	once    sync.Once
}

func (r *spyVaultRepo) Close() error {
	r.closed.Add(1)
	return r.RecordsRepo.Close()
}

func (r *spyVaultRepo) List(ctx context.Context, userID string, since int64) ([]domain.Record, int64, error) {
	if r.entered != nil {
		r.once.Do(func() { close(r.entered) })
		// Как и настоящий драйвер БД, уважает отмену контекста: Stop рвёт соединение и отменяет контекст запроса.
		select {
		case <-r.release:
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		}
	}
	return r.RecordsRepo.List(ctx, userID, since)
}

// spyRepos — фабрика репозиториев, запоминающая, сколько раз её вызвали и что она вернула.
type spyRepos struct {
	calls atomic.Int32
	auth  *spyAuthRepo
	vault *spyVaultRepo
}

func newSpyRepos() *spyRepos {
	return &spyRepos{
		auth:  &spyAuthRepo{UsersRepo: memory.NewUsersRepo()},
		vault: &spyVaultRepo{RecordsRepo: memory.NewRecordsRepo()},
	}
}

func (s *spyRepos) new() (authRepo, vaultRepo) {
	s.calls.Add(1)
	return s.auth, s.vault
}

func (s *spyRepos) options(timeout time.Duration) runOptions {
	return runOptions{shutdownTimeout: timeout, newRepos: s.new}
}

// syncBuffer — потокобезопасный буфер для логов, в который пишут несколько горутин.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startRunWith запускает run в горутине; контекст отменяется в t.Cleanup, чтобы не утекла горутина.
func startRunWith(t *testing.T, cfg Config, logger *slog.Logger, opts runOptions) *runResult {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r := &runResult{done: make(chan error, 1), cancel: cancel}
	go func() { r.done <- run(ctx, cfg, logger, opts) }()
	return r
}

// runToError вызывает run синхронно: все проверяемые здесь ошибки возвращаются до запуска сервера.
func runToError(t *testing.T, cfg Config, opts runOptions) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	defer cancel()
	err := run(ctx, cfg, discardLogger(), opts)
	require.Error(t, err)
	return err
}

// TestRun_DatabaseSecretsRequired — при заданном DSN отсутствие секрета даёт именно ошибку про этот секрет,
// а не какую-то другую ошибку старта (например, "database not implemented yet").
func TestRun_DatabaseSecretsRequired(t *testing.T) {
	const dsn = "postgres://u:p@127.0.0.1:1/db"

	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"without any secret", Config{DatabaseDsn: dsn, JWTTTL: 60}, "jwt secret is required"},
		{"without jwt secret", Config{DatabaseDsn: dsn, JWTTTL: 60, FakeSaltSecret: "salt"}, "jwt secret is required"},
		{"without fake salt secret", Config{DatabaseDsn: dsn, JWTTTL: 60, JWTSecret: "jwt"}, "fake salt secret is required"},
		// Контроль: с обоими секретами проверка секретов пройдена, и ошибка уже другая.
		{"with both secrets", Config{DatabaseDsn: dsn, JWTTTL: 60, JWTSecret: "jwt", FakeSaltSecret: "salt"}, "database not implemented"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repos := newSpyRepos()
			tt.cfg.RunAddr = freeAddr(t)

			err := runToError(t, tt.cfg, repos.options(time.Second))

			assert.ErrorContains(t, err, tt.wantErr)
			assert.Zero(t, repos.calls.Load(), "репозитории не должны создаваться до проверки секретов")
		})
	}
}

// TestRun_ClosesReposOnShutdown — при штатной остановке оба репозитория закрываются ровно один раз.
func TestRun_ClosesReposOnShutdown(t *testing.T) {
	repos := newSpyRepos()
	cfg := memoryConfig(freeAddr(t))

	r := startRunWith(t, cfg, discardLogger(), repos.options(time.Second))
	waitListening(t, cfg.RunAddr, r)
	assert.Zero(t, repos.auth.closed.Load(), "пока сервер работает, репозитории открыты")
	assert.Zero(t, repos.vault.closed.Load(), "пока сервер работает, репозитории открыты")

	require.NoError(t, shutdown(t, r))

	assert.Equal(t, int32(1), repos.auth.closed.Load())
	assert.Equal(t, int32(1), repos.vault.closed.Load())
}

// TestRun_ClosesReposOnEarlyReturn — ошибка на любом шаге после создания репозиториев не оставляет их открытыми.
func TestRun_ClosesReposOnEarlyReturn(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer busy.Close()

	tests := []struct {
		name    string
		cfg     func(t *testing.T) Config
		wantErr string
	}{
		{"jwt service", func(t *testing.T) Config {
			cfg := memoryConfig(freeAddr(t))
			cfg.JWTTTL = 0
			return cfg
		}, "failed to initialize jwt service"},
		{"tls credentials", func(t *testing.T) Config {
			cfg := memoryConfig(freeAddr(t))
			cfg.TLSCertPath = filepath.Join(t.TempDir(), "missing-cert.pem")
			cfg.TLSKeyPath = filepath.Join(t.TempDir(), "missing-key.pem")
			return cfg
		}, "error building tls creds"},
		{"listen", func(*testing.T) Config { return memoryConfig(busy.Addr().String()) }, "error listening gRPC address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repos := newSpyRepos()

			err := runToError(t, tt.cfg(t), repos.options(time.Second))

			assert.ErrorContains(t, err, tt.wantErr)
			assert.Equal(t, int32(1), repos.calls.Load(), "репозитории должны были быть созданы")
			assert.Equal(t, int32(1), repos.auth.closed.Load(), "репозиторий пользователей не закрыт")
			assert.Equal(t, int32(1), repos.vault.closed.Load(), "репозиторий записей не закрыт")
		})
	}
}

// TestRun_ForcedStopAfterShutdownTimeout — запрос, не уложившийся в таймаут, прерывается через Stop,
// Run возвращается без ожидания обработчика, а репозитории всё равно закрываются.
func TestRun_ForcedStopAfterShutdownTimeout(t *testing.T) {
	repos := newSpyRepos()
	repos.vault.entered = make(chan struct{})
	repos.vault.release = make(chan struct{})
	// Обработчик, заблокированный в репозитории, отпускается при любом исходе теста.
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(repos.vault.release) }) }
	t.Cleanup(release)

	cfg := memoryConfig(freeAddr(t))
	logs := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))

	r := startRunWith(t, cfg, logger, repos.options(100*time.Millisecond))
	waitListening(t, cfg.RunAddr, r)

	conn, err := grpc.NewClient(cfg.RunAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	defer cancel()

	salt := make([]byte, kdfparams.SaltSize)
	reg, err := pb.NewAuthServiceClient(conn).Register(ctx, pb.RegisterRequest_builder{
		Login:   "alice",
		AuthKey: []byte("auth-key"),
		Salt:    salt,
		Params:  pb.Argon2Params_builder{MemoryKib: kdfparams.MemoryLowerLimitKiB, Iterations: 1, Parallelism: 1}.Build(),
	}.Build())
	require.NoError(t, err)

	// Запрос, который зависнет в репозитории.
	rpcErr := make(chan error, 1)
	go func() {
		callCtx := metadata.AppendToOutgoingContext(ctx, auth.TokenKey, reg.GetToken())
		_, err := pb.NewVaultServiceClient(conn).ListChanges(callCtx, pb.ListChangesRequest_builder{}.Build())
		rpcErr <- err
	}()
	select {
	case <-repos.vault.entered:
	case <-time.After(waitTimeout):
		t.Fatal("запрос не дошёл до репозитория")
	}

	start := time.Now()
	r.cancel()
	select {
	case err := <-r.done:
		require.NoError(t, err)
	case <-time.After(waitTimeout):
		t.Fatal("Run не вернулся: принудительная остановка не сработала")
	}
	assert.Less(t, time.Since(start), waitTimeout, "Run должен вернуться вскоре после таймаута")

	assert.Contains(t, logs.String(), "graceful shutdown timed out, forcing stop")
	assert.Equal(t, int32(1), repos.auth.closed.Load())
	assert.Equal(t, int32(1), repos.vault.closed.Load())

	select {
	case err := <-rpcErr:
		require.Error(t, err, "прерванный запрос не может завершиться успехом")
	case <-time.After(waitTimeout):
		t.Fatal("клиент не узнал об обрыве запроса")
	}
	release()
}
