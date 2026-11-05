// Package app содержит логику настройки и запуска приложения.
package app

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/LifeforDream/pract-gophkeeper/internal/server/handler/grpcsrv"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/jwtauth"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/repository/dbrepo"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/repository/memory"
	authcase "github.com/LifeforDream/pract-gophkeeper/internal/server/usecase/auth"
	vaultcase "github.com/LifeforDream/pract-gophkeeper/internal/server/usecase/vault"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// cryptoGenLen - длины секретных ключей по-умолчанию.
const cryptoGenLen = 32

// shutdownTimeout - время, выделяемое на gracefulShutdown.
const shutdownTimeout = 15 * time.Second

// Config хранит настройки для приложения.
type Config struct {
	RunAddr        string // адрес для запуска сервера
	DatabaseDsn    string // строка подключения к БД
	SkipMigrate    bool   // флаг для пропуска миграций при старте
	TLSCertPath    string // путь к файлу сертификата
	TLSKeyPath     string // путь к файлу ключа
	JWTSecret      string // секрет для токена
	JWTTTL         int    // срок жизни JWT в минутах
	FakeSaltSecret string // фейковая "соль" для несуществующего секрета
}

// repoSet - репозитории, с которыми работают use case-ы, и функция освобождения их общих ресурсов.
type repoSet struct {
	auth  authcase.Repo  // репозиторий пользователей
	vault vaultcase.Repo // репозиторий записей
	close func()         // освобождает общие ресурсы (например, пул соединений); вызывается один раз
}

// reposFactory создаёт репозитории для выбранного бэкенда.
type reposFactory func(context.Context, Config, *slog.Logger) (*repoSet, error)

// runOptions - внутренние параметры запуска, которые подменяются в тестах.
type runOptions struct {
	shutdownTimeout time.Duration // предел ожидания GracefulStop до принудительной остановки
	newRepos        reposFactory
}

// newMemoryRepos создаёт репозитории в памяти.
func newMemoryRepos(_ context.Context, _ Config, _ *slog.Logger) (*repoSet, error) {
	return &repoSet{auth: memory.NewUsersRepo(), vault: memory.NewRecordsRepo(), close: func() {}}, nil
}

// newDbRepos создаёт репозитории PostgreSQL, применяя миграции, если они не отключены.
// Пул соединений общий для обоих репозиториев и закрывается через repoSet.close.
func newDbRepos(ctx context.Context, c Config, logger *slog.Logger) (*repoSet, error) {
	if !c.SkipMigrate {
		if err := dbrepo.Migrate(ctx, c.DatabaseDsn, logger); err != nil {
			return nil, fmt.Errorf("error performing migrations: %w", err)
		}
	}

	pool, err := dbrepo.NewPool(ctx, c.DatabaseDsn)
	if err != nil {
		return nil, fmt.Errorf("error connecting to db: %w", err)
	}

	return &repoSet{
		auth:  dbrepo.NewUsersRepository(pool),
		vault: dbrepo.NewRecordsRepository(pool, logger),
		close: pool.Close,
	}, nil
}

// Run пытается запустить сервер.
func Run(ctx context.Context, c Config, logger *slog.Logger) error {
	var newRepos reposFactory
	if c.DatabaseDsn != "" {
		newRepos = newDbRepos
	} else {
		newRepos = newMemoryRepos
	}
	return run(ctx, c, logger, runOptions{shutdownTimeout: shutdownTimeout, newRepos: newRepos})
}

// run - реализация Run с настраиваемыми параметрами запуска.
func run(ctx context.Context, c Config, logger *slog.Logger, opts runOptions) error {
	if (c.TLSKeyPath == "" && c.TLSCertPath != "") ||
		(c.TLSKeyPath != "" && c.TLSCertPath == "") {
		return fmt.Errorf("incomplete certificate config key: %s, cert: %s", c.TLSKeyPath, c.TLSCertPath)
	}

	jwtSecret, fakeSaltSecret, err := loadSecrets(c)
	if err != nil {
		return fmt.Errorf("error loading secrets: %w", err)
	}

	rh, err := opts.newRepos(ctx, c, logger)

	if err != nil {
		return fmt.Errorf("error creating repos: %w", err)
	}

	defer rh.close()

	jwtsvc, err := jwtauth.NewJWTService(jwtSecret, time.Duration(c.JWTTTL)*time.Minute)
	if err != nil {
		return fmt.Errorf("failed to initialize jwt service: %w", err)
	}

	authSvc := authcase.NewService(rh.auth, jwtsvc, fakeSaltSecret)
	vaultSvc, err := vaultcase.NewService(
		rh.vault,
		vaultcase.DefaultHeaderSizeLimit(),
		vaultcase.DefaultBodySizeLimit(),
	)
	if err != nil {
		return fmt.Errorf("error initializing vault service: %w", err)
	}

	creds, err := buildCreds(c)
	if err != nil {
		return fmt.Errorf("error building tls creds: %w", err)
	}

	lis, err := net.Listen("tcp", c.RunAddr)
	if err != nil {
		return fmt.Errorf("error listening gRPC address %s: %w", c.RunAddr, err)
	}

	grpcSrv := grpcsrv.New(authSvc, vaultSvc, jwtsvc, logger, creds)

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("running gRPC server", "address", c.RunAddr)
		serveErr <- grpcSrv.Serve(lis) // и nil тоже отправляем
	}()

	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if err != nil {
			return fmt.Errorf("failed to start application %w", err)
		}
		return nil
	}

	grpcSrv.Shutdown()

	stopped := make(chan struct{})
	go func() {
		logger.Info("starting graceful shutdown")
		grpcSrv.GracefulStop()
		close(stopped)
	}()

	timer := time.NewTimer(opts.shutdownTimeout)
	defer timer.Stop()

	select {
	case <-stopped:
	case <-timer.C:
		logger.Warn("graceful shutdown timed out, forcing stop")
		grpcSrv.Stop()
		// всё равно нужно дождаться закрытия обработчиков
		<-stopped
	}

	if err := <-serveErr; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("grpc serve: %w", err)
	}
	return nil
}

func loadSecrets(c Config) ([]byte, []byte, error) {
	var jwtSecret []byte
	var fakeSaltSecret []byte
	if c.JWTSecret == "" {
		if c.DatabaseDsn != "" {
			return nil, nil, fmt.Errorf("jwt secret is required for database deployments")
		}
		jwtSecret = make([]byte, cryptoGenLen)
		_, err := rand.Read(jwtSecret)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating fake jwt secret: %w", err)
		}
	} else {
		jwtSecret = []byte(c.JWTSecret)
	}

	if c.FakeSaltSecret == "" {
		if c.DatabaseDsn != "" {
			return nil, nil, fmt.Errorf("fake salt secret is required for database deployments")
		}
		fakeSaltSecret = make([]byte, cryptoGenLen)
		_, err := rand.Read(fakeSaltSecret)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating fake salt secret: %w", err)
		}
	} else {
		fakeSaltSecret = []byte(c.FakeSaltSecret)
	}
	return jwtSecret, fakeSaltSecret, nil
}

func buildCreds(c Config) (credentials.TransportCredentials, error) {
	var creds credentials.TransportCredentials
	if c.TLSKeyPath != "" && c.TLSCertPath != "" {
		cert, err := tls.LoadX509KeyPair(c.TLSCertPath, c.TLSKeyPath)
		if err != nil {
			return nil, fmt.Errorf("error loading certificate for gRPC: %w", err)
		}
		creds = credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		})
	}
	return creds, nil
}
