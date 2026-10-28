// Package app содержит логику настройки и запуска приложения.
package app

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/LifeforDream/pract-gophkeeper/internal/server/handler/grpcsrv"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/jwtauth"
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

// authRepo - репозиторий пользователей, который app умеет не только отдавать use case-у, но и закрывать.
type authRepo interface {
	authcase.Repo
	io.Closer
}

// vaultRepo - репозиторий записей, который app умеет не только отдавать use case-у, но и закрывать.
type vaultRepo interface {
	vaultcase.Repo
	io.Closer
}

// runOptions - внутренние параметры запуска, которые подменяются в тестах.
type runOptions struct {
	shutdownTimeout time.Duration                // предел ожидания GracefulStop до принудительной остановки
	newRepos        func() (authRepo, vaultRepo) // фабрика репозиториев memory-режима
}

// newMemoryRepos создаёт репозитории в памяти.
func newMemoryRepos() (authRepo, vaultRepo) {
	return memory.NewUsersRepo(), memory.NewRecordsRepo()
}

// Run пытается запустить сервер.
func Run(ctx context.Context, c Config, logger *slog.Logger) error {
	return run(ctx, c, logger, runOptions{shutdownTimeout: shutdownTimeout, newRepos: newMemoryRepos})
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

	if c.DatabaseDsn != "" {
		return fmt.Errorf("database not implemented yet")
	}
	authRepo, vaultRepo := opts.newRepos()

	defer func() {
		_ = authRepo.Close()
		_ = vaultRepo.Close()
	}()

	jwtsvc, err := jwtauth.NewJWTService(jwtSecret, time.Duration(c.JWTTTL)*time.Minute)
	if err != nil {
		return fmt.Errorf("failed to initialize jwt service: %w", err)
	}

	authSvc := authcase.NewService(authRepo, jwtsvc, fakeSaltSecret)
	vaultSvc, err := vaultcase.NewService(
		vaultRepo,
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
