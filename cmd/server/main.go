// Package main является входной точкой для старта сервера GophKeeper.
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/LifeforDream/pract-gophkeeper/internal/buildinfo"
	"github.com/LifeforDream/pract-gophkeeper/internal/logging"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/app"
)

var (
	buildVersion = "N/A"
	buildDate    = "N/A"
)

func main() {
	buildinfo.Print(os.Stdout, buildVersion, buildDate)

	so, err := parseOptions(os.Args[1:])
	if err != nil {
		log.Fatalf("error parsing options: %v", err)
	}

	logger, err := logging.Initialize(so.LogLevel)
	if err != nil {
		log.Fatalf("error configuring logger: %v", err)
	}

	if err = run(so, logger); err != nil {
		log.Fatalf("main: %v", err)
	}
}

func run(so *serverOptions, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	c := app.Config{
		RunAddr:        so.RunAddr,
		DatabaseDsn:    so.DatabaseDsn,
		SkipMigrate:    so.SkipMigrate,
		TLSCertPath:    so.TLSCertPath,
		TLSKeyPath:     so.TLSKeyPath,
		JWTSecret:      so.JWTSecret,
		JWTTTL:         so.JWTTTL,
		FakeSaltSecret: so.FakeSaltSecret,
	}
	if err := app.Run(ctx, c, logger); err != nil {
		return fmt.Errorf("error starting application: %w", err)
	}
	return nil
}
