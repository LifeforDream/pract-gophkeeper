// Package main является входной точкой для старта клиента GophKeeper.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/LifeforDream/pract-gophkeeper/internal/buildinfo"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/app"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/cache"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/cli"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/session"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/transport"
	"github.com/LifeforDream/pract-gophkeeper/internal/logging"
)

var (
	buildVersion = "N/A"
	buildDate    = "N/A"
)

func main() {
	buildinfo.Print(os.Stdout, buildVersion, buildDate)

	os.Exit(run())
}

func run() int {
	clientOptions, comArgs, err := parseOptions(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	logger, err := logging.Initialize(clientOptions.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error configuring logger: %v\n", err)
		return 2
	}
	srv, err := transport.NewClient(clientOptions.ServerAddress, clientOptions.CaCert, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error configuring gRPC client: %v\n", err)
		return 1
	}
	sess, err := session.NewFileStore(clientOptions.SessionFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating session file: %v\n", err)
		return 1
	}

	cacheDir := sess.Dir()
	openCache := func(serverAddr, userID string) (app.Cache, error) {
		c, err := cache.Open(cacheDir, serverAddr, userID)
		if c == nil {
			return nil, err
		}
		return c, err
	}
	cacheWiper := func() error { return cache.RemoveAll(cacheDir) }
	auth := app.NewAuth(srv, sess, clientOptions.ServerAddress, cacheWiper)
	vault, err := app.NewVault(srv, sess, openCache, clientOptions.ServerAddress, app.DefaultBodySizeLimit())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error configuring vault service: %v\n", err)
		return 1
	}
	client := cli.New(auth, vault, cli.NewStdTerminal(), cli.WithGlobalOptionsHelp(printGlobalOptions))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return client.Run(ctx, comArgs)
}
