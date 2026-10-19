// Package main является входной точкой для старта сервера GophKeeper.
package main

import (
	"log"
	"os"

	"github.com/LifeforDream/pract-gophkeeper/internal/buildinfo"
	"github.com/LifeforDream/pract-gophkeeper/internal/logging"
)

var (
	buildVersion = "N/A"
	buildDate    = "N/A"
)

func main() {
	buildinfo.Print(os.Stdout, buildVersion, buildDate)

	serverOptions, err := parseOptions(os.Args[1:])
	if err != nil {
		log.Fatalf("error parsing options: %v", err)
	}

	logger, err := logging.Initialize(serverOptions.LogLevel)
	if err != nil {
		log.Fatalf("error configuring logger: %v", err)
	}
	logger.Info("hey")
}
