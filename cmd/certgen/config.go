package main

import (
	"flag"
	"os"

	"github.com/caarlos0/env/v11"
)

// CertgenOptions хранит настройки для утилиты certgen
type CertgenOptions struct {
	OutDir string `env:"OUT_DIR"` // директория для сохранения файлов
}

func parseOptions(args ...string) (*CertgenOptions, error) {
	var certgenOptions CertgenOptions
	fs := flag.NewFlagSet("certgen", flag.ContinueOnError)

	fs.StringVar(&certgenOptions.OutDir, "o", "", "directory to save files to")

	if args == nil {
		args = os.Args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	err := env.Parse(&certgenOptions)
	if err != nil {
		return nil, err
	}

	if certgenOptions.OutDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		certgenOptions.OutDir = cwd
	}
	return &certgenOptions, nil
}
