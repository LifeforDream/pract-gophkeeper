package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/cli"
	"github.com/LifeforDream/pract-gophkeeper/internal/config"
)

type clientOptions struct {
	ServerAddress string `env:"ADDRESS"`      // адрес сервера для подключения
	LogLevel      string `env:"LOG_LEVEL"`    // уровень логирования
	CaCert        string `env:"CA_CERT"`      // путь к файлу с сертификатом
	SessionFile   string `env:"SESSION_FILE"` // путь к файлу для хранения данных сессии
}

func parseOptions(args []string) (*clientOptions, []string, error) {
	var clientOpt clientOptions

	fs := newFlagSet(&clientOpt)

	fs.Usage = func() {
		cli.PrintUsage(fs.Output())
		printGlobalOptions(fs.Output())
	}
	if err := config.Parse(fs, args, &clientOpt); err != nil {
		return nil, nil, err
	}

	return &clientOpt, fs.Args(), nil
}

// newFlagSet регистрирует глобальные флаги клиента в dst.
func newFlagSet(dst *clientOptions) *flag.FlagSet {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	fs.StringVar(&dst.ServerAddress, "a", "localhost:50001", "address and port to run grpc server")
	fs.StringVar(&dst.LogLevel, "l", "info", "log level")
	fs.StringVar(&dst.CaCert, "cert", "", "filepath for CA cert")
	fs.StringVar(&dst.SessionFile, "session", "", "path to a file to hold session data")
	return fs
}

// printGlobalOptions печатает описание глобальных флагов в w.
func printGlobalOptions(w io.Writer) {
	fs := newFlagSet(&clientOptions{})
	fs.SetOutput(w)
	fmt.Fprint(w, "\nGlobal options:\n")
	fs.PrintDefaults()
}
