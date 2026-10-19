package main

import (
	"flag"

	"github.com/LifeforDream/pract-gophkeeper/internal/config"
)

type clientOptions struct {
	ServerAddress string `env:"ADDRESS"`      // адрес сервера для подключения
	LogLevel      string `env:"LOG_LEVEL"`    // уровень логирования
	CaCert        string `env:"CA_CERT"`      // путь к файлу с сертификатом
	SessionFile   string `env:"SESSION_FILE"` // путь к файлу для хранения данных сессии
}

func parseOptions(args []string) (*clientOptions, error) {
	var clientOpt clientOptions

	fs := flag.NewFlagSet("client", flag.ContinueOnError)

	fs.StringVar(&clientOpt.ServerAddress, "a", "localhost:50001", "address and port to run grpc server")
	fs.StringVar(&clientOpt.LogLevel, "l", "info", "log level")
	fs.StringVar(&clientOpt.CaCert, "cert", "", "filepath for CA cert")
	fs.StringVar(&clientOpt.SessionFile, "file", "", "path to a file to hold session data")

	if err := config.Parse(fs, args, &clientOpt); err != nil {
		return nil, err
	}

	return &clientOpt, nil
}
