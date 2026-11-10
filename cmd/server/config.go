package main

import (
	"flag"

	"github.com/LifeforDream/pract-gophkeeper/internal/config"
)

type serverOptions struct {
	RunAddr        string `env:"ADDRESS"`         // адрес для запуска сервера
	LogLevel       string `env:"LOG_LEVEL"`       // уровень логирования
	DatabaseDsn    string `env:"DATABASE_DSN"`    // строка подключения к БД
	SkipMigrate    bool   `env:"SKIP_MIGRATIONS"` // флаг для пропуска миграций при старте
	TLSCertPath    string `env:"TLS_CERT"`        // путь к файлу сертификата
	TLSKeyPath     string `env:"TLS_KEY"`         // путь к файлу ключа
	JWTSecret      string `env:"JWT_SECRET"`      // секрет для токена
	JWTTTL         int    `env:"JWT_TTL"`         // срок жизни JWT в минутах
	FakeSaltSecret string `env:"FAKE_SALT"`       // фейковая "соль" для несуществующего секрета
}

func parseOptions(args []string) (*serverOptions, error) {
	var srvOpt serverOptions

	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.StringVar(&srvOpt.RunAddr, "a", "localhost:50001", "address and port to run grpc server")
	fs.StringVar(&srvOpt.LogLevel, "l", "info", "log level")
	fs.StringVar(&srvOpt.DatabaseDsn, "d", "", "connection string for database; if empty, memory is used. Prefer env")
	fs.BoolVar(&srvOpt.SkipMigrate, "skip-migrate", false, "pass skip-migrate to not check migrations on startup")
	fs.StringVar(&srvOpt.TLSCertPath, "tls-cert", "", "filepath to a TLS certificate for gRPC server")
	fs.StringVar(&srvOpt.TLSKeyPath, "tls-key", "", "filepath to a private key for gRPC server")
	fs.StringVar(&srvOpt.JWTSecret, "s", "", "secret for JWT encoding. Please prefer env.")
	fs.IntVar(&srvOpt.JWTTTL, "t", 24*60, "number of minutes for JWT to live")
	fs.StringVar(&srvOpt.FakeSaltSecret, "f", "", "fake salt secret for missing secrets")

	if err := config.Parse(fs, args, &srvOpt); err != nil {
		return nil, err
	}

	return &srvOpt, nil
}
