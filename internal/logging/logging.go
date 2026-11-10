// Package logging хранит функции, помогающие эффективно логировать.
package logging

import (
	"fmt"
	"log/slog"
	"os"
)

// parseLevel преобразует строку вида "debug", "INFO" и т.д. в уровень логирования.
func parseLevel(levelStr string) (slog.Level, error) {
	var level slog.Level
	err := level.UnmarshalText([]byte(levelStr))
	return level, err
}

// Initialize создаёт логгер на основании уровня логирования и возвращает его.
func Initialize(levelStr string) (*slog.Logger, error) {
	logLevel, err := parseLevel(levelStr)

	if err != nil {
		return slog.Default(), fmt.Errorf("error while configuring logging: %w", err)
	}

	logOpts := &slog.HandlerOptions{
		Level: logLevel,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, logOpts))
	return logger, nil
}
