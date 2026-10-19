// Package config содержит общую логику разбора конфигурации: флаги, затем переменные окружения.
package config

import (
	"flag"
	"fmt"

	"github.com/caarlos0/env/v11"
)

// Parse разбирает args через fs, затем применяет переменные окружения поверх значений флагов.
// dst должен быть указателем на структуру, к полям которой привязаны флаги fs.
func Parse(fs *flag.FlagSet, args []string, dst any) error {
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parsing args: %w", err)
	}
	if err := env.Parse(dst); err != nil {
		return fmt.Errorf("reading env: %w", err)
	}
	return nil
}
