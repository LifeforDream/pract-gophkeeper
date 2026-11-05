// Package migrations хранит миграции для базы данных.
package migrations

import "embed"

// FS - хранилище миграций для бинарника.
//
//go:embed *.sql
var FS embed.FS
