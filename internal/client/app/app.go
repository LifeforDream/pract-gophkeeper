// Package app содержит бизнес-логику клиентской части приложения.
package app

import (
	"context"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/cache"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/crypto"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
	"github.com/LifeforDream/pract-gophkeeper/internal/kdfparams"
)

// AuthServer описывает необходимые методы транспорта для аутентификации.
type AuthServer interface {
	GetKDFParams(ctx context.Context, login string) (salt []byte, p kdfparams.Params, err error)
	Register(ctx context.Context, login string, authKey, salt []byte, p kdfparams.Params) (token string, err error)
	Login(ctx context.Context, login string, authKey []byte) (token string, err error)
}

// VaultServer описывает необходимые методы транспорта для работы с хранилищем.
type VaultServer interface {
	Put(ctx context.Context, token, id string, expectedVersion int64, header domain.Header, body crypto.Sealed) (version int64, err error)
	Delete(ctx context.Context, token, id string, expectedVersion int64) error
	Get(ctx context.Context, token, id string) (domain.Record, error)
	ListChanges(ctx context.Context, token string, since int64) (revision int64, recs []domain.Record, err error)
	List(ctx context.Context, token string, filter domain.Filter) (recs []domain.Record, err error)
}

// Cache описывает необходимые методы локального кэша.
type Cache interface {
	LatestRevision() int64
	Entries() []cache.Entry
	Body(id string, version int64) (crypto.Sealed, bool, error)
	Put(e cache.Entry, body *crypto.Sealed) error
	PutBody(id string, version int64, body crypto.Sealed) error
	Remove(id string) error
	Apply(revision int64, recs []domain.Record) error
	Wipe() error
}

// CacheOpener открывает кэш, привязанный к серверу и пользователю.
// Если вместе с ошибкой возвращён не nil Cache, он пригоден к работе, а ошибка - лишь предупреждение
// (например, испорченный индекс был заменён пустым).
type CacheOpener func(serverAddr, userID string) (Cache, error)
