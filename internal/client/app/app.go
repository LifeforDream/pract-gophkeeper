// Package app содержит бизнес-логику клиентской части приложения.
package app

import (
	"context"

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
}
