package crypto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"

	"github.com/LifeforDream/pract-gophkeeper/internal/kdfparams"
	"golang.org/x/crypto/argon2"
)

const (
	// KeySize - стандартный размер "ключа".
	KeySize = 32
	// AuthKeyLabel - подпись для ключа, отправляемого на сервер.
	AuthKeyLabel = "gophkeeper/v1/auth"
	// EncodingKeyLabel - подпись для ключа, остающегося на клиенте.
	EncodingKeyLabel = "gophkeeper/v1/enc"
)

// Keys отражает разные части ключа.
type Keys struct {
	Auth [KeySize]byte // отправляется на сервер
	Enc  [KeySize]byte // остаётся на клиенте
}

// DeriveKeys создаёт из password два ключа:
//
// - AuthKey - для обмена с сервером.
//
// - EncodingKey - для шифрования/расшифрования на клиенте.
//
// Для генерации ключей использует salt и p Params.
func DeriveKeys(password, salt []byte, p kdfparams.Params) (Keys, error) {
	keys := Keys{}
	if err := p.Validate(); err != nil {
		return keys, fmt.Errorf("derive keys validation error: %w", err)
	}
	if len(salt) < kdfparams.SaltSize {
		return keys, fmt.Errorf("salt size %d is smaller than allowed: %w", len(salt), ErrInvalidSalt)
	}

	master := argon2.IDKey(password, salt, p.Iterations, p.MemoryKiB, p.Parallelism, KeySize)

	authKey, err := hkdf.Expand(sha256.New, master, AuthKeyLabel, KeySize)
	if err != nil {
		return keys, fmt.Errorf("error creating auth key: %w", err)
	}
	copy(keys.Auth[:], authKey)

	encKey, err := hkdf.Expand(sha256.New, master, EncodingKeyLabel, KeySize)
	if err != nil {
		return keys, fmt.Errorf("error creating encoding key: %w", err)
	}
	copy(keys.Enc[:], encKey)

	// очистим в памяти на всякий случай
	clear(master)
	clear(authKey)
	clear(encKey)

	return keys, nil
}
