package crypto

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	// SaltSize - стандартный размер "соли".
	SaltSize = 16
	// KeySize - стандартный размер "ключа".
	KeySize = 32
	// MemoryUpperLimitKib - верхний предел по памяти для ключа.
	// Нужен, чтобы с сервера нельзя было вызвать OOM на клиенте.
	MemoryUpperLimitKib = 1 * 1024 * 1024
	// MemoryLowerLimitKiB - нижний предел памяти. Нужен для минимальных гарантий безопасности.
	MemoryLowerLimitKiB = 1 * 1024
	// IterationsUpperLimit - верхний предел количества итераций для argon.
	IterationsUpperLimit = 100
	// IterationsLowerLimit - нижний предел количества итераций для argon. На 0 будет паника.
	IterationsLowerLimit = 1
	// ParallelismUpperLimit верхний предел количества тредов для argon.
	ParallelismUpperLimit = 200
	// ParallelismLowerLimit - нижний предел количества тредов для argon. На 0 будет паника.
	ParallelismLowerLimit = 1
	// AuthKeyLabel - подпись для ключа, отправляемого на сервер.
	AuthKeyLabel = "gophkeeper/v1/auth"
	// EncodingKeyLabel - подпись для ключа, остающегося на клиенте.
	EncodingKeyLabel = "gophkeeper/v1/enc"
)

// Params — параметры для Argon2Id.
type Params struct {
	MemoryKiB   uint32 // ограничение по памяти.
	Iterations  uint32 // количество итераций генерации.
	Parallelism uint8  // количество задействованных тредов.
}

// DefaultParams хранит стандартные параметры.
func DefaultParams() Params {
	return Params{
		MemoryKiB:   64 * 1024,
		Iterations:  3,
		Parallelism: 4,
	}
}

// Validate проверяет параметры на разумные пределы.
// Эти пределы подобраны "по ощущениям".
func (p Params) Validate() error {
	if p.MemoryKiB > MemoryUpperLimitKib || p.MemoryKiB < MemoryLowerLimitKiB {
		return fmt.Errorf("invalid memory limit: %w", ErrInvalidParams)
	}
	if p.Iterations < IterationsLowerLimit || p.Iterations > IterationsUpperLimit {
		return fmt.Errorf("invalid iterations %d: %w", p.Iterations, ErrInvalidParams)
	}
	if p.Parallelism < ParallelismLowerLimit || p.Parallelism > ParallelismUpperLimit {
		return fmt.Errorf("invalid parallelism %d: %w", p.Parallelism, ErrInvalidParams)
	}
	return nil
}

// NewSalt создаёт новую "соль" для паролей.
func NewSalt() ([]byte, error) {
	b := make([]byte, SaltSize)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("error creating salt: %w", err)
	}
	return b, nil
}

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
func DeriveKeys(password, salt []byte, p Params) (Keys, error) {
	keys := Keys{}
	if err := p.Validate(); err != nil {
		return keys, fmt.Errorf("derive keys validation error: %w", err)
	}
	if len(salt) < SaltSize {
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
