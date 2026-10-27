// Package kdfparams содержит общую логику для работы с параметрами шифрования, используемую на сервере и клиенте.
package kdfparams

import (
	"crypto/rand"
	"errors"
	"fmt"
)

const (
	// SaltSize - стандартный размер "соли".
	SaltSize = 16
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
)

// ErrInvalidParams выбрасывается Validate() в случае, когда параметры некорректны.
var ErrInvalidParams = errors.New("crypto: invalid KDF params")

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
