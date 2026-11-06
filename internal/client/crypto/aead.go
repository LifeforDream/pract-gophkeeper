// Package crypto хранит в себе логику шифрования/дешифрования без привязки к транспорту.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// Part привязывает blob к его роли.
type Part string

const (
	// PartHeader - блоб "заголовков".
	PartHeader Part = "header"
	// PartBody - блоб "контента".
	PartBody Part = "body"
)

// Sealed - результат шифрования: nonce и шифртекст (с тегом в конце).
type Sealed struct {
	Nonce      []byte // 12 байт.
	Ciphertext []byte // зашифрованный текст.
}

// Sealer оборачивает шифровальщик.
type Sealer struct {
	aead cipher.AEAD
}

// NewSealer создаёт инстанс шифровальщика, проверяя длину ключа.
func NewSealer(encKey []byte) (*Sealer, error) {
	if len(encKey) != KeySize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidKey, len(encKey))
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return &Sealer{aead: gcm}, nil
}

// Seal шифрует plaintext в Sealed с использованием aead из Sealer.
func (s *Sealer) Seal(userID, recordID string, part Part, plaintext []byte) (Sealed, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Sealed{}, fmt.Errorf("nonce generation: %w", err)
	}
	aad := buildAAD(userID, recordID, part)
	ct := s.aead.Seal(nil, nonce, plaintext, aad)
	return Sealed{Nonce: nonce, Ciphertext: ct}, nil
}

// Open расшифровывает sealed и возвращает исходные данные.
func (s *Sealer) Open(userID, recordID string, part Part, sealed Sealed) ([]byte, error) {
	if len(sealed.Nonce) != s.aead.NonceSize() {
		return nil, ErrDecrypt
	}
	aad := buildAAD(userID, recordID, part)
	plaintext, err := s.aead.Open(nil, sealed.Nonce, sealed.Ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

func buildAAD(userID, recordID string, part Part) []byte {
	var b []byte
	for _, f := range []string{userID, recordID, string(part)} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
		b = append(b, f...)
	}
	return b
}
