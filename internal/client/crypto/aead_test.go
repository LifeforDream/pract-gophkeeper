package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testKey = bytes.Repeat([]byte{0x01}, KeySize)
var otherKey = bytes.Repeat([]byte{0x02}, KeySize)
var testUserID = "testid"
var testRecordID = "testrecordid"

func newTestSealer(t *testing.T, key []byte) *Sealer {
	t.Helper()
	s, err := NewSealer(key)
	require.NoError(t, err)
	return s
}

func TestNewSealer_KeyLength(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		wantErr bool
	}{
		{
			name:    "0 bytes",
			key:     []byte{},
			wantErr: true,
		},
		{
			name:    "16 bytes",
			key:     bytes.Repeat([]byte{0x01}, 16),
			wantErr: true,
		},
		{
			name:    "24 bytes",
			key:     bytes.Repeat([]byte{0x01}, 24),
			wantErr: true,
		},
		{
			name:    "31 bytes",
			key:     bytes.Repeat([]byte{0x01}, 31),
			wantErr: true,
		},
		{
			name:    "32 bytes",
			key:     bytes.Repeat([]byte{0x01}, 32),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSealer(tt.key)
			if tt.wantErr {
				require.Error(t, err, "на некорректной длине ключа должна быть ошибка")
				assert.ErrorIs(t, err, ErrInvalidKey)
			} else {
				require.NoError(t, err, "правильный ключ не должен выдавать ошибку")
			}
		})
	}
}

func TestSealOpen_RoundTrip(t *testing.T) {
	sealer := newTestSealer(t, testKey)
	pt := []byte("sometext")

	sealed, err := sealer.Seal(testUserID, testRecordID, PartHeader, pt)
	require.NoError(t, err)

	assert.Equal(t, 12, len(sealed.Nonce))

	deciphered, err := sealer.Open(testUserID, testRecordID, PartHeader, sealed)
	require.NoError(t, err)

	assert.Equal(t, pt, deciphered)
}

// TestSealOpen_RoundTripParts проверяет круг для обеих частей и разных размеров данных,
// включая пустые: пустое тело секрета — реалистичный случай.
func TestSealOpen_RoundTripParts(t *testing.T) {
	sealer := newTestSealer(t, testKey)
	plaintexts := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"one byte", []byte{0x42}},
		{"text", []byte("sometext")},
		{"64 KiB", bytes.Repeat([]byte{0xAB}, 64*1024)},
	}
	for _, part := range []Part{PartHeader, PartBody} {
		for _, pt := range plaintexts {
			t.Run(string(part)+"/"+pt.name, func(t *testing.T) {
				sealed, err := sealer.Seal(testUserID, testRecordID, part, pt.data)
				require.NoError(t, err)
				assert.Len(t, sealed.Ciphertext, len(pt.data)+16, "шифртекст = данные + тег GCM")

				got, err := sealer.Open(testUserID, testRecordID, part, sealed)
				require.NoError(t, err)
				assert.Equal(t, len(pt.data), len(got))
				if len(pt.data) > 0 {
					assert.Equal(t, pt.data, got)
				}
			})
		}
	}
}

// TestBuildAAD_Format фиксирует формат кодирования AAD.
func TestBuildAAD_Format(t *testing.T) {
	need := []byte("\x00\x00\x00\x06testid\x00\x00\x00\x0ctestrecordid\x00\x00\x00\x06header")
	aad := buildAAD(testUserID, testRecordID, PartHeader)
	assert.Equal(t, need, aad)
}

// TestOpen_KnownVector строит Sealed "вручную" с фиксированной nonce, и пытается открыть с помощью Sealer.
// Так фиксируется формат шифрования.
func TestOpen_KnownVector(t *testing.T) {
	pt := []byte("sometext")

	block, err := aes.NewCipher(testKey)
	require.NoError(t, err)

	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	nonce := bytes.Repeat([]byte{0x03}, gcm.NonceSize())

	aad := buildAAD(testUserID, testRecordID, PartHeader)

	ct := gcm.Seal(nil, nonce, pt, aad)

	sealed := Sealed{Nonce: nonce, Ciphertext: ct}

	sealer := newTestSealer(t, testKey)

	deciphered, err := sealer.Open(testUserID, testRecordID, PartHeader, sealed)
	require.NoError(t, err)

	assert.Equal(t, pt, deciphered)
}

func TestSeal_FreshNonce(t *testing.T) {
	pt := []byte("sometext")
	sealer := newTestSealer(t, testKey)
	sealedA, err := sealer.Seal(testUserID, testRecordID, PartHeader, pt)
	require.NoError(t, err)

	sealedB, err := sealer.Seal(testUserID, testRecordID, PartHeader, pt)
	require.NoError(t, err)

	assert.NotEqual(t, sealedA.Nonce, sealedB.Nonce)
	assert.NotEqual(t, sealedA.Ciphertext, sealedB.Ciphertext)
}

// TestOpen_Rejects проверяет, что любое расхождение с тем, что было при Seal,
// приводит к ErrDecrypt.
func TestOpen_Rejects(t *testing.T) {
	tests := []struct {
		name     string
		key      []byte
		userID   string
		recordID string
		part     Part
		mutate   func(s *Sealed)
	}{
		{name: "wrong key", key: otherKey},
		{name: "wrong user id", userID: "otherid"},
		{name: "wrong record id", recordID: "otherrecordid"},
		{name: "wrong part", part: PartBody},
		// Конкатенация даёт ту же строку "testidtestrecordid", но поля разные.
		// Без префиксов длины AAD совпал бы.
		{name: "shifted field boundary", userID: "testi", recordID: "dtestrecordid"},
		{name: "flipped ciphertext bit", mutate: func(s *Sealed) { s.Ciphertext[0] ^= 0x01 }},
		{name: "flipped tag bit", mutate: func(s *Sealed) { s.Ciphertext[len(s.Ciphertext)-1] ^= 0x01 }},
		{name: "flipped nonce bit", mutate: func(s *Sealed) { s.Nonce[0] ^= 0x01 }},
		{name: "truncated ciphertext", mutate: func(s *Sealed) { s.Ciphertext = s.Ciphertext[:len(s.Ciphertext)-1] }},
		{name: "ciphertext shorter than tag", mutate: func(s *Sealed) { s.Ciphertext = s.Ciphertext[:5] }},
		{name: "appended byte", mutate: func(s *Sealed) { s.Ciphertext = append(s.Ciphertext, 0x00) }},
		{name: "empty ciphertext", mutate: func(s *Sealed) { s.Ciphertext = []byte{} }},
		{name: "nil ciphertext", mutate: func(s *Sealed) { s.Ciphertext = nil }},
		{name: "nil nonce", mutate: func(s *Sealed) { s.Nonce = nil }},
		{name: "short nonce", mutate: func(s *Sealed) { s.Nonce = s.Nonce[:11] }},
		{name: "long nonce", mutate: func(s *Sealed) { s.Nonce = append(s.Nonce, 0x00) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sealed, err := newTestSealer(t, testKey).Seal(testUserID, testRecordID, PartHeader, []byte("sometext"))
			require.NoError(t, err)

			// Незаданные поля означают "как при Seal".
			key, userID, recordID, part := testKey, testUserID, testRecordID, PartHeader
			if tt.key != nil {
				key = tt.key
			}
			if tt.userID != "" {
				userID = tt.userID
			}
			if tt.recordID != "" {
				recordID = tt.recordID
			}
			if tt.part != "" {
				part = tt.part
			}
			if tt.mutate != nil {
				tt.mutate(&sealed)
			}

			plaintext, openErr := newTestSealer(t, key).Open(userID, recordID, part, sealed)
			require.Error(t, openErr)
			assert.ErrorIs(t, openErr, ErrDecrypt)
			assert.Nil(t, plaintext, "при ошибке данные возвращаться не должны")
		})
	}
}

// TestSealer_Concurrent проверяет, что один Sealer безопасно используется из
// нескольких горутин.
func TestSealer_Concurrent(t *testing.T) {
	const (
		goroutines = 16
		iterations = 50
	)
	sealer := newTestSealer(t, testKey)

	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Go(func() {
			recordID := "record-" + strconv.Itoa(g)
			pt := []byte("plaintext-" + strconv.Itoa(g))
			for range iterations {
				sealed, err := sealer.Seal(testUserID, recordID, PartBody, pt)
				if !assert.NoError(t, err) {
					return
				}
				got, err := sealer.Open(testUserID, recordID, PartBody, sealed)
				if !assert.NoError(t, err) {
					return
				}
				assert.Equal(t, pt, got)
			}
		})
	}
	wg.Wait()
}
