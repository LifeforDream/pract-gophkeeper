package crypto

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
)

// testParams — дешёвые параметры Argon2id, чтобы тесты работали быстро.
// Память равна нижнему допустимому пределу.
var testParams = Params{MemoryKiB: MemoryLowerLimitKiB, Iterations: 1, Parallelism: 1}

var (
	testPassword = []byte("correct horse battery staple")
	testSalt     = []byte("0123456789abcdef")
)

func TestDefaultParams_Valid(t *testing.T) {
	assert.NoError(t, DefaultParams().Validate())
}

func TestParams_Validate(t *testing.T) {
	tests := []struct {
		name    string
		params  Params
		wantErr bool
	}{
		{"default", DefaultParams(), false},
		{"test params", testParams, false},
		{"memory at lower limit", Params{MemoryKiB: MemoryLowerLimitKiB, Iterations: 1, Parallelism: 1}, false},
		{"memory at upper limit", Params{MemoryKiB: MemoryUpperLimitKib, Iterations: 1, Parallelism: 1}, false},
		{"memory below lower limit", Params{MemoryKiB: MemoryLowerLimitKiB - 1, Iterations: 1, Parallelism: 1}, true},
		{"memory zero", Params{MemoryKiB: 0, Iterations: 1, Parallelism: 1}, true},
		{"memory above upper limit", Params{MemoryKiB: MemoryUpperLimitKib + 1, Iterations: 1, Parallelism: 1}, true},
		{"zero iterations", Params{MemoryKiB: MemoryLowerLimitKiB, Iterations: 0, Parallelism: 1}, true},
		{"iterations at upper limit", Params{MemoryKiB: MemoryLowerLimitKiB, Iterations: IterationsUpperLimit, Parallelism: 1}, false},
		{"iterations above upper limit", Params{MemoryKiB: MemoryLowerLimitKiB, Iterations: IterationsUpperLimit + 1, Parallelism: 1}, true},
		{"zero parallelism", Params{MemoryKiB: MemoryLowerLimitKiB, Iterations: 1, Parallelism: 0}, true},
		{"parallelism at upper limit", Params{MemoryKiB: MemoryLowerLimitKiB, Iterations: 1, Parallelism: ParallelismUpperLimit}, false},
		{"parallelism above upper limit", Params{MemoryKiB: MemoryLowerLimitKiB, Iterations: 1, Parallelism: ParallelismUpperLimit + 1}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.params.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidParams)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestNewSalt(t *testing.T) {
	a, err := NewSalt()
	require.NoError(t, err)
	b, err := NewSalt()
	require.NoError(t, err)

	assert.Len(t, a, SaltSize)
	assert.Len(t, b, SaltSize)
	assert.NotEqual(t, a, b, "две соли подряд не должны совпадать")
}

func TestDeriveKeys_Deterministic(t *testing.T) {
	first, err := DeriveKeys(testPassword, testSalt, testParams)
	require.NoError(t, err)
	second, err := DeriveKeys(testPassword, testSalt, testParams)
	require.NoError(t, err)

	assert.Equal(t, first, second)
}

func TestDeriveKeys_AuthDiffersFromEnc(t *testing.T) {
	keys, err := DeriveKeys(testPassword, testSalt, testParams)
	require.NoError(t, err)

	assert.NotEqual(t, keys.Auth, keys.Enc)
	assert.NotEqual(t, [KeySize]byte{}, keys.Auth, "ключ не должен быть нулевым")
	assert.NotEqual(t, [KeySize]byte{}, keys.Enc, "ключ не должен быть нулевым")
}

func TestDeriveKeys_EveryInputChangesBothKeys(t *testing.T) {
	base, err := DeriveKeys(testPassword, testSalt, testParams)
	require.NoError(t, err)

	tests := []struct {
		name     string
		password []byte
		salt     []byte
		params   Params
	}{
		{"password", []byte("another password"), testSalt, testParams},
		{"salt", testPassword, []byte("fedcba9876543210"), testParams},
		{"memory", testPassword, testSalt, Params{MemoryKiB: 2 * MemoryLowerLimitKiB, Iterations: 1, Parallelism: 1}},
		{"iterations", testPassword, testSalt, Params{MemoryKiB: MemoryLowerLimitKiB, Iterations: 2, Parallelism: 1}},
		{"parallelism", testPassword, testSalt, Params{MemoryKiB: MemoryLowerLimitKiB, Iterations: 1, Parallelism: 2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeriveKeys(tt.password, tt.salt, tt.params)
			require.NoError(t, err)

			assert.NotEqual(t, base.Auth, got.Auth, "auth_key должен зависеть от входа %q", tt.name)
			assert.NotEqual(t, base.Enc, got.Enc, "enc_key должен зависеть от входа %q", tt.name)
		})
	}
}

// TestDeriveKeys_InvalidParams проверяет, что DeriveKeys сам вызывает Validate:
// параметры приходят с сервера и не должны доходить до Argon2 непроверенными.
func TestDeriveKeys_InvalidParams(t *testing.T) {
	tests := []struct {
		name   string
		params Params
	}{
		{"zero value", Params{}},
		{"memory above upper limit", Params{MemoryKiB: MemoryUpperLimitKib + 1, Iterations: 1, Parallelism: 1}},
		{"iterations above upper limit", Params{MemoryKiB: MemoryLowerLimitKiB, Iterations: IterationsUpperLimit + 1, Parallelism: 1}},
		{"parallelism above upper limit", Params{MemoryKiB: MemoryLowerLimitKiB, Iterations: 1, Parallelism: ParallelismUpperLimit + 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, err := DeriveKeys(testPassword, testSalt, tt.params)

			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidParams)
			assert.Equal(t, Keys{}, keys, "при ошибке ключи возвращаться не должны")
		})
	}
}

// TestDeriveKeys_SaltLength проверяет, что слишком короткая "соль" (если её присылает сервер)
// отвергается до запуска Argon2, а длинная принимается.
func TestDeriveKeys_SaltLength(t *testing.T) {
	tests := []struct {
		name    string
		salt    []byte
		wantErr bool
	}{
		{"nil", nil, true},
		{"empty", []byte{}, true},
		{"one byte", []byte{0x01}, true},
		{"one byte short", bytes.Repeat([]byte{0x01}, SaltSize-1), true},
		{"exact size", bytes.Repeat([]byte{0x01}, SaltSize), false},
		{"longer than size", bytes.Repeat([]byte{0x01}, SaltSize+1), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, err := DeriveKeys(testPassword, tt.salt, testParams)
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidSalt)
				assert.Equal(t, Keys{}, keys, "при ошибке ключи возвращаться не должны")
				return
			}
			require.NoError(t, err)
			assert.NotEqual(t, Keys{}, keys)
		})
	}
}

func TestDeriveKeys_MatchesReferenceConstruction(t *testing.T) {
	master := argon2.IDKey(testPassword, testSalt, testParams.Iterations, testParams.MemoryKiB, testParams.Parallelism, KeySize)
	wantAuth, err := hkdf.Expand(sha256.New, master, AuthKeyLabel, KeySize)
	require.NoError(t, err)
	wantEnc, err := hkdf.Expand(sha256.New, master, EncodingKeyLabel, KeySize)
	require.NoError(t, err)

	got, err := DeriveKeys(testPassword, testSalt, testParams)
	require.NoError(t, err)

	assert.Equal(t, wantAuth, got.Auth[:])
	assert.Equal(t, wantEnc, got.Enc[:])
}

// Зафиксированный вектор защищает от случайной смены алгоритма, меток или
// порядка аргументов.
func TestDeriveKeys_KnownVector(t *testing.T) {
	const (
		wantAuth = "778dabca1f744f7e43c29c0bb21d1e3ab8c388546b1d54bdad1e7310a662e90c"
		wantEnc  = "15f80fa3799b354a9cad5221ad0ecd4d90f0e4e0df325d1a8878ece150c309bc"
	)

	got, err := DeriveKeys(testPassword, testSalt, testParams)
	require.NoError(t, err)

	assert.Equal(t, wantAuth, hex.EncodeToString(got.Auth[:]))
	assert.Equal(t, wantEnc, hex.EncodeToString(got.Enc[:]))
}
