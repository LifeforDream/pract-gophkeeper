package auth

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/LifeforDream/pract-gophkeeper/internal/kdfparams"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/domain"
	jwtsvc "github.com/LifeforDream/pract-gophkeeper/internal/server/jwtauth"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/repository/memory"
)

// validSalt - соль той длины, которую всегда присылает клиент.
var validSalt = bytes.Repeat([]byte{'s'}, kdfparams.SaltSize)

var params = kdfparams.Params{MemoryKiB: kdfparams.MemoryLowerLimitKiB, Iterations: 1, Parallelism: 1}

func newService(t *testing.T) *Service {
	t.Helper()
	jwt, err := jwtsvc.NewJWTService([]byte("jwt-secret"), time.Hour)
	require.NoError(t, err)
	return NewAuthService(memory.NewUsersRepo(), jwt, []byte("fake-secret"))
}

func TestRegisterLogin(t *testing.T) {
	ctx := t.Context()
	svc := newService(t)

	token, err := svc.Register(ctx, "alice", []byte("auth-key"), validSalt, params)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	token, err = svc.Login(ctx, "alice", []byte("auth-key"))
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestRegister_LoginTaken(t *testing.T) {
	ctx := t.Context()
	svc := newService(t)
	_, err := svc.Register(ctx, "alice", []byte("k"), validSalt, params)
	require.NoError(t, err)

	_, err = svc.Register(ctx, "alice", []byte("k2"), validSalt, params)
	assert.ErrorIs(t, err, domain.ErrLoginTaken)
}

func TestLogin_BadCredentials(t *testing.T) {
	ctx := t.Context()
	svc := newService(t)
	_, err := svc.Register(ctx, "alice", []byte("right"), validSalt, params)
	require.NoError(t, err)

	tests := []struct {
		name    string
		login   string
		authKey []byte
	}{
		{"wrong key", "alice", []byte("wrong")},
		{"unknown user", "bob", []byte("right")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.Login(ctx, tt.login, tt.authKey)
			// Оба случая должны быть неразличимы для клиента.
			assert.ErrorIs(t, err, domain.ErrBadCredentials)
		})
	}
}

func TestGetKDFParams_Registered(t *testing.T) {
	ctx := t.Context()
	svc := newService(t)
	_, err := svc.Register(ctx, "alice", []byte("k"), validSalt, params)
	require.NoError(t, err)

	salt, got, err := svc.GetKDFParams(ctx, "alice")
	require.NoError(t, err)
	assert.Equal(t, validSalt, salt)
	assert.Equal(t, params, got)
}

func TestGetKDFParams_FakeSaltForUnknown(t *testing.T) {
	ctx := t.Context()
	svc := newService(t)

	salt1, p1, err := svc.GetKDFParams(ctx, "ghost")
	require.NoError(t, err)
	salt2, p2, err := svc.GetKDFParams(ctx, "ghost")
	require.NoError(t, err)
	saltOther, _, err := svc.GetKDFParams(ctx, "phantom")
	require.NoError(t, err)

	assert.NotEmpty(t, salt1)
	assert.Equal(t, salt1, salt2, "соль должна быть детерминированной")
	assert.Equal(t, p1, p2)
	assert.NotEqual(t, salt1, saltOther, "у разных логинов разная соль")
}

func TestRegister_InvalidArgument(t *testing.T) {
	ctx := t.Context()
	tests := []struct {
		name    string
		login   string
		authKey []byte
		salt    []byte
		params  kdfparams.Params
		want    error
	}{
		{"empty login", "", []byte("k"), validSalt, params, domain.ErrInvalidArgument},
		{"empty auth key", "alice", nil, validSalt, params, domain.ErrInvalidArgument},
		{"empty salt", "alice", []byte("k"), nil, params, domain.ErrInvalidArgument},
		{"short salt", "alice", []byte("k"), validSalt[:kdfparams.SaltSize-1], params, domain.ErrInvalidArgument},
		{"long salt", "alice", []byte("k"), append(validSalt[:kdfparams.SaltSize:kdfparams.SaltSize], 's'), params, domain.ErrInvalidArgument},
		{"memory below limit", "alice", []byte("k"), validSalt,
			kdfparams.Params{MemoryKiB: kdfparams.MemoryLowerLimitKiB - 1, Iterations: 1, Parallelism: 1}, kdfparams.ErrInvalidParams},
		{"memory above limit", "alice", []byte("k"), validSalt,
			kdfparams.Params{MemoryKiB: kdfparams.MemoryUpperLimitKib + 1, Iterations: 1, Parallelism: 1}, kdfparams.ErrInvalidParams},
		{"zero iterations", "alice", []byte("k"), validSalt,
			kdfparams.Params{MemoryKiB: kdfparams.MemoryLowerLimitKiB, Iterations: 0, Parallelism: 1}, kdfparams.ErrInvalidParams},
		{"zero parallelism", "alice", []byte("k"), validSalt,
			kdfparams.Params{MemoryKiB: kdfparams.MemoryLowerLimitKiB, Iterations: 1, Parallelism: 0}, kdfparams.ErrInvalidParams},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newService(t)
			_, err := svc.Register(ctx, tt.login, tt.authKey, tt.salt, tt.params)
			assert.ErrorIs(t, err, tt.want)

			// Отклонённая регистрация не должна занимать логин.
			if tt.login != "" {
				_, err = svc.Register(ctx, tt.login, []byte("k"), validSalt, params)
				assert.NoError(t, err)
			}
		})
	}
}

func TestLogin_InvalidArgument(t *testing.T) {
	ctx := t.Context()
	svc := newService(t)
	_, err := svc.Register(ctx, "alice", []byte("k"), validSalt, params)
	require.NoError(t, err)

	_, err = svc.Login(ctx, "", []byte("k"))
	assert.ErrorIs(t, err, domain.ErrInvalidArgument)
	_, err = svc.Login(ctx, "alice", nil)
	assert.ErrorIs(t, err, domain.ErrInvalidArgument)
}

func TestGetKDFParams_FakeLooksLikeReal(t *testing.T) {
	ctx := t.Context()
	svc := newService(t)
	// Соль у клиента всегда SaltSize байт.
	realSalt := bytes.Repeat([]byte{'s'}, kdfparams.SaltSize)
	_, err := svc.Register(ctx, "alice", []byte("k"), realSalt, kdfparams.DefaultParams())
	require.NoError(t, err)

	gotSalt, gotParams, err := svc.GetKDFParams(ctx, "alice")
	require.NoError(t, err)
	fakeSalt, fakeParams, err := svc.GetKDFParams(ctx, "ghost")
	require.NoError(t, err)

	// Фейк неотличим по длине соли и параметрам от настоящего ответа.
	assert.Len(t, fakeSalt, len(gotSalt))
	assert.Len(t, fakeSalt, kdfparams.SaltSize)
	assert.Equal(t, gotParams, fakeParams)
}
