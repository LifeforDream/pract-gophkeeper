package app

import (
	"context"
	"testing"
	"time"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/crypto"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
	"github.com/LifeforDream/pract-gophkeeper/internal/kdfparams"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenClaims(t *testing.T) {
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	tests := []struct {
		name    string
		token   string
		wantID  string
		wantErr bool
	}{
		{"valid", validJWT("u-1", exp), "u-1", false},
		{"garbage", "not-a-jwt", "", true},
		{"no exp", makeJWT(jwt.MapClaims{"sub": "u-1"}), "", true},
		{"no sub", makeJWT(jwt.MapClaims{"exp": exp.Unix()}), "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// отсутствие exp не должно приводить к панике
			id, gotExp, err := tokenClaims(tt.token)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantID, id)
			assert.True(t, exp.Equal(gotExp))
		})
	}
}

func TestAuth_Register(t *testing.T) {
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	srv := &fakeAuth{token: validJWT("u-1", exp)}
	store := &memStore{}

	require.NoError(t, NewAuth(srv, store, testAddr).Register(context.Background(), "alice", []byte("pw")))

	assert.Equal(t, "alice", srv.regLogin)
	assert.Equal(t, kdfparams.DefaultParams(), srv.regParams)
	assert.Len(t, srv.regSalt, kdfparams.SaltSize)

	// ключи, посчитанные независимо, совпадают с отправленным на сервер и сохранённым в сессии
	keys, err := crypto.DeriveKeys([]byte("pw"), srv.regSalt, srv.regParams)
	require.NoError(t, err)
	assert.Equal(t, keys.Auth[:], srv.regAuthKey)

	require.NotNil(t, store.sess)
	assert.Equal(t, keys.Enc[:], store.sess.EncKey)
	assert.NotEqual(t, srv.regAuthKey, store.sess.EncKey, "enc_key не должен совпадать с auth_key")
	assert.Equal(t, "u-1", store.sess.UserID)
	assert.Equal(t, srv.token, store.sess.Token)
	assert.Equal(t, "alice", store.sess.Login)
	assert.Equal(t, testAddr, store.sess.ServerAddr)
	assert.True(t, exp.Equal(store.sess.ExpiresAt))
}

func TestAuth_Register_Failures(t *testing.T) {
	tests := []struct {
		name    string
		srv     *fakeAuth
		store   *memStore
		wantErr error
	}{
		{"login taken", &fakeAuth{regErr: domain.ErrLoginTaken}, &memStore{}, domain.ErrLoginTaken},
		{"garbage token", &fakeAuth{token: "garbage"}, &memStore{}, nil},
		{"save fails", &fakeAuth{token: validJWT("u", time.Now().Add(time.Hour))}, &memStore{saveErr: assert.AnError}, assert.AnError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewAuth(tt.srv, tt.store, testAddr).Register(context.Background(), "alice", []byte("pw"))
			require.Error(t, err)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}
			assert.Nil(t, tt.store.sess, "сессия не должна сохраняться при ошибке")
		})
	}
}

func TestAuth_Login(t *testing.T) {
	salt, err := kdfparams.NewSalt()
	require.NoError(t, err)
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	srv := &fakeAuth{salt: salt, params: testKDF, token: validJWT("u-1", exp)}
	store := &memStore{}

	require.NoError(t, NewAuth(srv, store, testAddr).Login(context.Background(), "alice", []byte("pw")))

	keys, err := crypto.DeriveKeys([]byte("pw"), salt, testKDF)
	require.NoError(t, err)
	assert.Equal(t, keys.Auth[:], srv.loginKey)
	require.NotNil(t, store.sess)
	assert.Equal(t, keys.Enc[:], store.sess.EncKey)
	assert.Equal(t, "u-1", store.sess.UserID)
	assert.Equal(t, testAddr, store.sess.ServerAddr)
}

func TestAuth_Login_Failures(t *testing.T) {
	salt, err := kdfparams.NewSalt()
	require.NoError(t, err)
	goodToken := validJWT("u-1", time.Now().Add(time.Hour))

	tests := []struct {
		name       string
		srv        *fakeAuth
		wantErr    error
		wantLogin  bool // дошли ли до srv.Login
		wantParams bool // ошибка именно валидации параметров
	}{
		{
			name:       "hostile params: huge memory",
			srv:        &fakeAuth{salt: salt, params: kdfparams.Params{MemoryKiB: kdfparams.MemoryUpperLimitKib + 1, Iterations: 1, Parallelism: 1}, token: goodToken},
			wantErr:    kdfparams.ErrInvalidParams,
			wantParams: true,
		},
		{
			name:       "hostile params: zero parallelism",
			srv:        &fakeAuth{salt: salt, params: kdfparams.Params{MemoryKiB: kdfparams.MemoryLowerLimitKiB, Iterations: 1}, token: goodToken},
			wantErr:    kdfparams.ErrInvalidParams,
			wantParams: true,
		},
		{
			name:    "get params fails",
			srv:     &fakeAuth{getErr: assert.AnError},
			wantErr: assert.AnError,
		},
		{
			name:      "invalid credentials",
			srv:       &fakeAuth{salt: salt, params: testKDF, loginErr: domain.ErrInvalidCredentials},
			wantErr:   domain.ErrInvalidCredentials,
			wantLogin: true,
		},
		{
			name:      "short salt from server",
			srv:       &fakeAuth{salt: []byte{1, 2}, params: testKDF, token: goodToken},
			wantErr:   crypto.ErrInvalidSalt,
			wantLogin: false,
		},
		{
			name:      "garbage token",
			srv:       &fakeAuth{salt: salt, params: testKDF, token: "garbage"},
			wantLogin: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &memStore{}
			err := NewAuth(tt.srv, store, testAddr).Login(context.Background(), "alice", []byte("pw"))
			require.Error(t, err)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}
			assert.Equal(t, tt.wantLogin, tt.srv.loginCalled)
			assert.Nil(t, store.sess, "сессия не должна сохраняться при ошибке")
		})
	}
}

func TestAuth_Logout(t *testing.T) {
	store := &memStore{}
	require.NoError(t, store.Save(sessionFor(testAddr)))
	a := NewAuth(&fakeAuth{}, store, testAddr)

	require.NoError(t, a.Logout())
	assert.Nil(t, store.sess)

	store.clearErr = assert.AnError
	assert.ErrorIs(t, a.Logout(), assert.AnError)
}

func TestAuth_ZeroesPassword(t *testing.T) {
	salt, err := kdfparams.NewSalt()
	require.NoError(t, err)
	srv := &fakeAuth{salt: salt, params: testKDF, token: validJWT("u-1", time.Now().Add(time.Hour))}

	for name, call := range map[string]func(a *Auth, pw []byte) error{
		"register": func(a *Auth, pw []byte) error { return a.Register(context.Background(), "alice", pw) },
		"login":    func(a *Auth, pw []byte) error { return a.Login(context.Background(), "alice", pw) },
	} {
		t.Run(name, func(t *testing.T) {
			pw := []byte("secret")
			require.NoError(t, call(NewAuth(srv, &memStore{}, testAddr), pw))
			assert.Equal(t, make([]byte, len("secret")), pw, "пароль не должен остаться в памяти")
		})
	}
}
