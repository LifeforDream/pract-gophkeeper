package jwtauth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var secret = []byte("test-secret")

// newSvc создаёт сервис и падает, если конструктор вернул ошибку.
func newSvc(t *testing.T, key []byte, ttl time.Duration) *Service {
	t.Helper()
	svc, err := NewJWTService(key, ttl)
	require.NoError(t, err)
	return svc
}

func TestNewJWTService_InvalidTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Minute} {
		_, err := NewJWTService(secret, ttl)
		assert.Error(t, err, "ttl=%s", ttl)
	}
}

func TestNewJWTService_EmptySecret(t *testing.T) {
	for _, key := range [][]byte{nil, {}} {
		_, err := NewJWTService(key, time.Hour)
		assert.Error(t, err)
	}
}

func TestJWT_RoundTrip(t *testing.T) {
	svc := newSvc(t, secret, time.Hour)
	token, err := svc.CreateJWT("user-1")
	require.NoError(t, err)

	id, err := svc.ValidateJWT(token)
	require.NoError(t, err)
	assert.Equal(t, "user-1", id)
}

func TestValidateJWT_Rejects(t *testing.T) {
	good, err := newSvc(t, secret, time.Hour).CreateJWT("user-1")
	require.NoError(t, err)

	sign := func(method jwt.SigningMethod, claims jwt.MapClaims, key any) string {
		s, err := jwt.NewWithClaims(method, claims).SignedString(key)
		require.NoError(t, err)
		return s
	}
	future := jwt.NewNumericDate(time.Now().Add(time.Hour))
	past := jwt.NewNumericDate(time.Now().Add(-time.Minute))

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"garbage", "not-a-jwt"},
		{"wrong secret", func() string {
			s, err := newSvc(t, []byte("other"), time.Hour).CreateJWT("user-1")
			require.NoError(t, err)
			return s
		}()},
		{"expired", sign(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "user-1", "exp": past}, secret)},
		{"tampered payload", good[:len(good)-4] + "AAAA"},
		{"alg none", sign(jwt.SigningMethodNone, jwt.MapClaims{"sub": "user-1", "exp": future}, jwt.UnsafeAllowNoneSignatureType)},
		{"other hmac alg", sign(jwt.SigningMethodHS512, jwt.MapClaims{"sub": "user-1", "exp": future}, secret)},
		{"no exp", sign(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "user-1"}, secret)},
		{"no sub", sign(jwt.SigningMethodHS256, jwt.MapClaims{"exp": future}, secret)},
	}
	svc := newSvc(t, secret, time.Hour)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := svc.ValidateJWT(tt.token)
			assert.Error(t, err)
			assert.Empty(t, id)
		})
	}
}
