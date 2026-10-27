// Package jwtauth хранит методы по работе с JWT.
package jwtauth

import (
	"fmt"
	"time"

	"github.com/LifeforDream/pract-gophkeeper/internal/server/domain"
	"github.com/golang-jwt/jwt/v5"
)

// Service реализует методы по выпуску и проверке JWT.
type Service struct {
	secretKey []byte
	ttl       time.Duration
}

// NewJWTService создаёт JWTService с ключом secretKey.
func NewJWTService(secretKey []byte, ttl time.Duration) (*Service, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("invalid ttl")
	}
	if len(secretKey) == 0 {
		return nil, fmt.Errorf("empty secret key")
	}
	return &Service{secretKey: secretKey, ttl: ttl}, nil
}

// CreateJWT создаёт подписанный JWT для конкретного пользователя.
func (s *Service) CreateJWT(userID string) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"iss": "pract-gophkeeper",
			"sub": userID,
			"iat": jwt.NewNumericDate(time.Now()),
			"exp": jwt.NewNumericDate(time.Now().Add(s.ttl)),
		})
	return t.SignedString(s.secretKey)
}

// ValidateJWT валидирует JWT и возвращает ID пользователя, для которого он выпущен.
func (s *Service) ValidateJWT(token string) (string, error) {
	tok, err := jwt.Parse(token, func(_ *jwt.Token) (any, error) {
		return s.secretKey, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuer("pract-gophkeeper"),
	)
	if err != nil {
		return "", fmt.Errorf("error validating jwt: %w", err)
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid claims in jwt")
	}

	sub, err := claims.GetSubject()
	if err != nil {
		return "", fmt.Errorf("error getting sub claim: %w", err)
	}
	if sub == "" {
		return sub, domain.ErrNoUserID
	}
	return sub, nil
}
