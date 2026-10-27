// Package auth хранит бизнес-логику работы с пользователем.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/LifeforDream/pract-gophkeeper/internal/kdfparams"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/domain"
)

// Repo описывает методы, необходимые для работы с пользователями.
type Repo interface {
	CreateUser(ctx context.Context, login string, authHash, salt []byte, params kdfparams.Params) (domain.User, error)
	GetUser(ctx context.Context, id string) (domain.User, error)
	GetUserByLogin(ctx context.Context, login string) (domain.User, error)
}

// JWTService описывает необходимые методы для работы с JWT.
type JWTService interface {
	CreateJWT(userID string) (string, error)
}

// Service - методы, нужные для работы с пользователями.
type Service struct {
	repo           Repo
	jwtService     JWTService
	fakeSaltSecret []byte
}

// NewAuthService возвращает экземпляр AuthService.
func NewAuthService(repo Repo, jwtService JWTService, fakeSaltSecret []byte) *Service {
	return &Service{repo: repo, jwtService: jwtService, fakeSaltSecret: fakeSaltSecret}
}

// Register регистрирует пользователя и в случае успеха возвращает его токен.
func (s *Service) Register(ctx context.Context, login string, authKey, salt []byte, params kdfparams.Params) (string, error) {
	if login == "" || len(authKey) == 0 {
		return "", domain.ErrInvalidArgument
	}
	// Клиент всегда генерирует соль фиксированной длины; иная длина выдала бы настоящий аккаунт при сравнении с фейком.
	if len(salt) != kdfparams.SaltSize {
		return "", fmt.Errorf("salt must be %d bytes: %w", kdfparams.SaltSize, domain.ErrInvalidArgument)
	}

	if err := params.Validate(); err != nil {
		return "", fmt.Errorf("auth service: %w", err)
	}

	authHash := sha256.Sum256(authKey)

	user, err := s.repo.CreateUser(ctx, login, authHash[:], salt, params)
	if err != nil {
		return "", fmt.Errorf("auth service: error creating user: %w", err)
	}
	token, err := s.jwtService.CreateJWT(user.ID)
	if err != nil {
		return "", fmt.Errorf("auth service: error creating JWT: %w", err)
	}
	return token, nil
}

// Login проверяет наличие пользователя и корректность ключа. В случае успеха возвращает токен.
func (s *Service) Login(ctx context.Context, login string, authKey []byte) (string, error) {
	if login == "" || len(authKey) == 0 {
		return "", domain.ErrInvalidArgument
	}

	authHash := sha256.Sum256(authKey)

	user, err := s.repo.GetUserByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return "", domain.ErrBadCredentials
		}
		return "", fmt.Errorf("auth service: error getting user: %w", err)
	}

	if subtle.ConstantTimeCompare(user.AuthHash, authHash[:]) != 1 {
		return "", domain.ErrBadCredentials
	}
	token, err := s.jwtService.CreateJWT(user.ID)
	if err != nil {
		return "", fmt.Errorf("auth service: error creating JWT: %w", err)
	}
	return token, nil
}

// GetKDFParams забирает из хранилища или генерирует параметры для последующего логина пользователя.
func (s *Service) GetKDFParams(ctx context.Context, login string) ([]byte, kdfparams.Params, error) {
	user, err := s.repo.GetUserByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			h := hmac.New(sha256.New, s.fakeSaltSecret)
			_, err := h.Write([]byte(login))
			if err != nil {
				return nil, kdfparams.Params{}, fmt.Errorf("error generating fake salt: %w", err)
			}
			reth := h.Sum(nil)[:kdfparams.SaltSize:kdfparams.SaltSize]
			return reth, kdfparams.DefaultParams(), nil
		}
		return nil, kdfparams.Params{}, fmt.Errorf("unexpected error: %w", err)
	}
	return user.KDFSalt, user.KDFParams, nil
}
