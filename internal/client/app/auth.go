package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/crypto"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/session"
	"github.com/LifeforDream/pract-gophkeeper/internal/kdfparams"
)

// Auth содержит методы для работы с аутентификацией клиента на сервере.
type Auth struct {
	srv        AuthServer
	store      session.Store
	serverAddr string
	wipeCache  func() error // удаляет локальный кэш; nil - кэш не подключён.
}

// NewAuth создаёт новый экземпляр аутентификатора.
// wipeCache вызывается при Logout; может быть nil.
func NewAuth(srv AuthServer, store session.Store, serverAddr string, wipeCache func() error) *Auth {
	return &Auth{srv: srv, store: store, serverAddr: serverAddr, wipeCache: wipeCache}
}

// Register регистрирует пользователя и сохраняет токен с ключом в файл сессии.
// Password зануляется в этом методе, и в случае успеха в памяти его больше нет.
func (a *Auth) Register(ctx context.Context, login string, password []byte) error {
	params := kdfparams.DefaultParams()
	salt, err := kdfparams.NewSalt()
	if err != nil {
		return fmt.Errorf("register generate salt: %w", err)
	}
	keys, err := crypto.DeriveKeys(password, salt, params)
	if err != nil {
		return fmt.Errorf("register derive keys: %w", err)
	}
	// пароль больше не нужен
	clear(password)

	token, err := a.srv.Register(ctx, login, keys.Auth[:], salt, params)
	if err != nil {
		return fmt.Errorf("register on server: %w", err)
	}
	return a.saveSession(token, login, keys)
}

// Login получает параметры, а потом токен заранее зарегистрированного пользователя.
// Password зануляется в этом методе, и в случае успеха в памяти его больше нет.
func (a *Auth) Login(ctx context.Context, login string, password []byte) error {
	salt, params, err := a.srv.GetKDFParams(ctx, login)
	if err != nil {
		return fmt.Errorf("login get params: %w", err)
	}
	if err = params.Validate(); err != nil {
		return fmt.Errorf("incorrect params from server: %w", err)
	}

	keys, err := crypto.DeriveKeys(password, salt, params)
	if err != nil {
		return fmt.Errorf("login derive keys: %w", err)
	}

	// пароль больше не нужен.
	clear(password)

	token, err := a.srv.Login(ctx, login, keys.Auth[:])
	if err != nil {
		return fmt.Errorf("login on server: %w", err)
	}

	return a.saveSession(token, login, keys)
}

func (a *Auth) saveSession(token, login string, keys crypto.Keys) error {
	userID, exp, err := tokenClaims(token)
	if err != nil {
		return fmt.Errorf("invalid claims in token: %w", err)
	}
	return a.store.Save(session.Session{
		ServerAddr: a.serverAddr,
		Login:      login,
		UserID:     userID,
		Token:      token,
		ExpiresAt:  exp,
		EncKey:     keys.Enc[:],
	})
}

// Logout очищает хранилище сессии и удаляет локальный кэш. Сбой одного шага не отменяет другой.
func (a *Auth) Logout() error {
	err := a.store.Clear()
	if a.wipeCache != nil {
		err = errors.Join(err, a.wipeCache())
	}
	return err
}

func tokenClaims(token string) (string, time.Time, error) {
	var claims jwt.RegisteredClaims
	_, _, err := jwt.NewParser().ParseUnverified(token, &claims)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("error parsing jwt: %w", err)
	}
	if claims.Subject == "" {
		return "", time.Time{}, errors.New("jwt has no sub")
	}
	if claims.ExpiresAt == nil {
		return "", time.Time{}, errors.New("jwt has no exp")
	}
	return claims.Subject, claims.ExpiresAt.Time, nil
}
