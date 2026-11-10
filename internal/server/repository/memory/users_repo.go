package memory

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/LifeforDream/pract-gophkeeper/internal/kdfparams"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/domain"
)

// UsersRepo реализует хранилище пользователей в памяти.
type UsersRepo struct {
	mu        sync.RWMutex
	users     map[string]domain.User // ключ - id пользователя
	idByLogin map[string]string
}

// NewUsersRepo создаёт новое хранилище пользователей.
func NewUsersRepo() *UsersRepo {
	return &UsersRepo{
		users:     make(map[string]domain.User),
		idByLogin: make(map[string]string),
	}
}

// CreateUser создаёт пользователя и возвращает его вместе со сгенерированным ID.
// Если логин уже занят, возвращает domain.ErrLoginTaken.
func (r *UsersRepo) CreateUser(_ context.Context, login string, authHash, salt []byte, params kdfparams.Params) (domain.User, error) {
	id, err := newUserID()
	if err != nil {
		return domain.User{}, fmt.Errorf("users repo: error generating user id: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exist := r.idByLogin[login]; exist {
		return domain.User{}, domain.ErrLoginTaken
	}

	user := domain.User{
		ID:        id,
		Login:     login,
		AuthHash:  slices.Clone(authHash),
		KDFSalt:   slices.Clone(salt),
		KDFParams: params,
		CreatedAt: time.Now(),
	}
	r.users[id] = user
	r.idByLogin[login] = id

	return cloneUser(user), nil
}

// GetUser получает пользователя по id или domain.ErrNotFound, если такого нет.
func (r *UsersRepo) GetUser(_ context.Context, id string) (domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	user, ok := r.users[id]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return cloneUser(user), nil
}

// GetUserByLogin возвращает пользователя по логину или domain.ErrNotFound, если такого нет.
func (r *UsersRepo) GetUserByLogin(_ context.Context, login string) (domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	id, ok := r.idByLogin[login]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	user, ok := r.users[id]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return cloneUser(user), nil
}

// cloneUser копирует слайсы в данных пользователя, чтобы вызывающий код не мог изменить хранимые данные.
func cloneUser(u domain.User) domain.User {
	u.AuthHash = slices.Clone(u.AuthHash)
	u.KDFSalt = slices.Clone(u.KDFSalt)
	return u
}

// newUserID генерирует случайный идентификатор пользователя.
func newUserID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
