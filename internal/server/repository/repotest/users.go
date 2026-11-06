package repotest

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/LifeforDream/pract-gophkeeper/internal/kdfparams"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/domain"
)

// UsersRepo описывает контракт репозитория пользователей, который проверяет набор тестов.
type UsersRepo interface {
	CreateUser(ctx context.Context, login string, authHash, salt []byte, params kdfparams.Params) (domain.User, error)
	GetUser(ctx context.Context, id string) (domain.User, error)
	GetUserByLogin(ctx context.Context, login string) (domain.User, error)
}

// UsersFactory создаёт чистый (пустой) репозиторий для каждого теста.
type UsersFactory func(t *testing.T) UsersRepo

var usersTestParams = kdfparams.Params{MemoryKiB: 64, Iterations: 1, Parallelism: 1}

// RunUsers запускает контрактный набор тестов против репозитория пользователей, созданного factory.
func RunUsers(t *testing.T, factory UsersFactory) {
	tests := []struct {
		name string
		run  func(t *testing.T, repo UsersRepo)
	}{
		{"create and get", testUserCreateGet},
		{"duplicate login", testUserDuplicate},
		{"unknown login", testUserUnknown},
		{"unique ids", testUserUniqueIDs},
		{"logins are case sensitive", testUserCaseSensitive},
		{"returned slices are copies", testUserCopies},
		{"concurrent same login: single winner", testUserConcurrentSame},
		{"concurrent different logins", testUserConcurrentDifferent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.run(t, factory(t))
		})
	}
}

func testUserCreateGet(t *testing.T, repo UsersRepo) {
	ctx := context.Background()
	created, err := repo.CreateUser(ctx, "alice", []byte("hash"), []byte("salt"), usersTestParams)
	require.NoError(t, err)
	assert.NotEmpty(t, created.ID)
	assert.Equal(t, "alice", created.Login)
	assert.Equal(t, []byte("hash"), created.AuthHash)
	assert.Equal(t, []byte("salt"), created.KDFSalt)
	assert.Equal(t, usersTestParams, created.KDFParams)
	assert.False(t, created.CreatedAt.IsZero())

	got, err := repo.GetUserByLogin(ctx, "alice")
	require.NoError(t, err)
	assert.Equal(t, created.ID, got.ID)
	assert.Equal(t, created.Login, got.Login)
	assert.Equal(t, created.AuthHash, got.AuthHash)
	assert.Equal(t, created.KDFSalt, got.KDFSalt)
	assert.Equal(t, created.KDFParams, got.KDFParams)
}

func testUserDuplicate(t *testing.T, repo UsersRepo) {
	ctx := context.Background()
	first, err := repo.CreateUser(ctx, "alice", []byte("h1"), []byte("s1"), usersTestParams)
	require.NoError(t, err)

	_, err = repo.CreateUser(ctx, "alice", []byte("h2"), []byte("s2"), usersTestParams)
	assert.ErrorIs(t, err, domain.ErrLoginTaken)

	// Неудачная регистрация не должна затирать существующего пользователя.
	got, err := repo.GetUserByLogin(ctx, "alice")
	require.NoError(t, err)
	assert.Equal(t, first.ID, got.ID)
	assert.Equal(t, []byte("h1"), got.AuthHash)
	assert.Equal(t, []byte("s1"), got.KDFSalt)
}

func testUserUnknown(t *testing.T, repo UsersRepo) {
	ctx := context.Background()
	_, err := repo.GetUserByLogin(ctx, "ghost")
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func testUserUniqueIDs(t *testing.T, repo UsersRepo) {
	ctx := context.Background()
	a, err := repo.CreateUser(ctx, "a", []byte("h"), []byte("s"), usersTestParams)
	require.NoError(t, err)
	b, err := repo.CreateUser(ctx, "b", []byte("h"), []byte("s"), usersTestParams)
	require.NoError(t, err)
	assert.NotEqual(t, a.ID, b.ID)
}

func testUserCaseSensitive(t *testing.T, repo UsersRepo) {
	ctx := context.Background()
	_, err := repo.CreateUser(ctx, "Alice", []byte("h"), []byte("s"), usersTestParams)
	require.NoError(t, err)
	_, err = repo.CreateUser(ctx, "alice", []byte("h"), []byte("s"), usersTestParams)
	assert.NoError(t, err)
}

func testUserCopies(t *testing.T, repo UsersRepo) {
	ctx := context.Background()
	hash, salt := []byte("hash"), []byte("salt")
	created, err := repo.CreateUser(ctx, "alice", hash, salt, usersTestParams)
	require.NoError(t, err)

	// Изменение входных срезов и результатов не должно влиять на хранилище.
	hash[0], salt[0] = 'X', 'X'
	created.AuthHash[1] = 'Y'
	got, err := repo.GetUserByLogin(ctx, "alice")
	require.NoError(t, err)
	got.KDFSalt[0] = 'Z'

	again, err := repo.GetUserByLogin(ctx, "alice")
	require.NoError(t, err)
	assert.Equal(t, []byte("hash"), again.AuthHash)
	assert.Equal(t, []byte("salt"), again.KDFSalt)
}

func testUserConcurrentSame(t *testing.T, repo UsersRepo) {
	ctx := context.Background()
	const workers = 50
	var (
		wg    sync.WaitGroup
		wins  atomic.Int32
		taken atomic.Int32
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := repo.CreateUser(ctx, "alice", []byte("h"), []byte("s"), usersTestParams)
			switch {
			case err == nil:
				wins.Add(1)
			case assert.ErrorIs(t, err, domain.ErrLoginTaken):
				taken.Add(1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), wins.Load())
	assert.Equal(t, int32(workers-1), taken.Load())
}

func testUserConcurrentDifferent(t *testing.T, repo UsersRepo) {
	ctx := context.Background()
	const workers = 50
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			login := fmt.Sprintf("user-%d", i)
			_, err := repo.CreateUser(ctx, login, []byte("h"), []byte("s"), usersTestParams)
			assert.NoError(t, err)
			_, err = repo.GetUserByLogin(ctx, login)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
}
