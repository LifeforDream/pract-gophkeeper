package dbrepo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/LifeforDream/pract-gophkeeper/internal/kdfparams"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UsersRepository реализует методы для работы с пользователями в БД.
type UsersRepository struct {
	pool *pgxpool.Pool
}

// NewUsersRepository возвращает ссылку на новый репозиторий с пулом pool.
func NewUsersRepository(pool *pgxpool.Pool) *UsersRepository {
	return &UsersRepository{pool: pool}
}

// userColumns — список колонок users в порядке, ожидаемом scanUser.
const userColumns = `id, login, auth_hash, kdf_salt, kdf_memory_kib, kdf_iterations, kdf_parallelism, created_at`

// scanUser читает строку users в domain.User. Порядок колонок задан userColumns.
func scanUser(row pgx.Row) (domain.User, error) {
	var u domain.User
	err := row.Scan(
		&u.ID, &u.Login, &u.AuthHash, &u.KDFSalt,
		&u.KDFParams.MemoryKiB, &u.KDFParams.Iterations, &u.KDFParams.Parallelism,
		&u.CreatedAt,
	)
	return u, err
}

// CreateUser создаёт пользователя. ID генерируется. Если такой логин уже занят, возвращается domain.ErrLoginTaken.
func (r *UsersRepository) CreateUser(ctx context.Context, login string, authHash, salt []byte, params kdfparams.Params) (domain.User, error) {
	id, err := newUserID()
	if err != nil {
		return domain.User{}, fmt.Errorf("create user: %w", err)
	}
	row := r.pool.QueryRow(ctx,
		`INSERT INTO users(id, login, auth_hash, kdf_salt, kdf_memory_kib, kdf_iterations, kdf_parallelism) VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING `+userColumns,
		id, login, authHash, salt, params.MemoryKiB, params.Iterations, params.Parallelism,
	)
	user, err := scanUser(row)
	if err != nil {
		return domain.User{}, fmt.Errorf("create user: %w", mapUniqueViolation(err, "uq_users_login", domain.ErrLoginTaken))
	}
	return user, nil
}

// GetUser получает пользователя по id.
func (r *UsersRepository) GetUser(ctx context.Context, id string) (domain.User, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users where id = ($1) `,
		id)
	user, err := scanUser(row)
	if err != nil {
		return domain.User{}, fmt.Errorf("get user: %w", mapNoRows(err, domain.ErrNotFound))
	}
	return user, nil
}

// GetUserByLogin получает пользователя по логину.
func (r *UsersRepository) GetUserByLogin(ctx context.Context, login string) (domain.User, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users where login = ($1) `,
		login)
	user, err := scanUser(row)
	if err != nil {
		return domain.User{}, fmt.Errorf("get user by login: %w", mapNoRows(err, domain.ErrNotFound))
	}
	return user, nil
}

// newUserID генерирует случайный идентификатор пользователя.
func newUserID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
