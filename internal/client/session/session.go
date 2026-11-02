// Package session хранит логику работы с сессией пользователя.
// В частности, хранение токена, выпускаемого сервером.
package session

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
)

// Session хранит в себе данные одной сессии на клиенте.
type Session struct {
	ServerAddr string    `json:"serverAddr"` // адрес сервера. Нужен для того, чтобы не передать на "не тот" сервер ключи.
	Login      string    `json:"login"`      // логин пользователя. Выбирается пользователем.
	UserID     string    `json:"userID"`     // ID пользователя. Назначается сервером.
	Token      string    `json:"token"`      // JWT, полученный с сервера.
	ExpiresAt  time.Time `json:"expiresAt"`  // время, после которого JWT недействителен.
	EncKey     []byte    `json:"encKey"`     // ключ для кодирования записей. Сервер его не знает.
}

// Store описывает необходимые методы для работы с сессией.
type Store interface {
	Load(serverAddr string) (Session, error) // загружает сессию для конкретного сервера.
	Save(Session) error                      // сохраняет сессию.
	Clear() error                            // очищает файл сессии.
}

// FileStore реализует интерфейс Store для файла.
type FileStore struct {
	path string
}

// NewFileStore создаёт и возвращает файловое хранилище для сессии.
func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return nil, fmt.Errorf("getting user dir: %w", err)
		}
		path = filepath.Join(dir, "gophkeeper", "session.json")
	}

	err := os.MkdirAll(filepath.Dir(path), 0o700)
	if err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}
	return &FileStore{path: path}, nil
}

// Load загружает из файлового хранилища сессию.
func (s *FileStore) Load(serverAddr string) (Session, error) {
	file, err := os.Open(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Session{}, fmt.Errorf("file %s does not exist: %w", s.path, domain.ErrNoSession)
		}
		return Session{}, fmt.Errorf("loading session: %w", err)
	}
	defer file.Close()

	var session Session
	if err := json.UnmarshalRead(file, &session); err != nil {
		return Session{}, fmt.Errorf("error decoding json from file: %w", err)
	}
	if session.ServerAddr != serverAddr {
		return Session{}, fmt.Errorf("found session for server %s, requested for %s: %w", session.ServerAddr, serverAddr, domain.ErrServerMismatch)
	}
	return session, nil
}

// Save сохраняет сессию в файл.
func (s *FileStore) Save(session Session) error {
	tfile, err := os.CreateTemp(filepath.Dir(s.path), "session-*.tmp")
	if err != nil {
		return err
	}

	defer os.Remove(tfile.Name())

	err = json.MarshalWrite(tfile, session)
	if err != nil {
		_ = tfile.Close()
		return fmt.Errorf("write session json: %w", err)
	}

	err = tfile.Sync()
	if err != nil {
		_ = tfile.Close()
		return fmt.Errorf("error syncing temp file: %w", err)
	}

	err = tfile.Close()
	if err != nil {
		return fmt.Errorf("error closing temp file: %w", err)
	}

	return os.Rename(tfile.Name(), s.path)
}

// Clear очищает сессию, удаляя файл.
func (s *FileStore) Clear() error {
	err := os.Remove(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// если сессии уже нет, это нормально
			return nil
		}
		return fmt.Errorf("error clearing session file: %w", err)
	}
	return nil
}
