package session

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testAddr = "localhost:8443"

func testSession() Session {
	return Session{
		ServerAddr: testAddr,
		Login:      "alice",
		UserID:     "user-1",
		Token:      "token",
		ExpiresAt:  time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
		EncKey:     []byte("0123456789abcdef0123456789abcdef"),
	}
}

// newStore создаёт хранилище во вложенной (ещё не существующей) директории.
func newStore(t *testing.T) (*FileStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sub", "session.json")
	s, err := NewFileStore(path)
	require.NoError(t, err)
	return s, path
}

func TestFileStore_SaveLoad(t *testing.T) {
	s, _ := newStore(t)
	want := testSession()
	require.NoError(t, s.Save(want))

	got, err := s.Load(testAddr)
	require.NoError(t, err)
	assert.Equal(t, want.EncKey, got.EncKey)
	assert.Equal(t, want.Token, got.Token)
	assert.Equal(t, want.UserID, got.UserID)
	assert.Equal(t, want.Login, got.Login)
	assert.True(t, want.ExpiresAt.Equal(got.ExpiresAt))
}

func TestFileStore_SaveOverwritesLongerFile(t *testing.T) {
	s, _ := newStore(t)
	long := testSession()
	long.Token = string(make([]byte, 4096)) // заведомо длиннее второй сессии
	require.NoError(t, s.Save(long))

	short := testSession()
	require.NoError(t, s.Save(short))

	got, err := s.Load(testAddr)
	require.NoError(t, err, "хвост старого файла не должен ломать JSON")
	assert.Equal(t, short.Token, got.Token)
}

func TestFileStore_FileAndDirModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX-права на Windows не применяются")
	}
	s, path := newStore(t)
	require.NoError(t, s.Save(testSession()))

	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.True(t, fi.Mode().IsRegular(), "по пути сессии должен лежать файл, а не директория")
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())

	di, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), di.Mode().Perm())
}

func TestFileStore_SaveLeavesNoTempFiles(t *testing.T) {
	s, path := newStore(t)
	require.NoError(t, s.Save(testSession()))
	require.NoError(t, s.Save(testSession()))

	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, filepath.Base(path), entries[0].Name())
}

func TestFileStore_Load_Errors(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		s, _ := newStore(t)
		_, err := s.Load(testAddr)
		assert.ErrorIs(t, err, domain.ErrNoSession)
	})
	t.Run("address mismatch", func(t *testing.T) {
		s, _ := newStore(t)
		require.NoError(t, s.Save(testSession()))
		_, err := s.Load("other:1")
		assert.ErrorIs(t, err, domain.ErrServerMismatch)
	})
	t.Run("corrupted file", func(t *testing.T) {
		s, path := newStore(t)
		require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o600))
		_, err := s.Load(testAddr)
		require.Error(t, err)
		assert.NotErrorIs(t, err, domain.ErrNoSession)
	})
}

func TestFileStore_Clear(t *testing.T) {
	s, _ := newStore(t)
	require.NoError(t, s.Save(testSession()))

	require.NoError(t, s.Clear())
	_, err := s.Load(testAddr)
	assert.ErrorIs(t, err, domain.ErrNoSession)

	assert.NoError(t, s.Clear(), "повторный Clear идемпотентен")
}

func TestNewFileStore_DefaultPath(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg) // Linux
	t.Setenv("HOME", cfg)            // macOS: UserConfigDir = $HOME/Library/Application Support
	t.Setenv("AppData", cfg)         // Windows

	s, err := NewFileStore("")
	require.NoError(t, err)
	require.NoError(t, s.Save(testSession()))

	_, err = s.Load(testAddr)
	assert.NoError(t, err)
	assert.Equal(t, "session.json", filepath.Base(s.path))
	assert.Equal(t, "gophkeeper", filepath.Base(filepath.Dir(s.path)))
}

func TestFileStore_Dir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "gk")
	s, err := NewFileStore(filepath.Join(dir, "session.json"))
	require.NoError(t, err)
	assert.Equal(t, dir, s.Dir())
}
