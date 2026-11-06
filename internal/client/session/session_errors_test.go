package session

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fileAsDir создаёт обычный файл и возвращает путь внутри него: любое обращение к такому пути
// заканчивается ошибкой ENOTDIR.
func fileAsDir(t *testing.T) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "plain-file")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0o600))
	return filepath.Join(f, "sub", "session.json")
}

// dirAtPath создаёт непустую директорию по месту, где должен лежать файл сессии.
func dirAtPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "session.json")
	require.NoError(t, os.MkdirAll(filepath.Join(p, "inner"), 0o700))
	return p
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestNewFileStore_MkdirFails(t *testing.T) {
	s, err := NewFileStore(fileAsDir(t))
	assert.Error(t, err)
	assert.Nil(t, s)
}

func TestFileStore_Load_OpenError(t *testing.T) {
	s := &FileStore{path: fileAsDir(t)}
	_, err := s.Load(testAddr)
	require.Error(t, err)
	assert.NotErrorIs(t, err, domain.ErrNoSession, "ENOTDIR — не «сессии нет», а настоящая ошибка")
}

func TestFileStore_Clear_Error(t *testing.T) {
	s := &FileStore{path: dirAtPath(t)}
	err := s.Clear()
	require.Error(t, err)
	assert.NotErrorIs(t, err, os.ErrNotExist)
}

func TestFileStore_Save_Errors(t *testing.T) {
	t.Run("directory was removed", func(t *testing.T) {
		s, path := newStore(t)
		require.NoError(t, os.RemoveAll(filepath.Dir(path)))
		assert.Error(t, s.Save(testSession()))
	})

	t.Run("rename fails and temp file is cleaned up", func(t *testing.T) {
		path := dirAtPath(t) // rename файла поверх непустой директории невозможен
		s := &FileStore{path: path}

		assert.Error(t, s.Save(testSession()))
		assert.Equal(t, []string{"session.json"}, listDir(t, filepath.Dir(path)),
			"временный файл должен быть удалён")
	})

	t.Run("failed save keeps the previous session", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("права на директорию не действуют (Windows или root)")
		}
		s, path := newStore(t)
		old := testSession()
		require.NoError(t, s.Save(old))

		dir := filepath.Dir(path)
		require.NoError(t, os.Chmod(dir, 0o500)) // нельзя создать временный файл
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

		next := testSession()
		next.Token = "new-token"
		require.Error(t, s.Save(next))

		got, err := s.Load(testAddr)
		require.NoError(t, err, "старая сессия не должна пострадать")
		assert.Equal(t, old.Token, got.Token)
	})
}

func TestFileStore_Save_TempFileStaysNextToSession(t *testing.T) {
	// rename между разными файловыми системами не работает, поэтому временный файл
	// обязан создаваться рядом с файлом сессии, а не в os.TempDir()
	osTmp := t.TempDir()
	t.Setenv("TMPDIR", osTmp)
	t.Setenv("TMP", osTmp)
	t.Setenv("TEMP", osTmp)

	s, _ := newStore(t)
	require.NoError(t, s.Save(testSession()))
	require.NoError(t, s.Save(testSession()))

	assert.Empty(t, listDir(t, osTmp))
}
