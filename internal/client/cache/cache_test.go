package cache

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/crypto"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
)

const (
	addr = "srv:1"
	user = "user-1"
)

func sealed(s string) crypto.Sealed {
	return crypto.Sealed{Nonce: []byte("nonce-12byte"), Ciphertext: []byte(s)}
}

func entry(id string, version int64) Entry {
	return Entry{ID: id, Version: version, Header: domain.Header{Type: domain.TypeText, Name: "n-" + id}}
}

func mustOpen(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir, addr, user)
	require.NoError(t, err)
	return s
}

func TestOpen(t *testing.T) {
	t.Run("fresh dir gives empty store", func(t *testing.T) {
		s := mustOpen(t, filepath.Join(t.TempDir(), "nested"))
		assert.Zero(t, s.LatestRevision())
		assert.Empty(t, s.Entries())
	})

	t.Run("binding mismatch wipes", func(t *testing.T) {
		tests := []struct{ name, addr, user string }{
			{"other server", "srv:2", user},
			{"other user", addr, "user-2"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				dir := t.TempDir()
				s := mustOpen(t, dir)
				require.NoError(t, s.Put(entry("a", 1), nil))
				require.NoError(t, s.PutBody("a", 1, sealed("x")))

				s2, err := Open(dir, tt.addr, tt.user)
				require.NoError(t, err)
				assert.Empty(t, s2.Entries())
				assert.Zero(t, s2.LatestRevision())
				files, _ := os.ReadDir(filepath.Join(dir, bodiesDir))
				assert.Empty(t, files)
			})
		}
	})

	t.Run("broken index is an empty store with ErrCorrupt", func(t *testing.T) {
		tests := []struct{ name, content string }{
			{"garbage", "not json at all"},
			{"truncated", `{"serverAddr":"srv:1","userID":"user-1","records":[{"id":"a"`},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				dir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dir, indexFile), []byte(tt.content), 0o600))
				s, err := Open(dir, addr, user)
				require.ErrorIs(t, err, ErrCorrupt)
				require.NotNil(t, s)
				assert.Empty(t, s.Entries())
				// хранилище остаётся рабочим
				require.NoError(t, s.Put(entry("a", 1), nil))
			})
		}
	})
}

func TestStore_PersistsAcrossOpen(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir)
	e := entry("a", 3)
	e.Header.Meta = []domain.MetaItem{{Key: "k", Value: "v"}}
	require.NoError(t, s.Put(e, nil))
	require.NoError(t, s.PutBody("a", 3, sealed("secret")))

	s2 := mustOpen(t, dir)
	got, ok := s2.Lookup("a")
	require.True(t, ok)
	assert.Equal(t, e, got)
	body, ok, err := s2.Body("a", 3)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, sealed("secret"), body)
}

func TestStore_Body(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, dir string, s *Store)
		version int64
		wantOK  bool
	}{
		{"hit", func(*testing.T, string, *Store) {}, 1, true},
		{"version mismatch", func(*testing.T, string, *Store) {}, 2, false},
		{"unknown id", func(t *testing.T, _ string, s *Store) { require.NoError(t, s.Remove("a")) }, 1, false},
		{"truncated body file", func(t *testing.T, dir string, _ *Store) {
			files, err := os.ReadDir(filepath.Join(dir, bodiesDir))
			require.NoError(t, err)
			require.Len(t, files, 1)
			require.NoError(t, os.WriteFile(filepath.Join(dir, bodiesDir, files[0].Name()), []byte(`{"ver`), 0o600))
		}, 1, false},
		{"missing body file", func(t *testing.T, dir string, _ *Store) {
			files, _ := os.ReadDir(filepath.Join(dir, bodiesDir))
			require.NoError(t, os.Remove(filepath.Join(dir, bodiesDir, files[0].Name())))
		}, 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			s := mustOpen(t, dir)
			require.NoError(t, s.Put(entry("a", 1), nil))
			require.NoError(t, s.PutBody("a", 1, sealed("x")))
			tt.prepare(t, dir, s)

			body, ok, err := s.Body("a", tt.version)
			require.NoError(t, err)
			assert.Equal(t, tt.wantOK, ok)
			if ok {
				assert.Equal(t, sealed("x"), body)
			}
		})
	}
}

func TestStore_Put_BodyHandling(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir)
	require.NoError(t, s.Put(entry("a", 1), nil))
	require.NoError(t, s.PutBody("a", 1, sealed("v1")))

	// тот же version без тела: тело сохраняется
	require.NoError(t, s.Put(entry("a", 1), nil))
	_, ok, _ := s.Body("a", 1)
	assert.True(t, ok)

	// новый version без тела: старое тело сбрасывается
	require.NoError(t, s.Put(entry("a", 2), nil))
	_, ok, _ = s.Body("a", 1)
	assert.False(t, ok)
	_, ok, _ = s.Body("a", 2)
	assert.False(t, ok)

	// новый version с телом
	b := sealed("v3")
	require.NoError(t, s.Put(entry("a", 3), &b))
	got, ok, err := s.Body("a", 3)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, b, got)
}

func TestStore_PutBody_UnknownID(t *testing.T) {
	s := mustOpen(t, t.TempDir())
	err := s.PutBody("ghost", 1, sealed("x"))
	require.Error(t, err)
}

func TestStore_HostileIDs(t *testing.T) {
	for _, id := range []string{"../x", "../../etc/passwd", "a/b", `a\b`, "a\x00b", ".."} {
		t.Run(id, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "cache")
			s := mustOpen(t, dir)
			require.NoError(t, s.Put(entry(id, 1), nil))
			require.NoError(t, s.PutBody(id, 1, sealed("x")))
			_, ok, err := s.Body(id, 1)
			require.NoError(t, err)
			assert.True(t, ok)
			require.NoError(t, s.Remove(id))

			require.NoError(t, s.Put(entry(id, 1), nil))
			require.NoError(t, s.PutBody(id, 1, sealed("x")))
			require.NoError(t, filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
				require.NoError(t, err)
				rel, err := filepath.Rel(dir, p)
				require.NoError(t, err)
				if p != root {
					assert.False(t, strings.HasPrefix(rel, ".."), "file %s escapes the cache dir", p)
				}
				return nil
			}))
		})
	}
}

func TestOpen_RemovesOrphanBodies(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir)
	require.NoError(t, s.Put(entry("a", 1), nil))
	require.NoError(t, s.PutBody("a", 1, sealed("x")))
	require.NoError(t, s.Put(entry("b", 1), nil))
	require.NoError(t, s.PutBody("b", 1, sealed("y")))

	orphan := filepath.Join(dir, bodiesDir, strings.Repeat("ab", 32))
	foreign := filepath.Join(dir, bodiesDir, "README.txt")
	require.NoError(t, os.WriteFile(orphan, []byte("{}"), 0o600))
	require.NoError(t, os.WriteFile(foreign, []byte("mine"), 0o600))
	// запись b исчезла из индекса, а файл тела остался (сбой между шагами)
	require.NoError(t, s.Remove("b"))
	require.NoError(t, os.WriteFile(filepath.Join(dir, bodiesDir, bodyName("b")), []byte("{}"), 0o600))

	_ = mustOpen(t, dir)

	_, err := os.Stat(orphan)
	assert.ErrorIs(t, err, fs.ErrNotExist)
	_, err = os.Stat(filepath.Join(dir, bodiesDir, bodyName("b")))
	assert.ErrorIs(t, err, fs.ErrNotExist)
	_, err = os.Stat(filepath.Join(dir, bodiesDir, bodyName("a")))
	assert.NoError(t, err)
	_, err = os.Stat(foreign)
	assert.NoError(t, err, "чужой файл не должен удаляться")
}

func TestOpen_MissingBodiesDir(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir)
	require.NoError(t, s.Put(entry("a", 1), nil))
	require.NoError(t, os.RemoveAll(filepath.Join(dir, bodiesDir)))

	s2 := mustOpen(t, dir)
	require.NoError(t, s2.PutBody("a", 1, sealed("x")))
}

func TestStore_Entries_Order(t *testing.T) {
	s := mustOpen(t, t.TempDir())
	for _, e := range []Entry{
		{ID: "z", Version: 1, Revision: 1, Header: domain.Header{Type: domain.TypeText, Name: "z"}},
		{ID: "local", Version: 1, Revision: 0, Header: domain.Header{Type: domain.TypeText, Name: "l"}},
		{ID: "b", Version: 1, Revision: 5, Header: domain.Header{Type: domain.TypeText, Name: "b"}},
	} {
		require.NoError(t, s.Put(e, nil))
	}
	var ids []string
	for _, e := range s.Entries() {
		ids = append(ids, e.ID)
	}
	assert.Equal(t, []string{"z", "b", "local"}, ids)
}

func TestStore_AtomicWrite(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("права на каталог не ограничивают запись")
	}
	dir := t.TempDir()
	s := mustOpen(t, dir)
	require.NoError(t, s.Put(entry("a", 1), nil))
	require.NoError(t, s.PutBody("a", 1, sealed("old")))

	bodies := filepath.Join(dir, bodiesDir)
	require.NoError(t, os.Chmod(bodies, 0o500))
	t.Cleanup(func() { _ = os.Chmod(bodies, 0o700) })

	require.Error(t, s.PutBody("a", 1, sealed("new")))

	require.NoError(t, os.Chmod(bodies, 0o700))
	got, ok, err := s.Body("a", 1)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, sealed("old"), got)
	files, _ := os.ReadDir(bodies)
	for _, f := range files {
		assert.False(t, strings.HasSuffix(f.Name(), ".tmp"), "остался временный файл %s", f.Name())
	}
}

func TestStore_Wipe_RemoveAll(t *testing.T) {
	dir := t.TempDir()
	session := filepath.Join(dir, "session.json")
	require.NoError(t, os.WriteFile(session, []byte("{}"), 0o600))
	s := mustOpen(t, dir)
	require.NoError(t, s.Put(entry("a", 1), nil))
	require.NoError(t, s.PutBody("a", 1, sealed("x")))

	require.NoError(t, s.Wipe())
	assert.Empty(t, s.Entries())

	require.NoError(t, s.Put(entry("a", 1), nil))
	require.NoError(t, RemoveAll(dir))
	_, err := os.Stat(filepath.Join(dir, indexFile))
	assert.ErrorIs(t, err, fs.ErrNotExist)
	_, err = os.Stat(filepath.Join(dir, bodiesDir))
	assert.ErrorIs(t, err, fs.ErrNotExist)
	_, err = os.Stat(session)
	assert.NoError(t, err, "RemoveAll не должен трогать файл сессии")

	// повторный вызов на чистом каталоге не ошибка
	assert.False(t, errors.Is(RemoveAll(dir), fs.ErrNotExist))
	require.NoError(t, RemoveAll(dir))
}

func rec(id string, version, revision int64, deleted bool) domain.Record {
	return domain.Record{
		ID: id, Version: version, Revision: revision, Deleted: deleted,
		Header: domain.Header{Type: domain.TypeText, Name: "n-" + id},
	}
}

func TestStore_Apply(t *testing.T) {
	seed := func(t *testing.T, s *Store) {
		t.Helper()
		require.NoError(t, s.Put(Entry{ID: "a", Version: 1, Revision: 1, Header: domain.Header{Type: domain.TypeText, Name: "old"}}, nil))
		require.NoError(t, s.PutBody("a", 1, sealed("a1")))
		require.NoError(t, s.Apply(1, nil))
	}
	tests := []struct {
		name       string
		recs       []domain.Record
		revision   int64
		wantErr    error
		wantIDs    []string
		wantRev    int64
		bodyOfA    int64 // версия, для которой тело a должно быть в кэше; 0 - тела нет
		wantAName  string
		skipSeeded bool
	}{
		{name: "add", recs: []domain.Record{rec("b", 1, 2, false)}, revision: 2, wantIDs: []string{"a", "b"}, wantRev: 2, bodyOfA: 1, wantAName: "old"},
		{name: "same version keeps body", recs: []domain.Record{rec("a", 1, 2, false)}, revision: 2, wantIDs: []string{"a"}, wantRev: 2, bodyOfA: 1, wantAName: "n-a"},
		{name: "new version drops body", recs: []domain.Record{rec("a", 2, 2, false)}, revision: 2, wantIDs: []string{"a"}, wantRev: 2, wantAName: "n-a"},
		{name: "tombstone removes record and body", recs: []domain.Record{rec("a", 2, 2, true)}, revision: 2, wantIDs: nil, wantRev: 2},
		{name: "tombstone of unknown id", recs: []domain.Record{rec("zzz", 1, 2, true)}, revision: 2, wantIDs: []string{"a"}, wantRev: 2, bodyOfA: 1, wantAName: "old"},
		{name: "same record twice", recs: []domain.Record{rec("b", 1, 2, false), rec("b", 1, 2, false)}, revision: 2, wantIDs: []string{"a", "b"}, wantRev: 2, bodyOfA: 1, wantAName: "old"},
		{name: "empty response advances revision", revision: 7, wantIDs: []string{"a"}, wantRev: 7, bodyOfA: 1, wantAName: "old"},
		{name: "revision regression", recs: []domain.Record{rec("b", 1, 2, false)}, revision: 0, wantErr: domain.ErrServerReset, wantIDs: []string{"a"}, wantRev: 1, bodyOfA: 1, wantAName: "old"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			s := mustOpen(t, dir)
			seed(t, s)

			err := s.Apply(tt.revision, tt.recs)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			// состояние должно пережить переоткрытие
			s = mustOpen(t, dir)

			var ids []string
			for _, e := range s.Entries() {
				ids = append(ids, e.ID)
			}
			assert.Equal(t, tt.wantIDs, ids)
			assert.Equal(t, tt.wantRev, s.LatestRevision())
			if tt.bodyOfA != 0 {
				_, ok, err := s.Body("a", tt.bodyOfA)
				require.NoError(t, err)
				assert.True(t, ok)
			}
			_, err = os.Stat(filepath.Join(dir, bodiesDir, bodyName("a")))
			assert.Equal(t, tt.bodyOfA != 0, err == nil, "файл тела a")
			if tt.wantAName != "" {
				a, _ := s.Lookup("a")
				assert.Equal(t, tt.wantAName, a.Header.Name)
			}
		})
	}
}

func TestStore_Apply_RevisionSetOnlyAfterAllApplied(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("права на каталог не ограничивают запись")
	}
	dir := t.TempDir()
	s := mustOpen(t, dir)
	require.NoError(t, s.Put(entry("a", 1), nil))
	require.NoError(t, s.PutBody("a", 1, sealed("x")))

	bodies := filepath.Join(dir, bodiesDir)
	require.NoError(t, os.Chmod(bodies, 0o500))
	t.Cleanup(func() { _ = os.Chmod(bodies, 0o700) })

	require.Error(t, s.Apply(5, []domain.Record{rec("a", 2, 5, true)}))
	assert.Zero(t, s.LatestRevision())
}

func TestStore_PutDoesNotTouchRevision(t *testing.T) {
	s := mustOpen(t, t.TempDir())
	require.NoError(t, s.Apply(4, nil))
	require.NoError(t, s.Put(entry("a", 2), nil))
	require.NoError(t, s.PutBody("a", 2, sealed("x")))
	require.NoError(t, s.Remove("a"))
	assert.EqualValues(t, 4, s.LatestRevision())
}
