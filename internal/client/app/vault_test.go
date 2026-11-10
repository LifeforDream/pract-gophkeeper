package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/cache"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/crypto"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testBodyLimit = 1024

func sessionFor(addr string) session.Session {
	return session.Session{
		ServerAddr: addr,
		Login:      "alice",
		UserID:     testUserID,
		Token:      testToken,
		ExpiresAt:  time.Now().Add(time.Hour),
		EncKey:     bytes.Repeat([]byte{7}, crypto.KeySize),
	}
}

type env struct {
	v        *Vault
	srv      *fakeVault
	store    *memStore
	cacheDir string
	opens    []string // userID каждого открытия кэша
}

// openCache открывает настоящий кэш в каталоге теста и запоминает, для кого он открыт.
func (e *env) openCache(addr, userID string) (Cache, error) {
	e.opens = append(e.opens, userID)
	return cache.Open(e.cacheDir, addr, userID)
}

func newEnv(t *testing.T) *env {
	t.Helper()
	srv := newFakeVault()
	s := sessionFor(testAddr)
	store := &memStore{sess: &s}
	e := &env{srv: srv, store: store, cacheDir: t.TempDir()}
	v, err := NewVault(srv, store, e.openCache, testAddr, testBodyLimit)
	require.NoError(t, err)
	e.v = v
	return e
}

// dropCache стирает кэш, чтобы Get пошёл на сервер за телом.
func (e *env) dropCache(t *testing.T) {
	t.Helper()
	require.NoError(t, os.RemoveAll(e.cacheDir))
}

// addOnly, updateOnly и deleteOnly отбрасывают предупреждения: большинство тестов их не проверяет.
func addOnly(v *Vault, ctx context.Context, s domain.Secret) (string, error) {
	id, _, err := v.Add(ctx, s)
	return id, err
}

func updateOnly(v *Vault, ctx context.Context, id string, expected int64, s domain.Secret) error {
	_, err := v.Update(ctx, id, expected, s)
	return err
}

func deleteOnly(v *Vault, ctx context.Context, ref string) error {
	_, err := v.Delete(ctx, ref)
	return err
}

func textSecret(name, text string) domain.Secret {
	return domain.Secret{
		Header:  domain.Header{Type: domain.TypeText, Name: name},
		Content: domain.Text(text),
	}
}

func mustAdd(t *testing.T, e *env, s domain.Secret) string {
	t.Helper()
	id, err := addOnly(e.v, context.Background(), s)
	require.NoError(t, err)
	return id
}

func TestNewVault_BodySizeLimit(t *testing.T) {
	for _, tt := range []struct {
		limit   int
		wantErr bool
	}{{-1, true}, {0, true}, {1, false}, {DefaultBodySizeLimit(), false}} {
		_, err := NewVault(newFakeVault(), &memStore{}, nil, testAddr, tt.limit)
		assert.Equal(t, tt.wantErr, err != nil, "limit=%d", tt.limit)
	}
}

func TestVault_AddGet_RoundTrip(t *testing.T) {
	meta := []domain.MetaItem{{Key: "site", Value: "example.com"}, {Key: "k", Value: "v"}}
	tests := []struct {
		name   string
		secret domain.Secret
	}{
		{"login", domain.Secret{
			Header:  domain.Header{Type: domain.TypeLogin, Name: "mail", Meta: meta},
			Content: domain.Login{Username: "alice", Password: "hunter2-unique"},
		}},
		{"text", domain.Secret{
			Header:  domain.Header{Type: domain.TypeText, Name: "note", Meta: meta},
			Content: domain.Text("заметка"),
		}},
		{"binary", domain.Secret{
			Header:  domain.Header{Type: domain.TypeBinary, Name: "key", Meta: meta},
			Content: domain.Binary{Filename: "id.bin", Data: []byte{0, 1, 2, 3}},
		}},
		{"card", domain.Secret{
			Header:  domain.Header{Type: domain.TypeCard, Name: "visa", Meta: meta},
			Content: domain.Card{Number: "4111111111111111", Holder: "A B", Expiry: "01/30", CVV: "123"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			id := mustAdd(t, e, tt.secret)

			entry, err := e.v.Get(context.Background(), id, ReadOptions{})
			require.NoError(t, err)
			assert.Equal(t, id, entry.ID)
			assert.Equal(t, int64(1), entry.Version)
			assert.Equal(t, tt.secret, entry.Secret)
			assert.Equal(t, tt.secret.Header, entry.Header)
		})
	}
}

// TestVault_Add_ServerSeesHeaderButNotContent проверяет, что заголовок уходит на сервер открыто, а содержимое - только шифртекстом.
func TestVault_Add_ServerSeesHeaderButNotContent(t *testing.T) {
	e := newEnv(t)
	header := domain.Header{Type: domain.TypeLogin, Name: "visible-name-xyz", Meta: []domain.MetaItem{{Key: "url", Value: "example.com"}}}
	id := mustAdd(t, e, domain.Secret{
		Header:  header,
		Content: domain.Login{Username: "user-xyz", Password: "pass-xyz"},
	})

	rec := e.srv.recs[id]
	assert.Equal(t, header, rec.Header)
	for _, plain := range []string{"visible-name-xyz", "user-xyz", "pass-xyz"} {
		assert.NotContains(t, string(rec.Body.Ciphertext), plain)
	}
}

func TestVault_Add_GeneratesDistinctIDs(t *testing.T) {
	e := newEnv(t)
	a := mustAdd(t, e, textSecret("a", "1"))
	b := mustAdd(t, e, textSecret("a", "1"))
	assert.NotEmpty(t, a)
	assert.NotEqual(t, a, b)
}

func TestVault_Add_Failures(t *testing.T) {
	tooBig := domain.Secret{
		Header:  domain.Header{Type: domain.TypeBinary, Name: "big"},
		Content: domain.Binary{Filename: "f", Data: make([]byte, testBodyLimit+1)},
	}
	tests := []struct {
		name    string
		secret  domain.Secret
		prepare func(*env)
		wantErr error
	}{
		{"invalid secret", textSecret("", "x"), nil, domain.ErrInvalidData},
		{"binary over limit", tooBig, nil, domain.ErrTooLarge},
		{"no session", textSecret("n", "x"), func(e *env) { e.store.sess = nil }, domain.ErrNoSession},
		{"server mismatch", textSecret("n", "x"), func(e *env) { e.store.sess.ServerAddr = "other" }, domain.ErrServerMismatch},
		{"expired token", textSecret("n", "x"), func(e *env) { e.srv.token = "rotated" }, domain.ErrSessionExpired},
		{"session past exp, caught before the request", textSecret("n", "x"),
			func(e *env) { e.store.sess.ExpiresAt = time.Now().Add(-time.Minute) }, domain.ErrSessionExpired},
		{"session without exp", textSecret("n", "x"),
			func(e *env) { e.store.sess.ExpiresAt = time.Time{} }, domain.ErrSessionExpired},
		{"short enc key", textSecret("n", "x"), func(e *env) { e.store.sess.EncKey = []byte{1} }, crypto.ErrInvalidKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			if tt.prepare != nil {
				tt.prepare(e)
			}
			_, err := addOnly(e.v, context.Background(), tt.secret)
			assert.ErrorIs(t, err, tt.wantErr)
			assert.Empty(t, e.srv.recs, "на сервер ничего не должно попасть")
		})
	}
}

func TestVault_ListChanges(t *testing.T) {
	e := newEnv(t)
	idA := mustAdd(t, e, textSecret("a", "1"))
	idB := mustAdd(t, e, textSecret("b", "2"))

	res, err := e.v.ListChanges(context.Background(), ReadOptions{})
	require.NoError(t, err)

	names := map[string]string{}
	for _, it := range res.Items {
		names[it.ID] = it.Header.Name
		assert.Equal(t, int64(1), it.Version)
	}
	assert.Equal(t, map[string]string{idA: "a", idB: "b"}, names)
}

func TestVault_ListChanges_OmitsDeleted(t *testing.T) {
	e := newEnv(t)
	id := mustAdd(t, e, textSecret("gone", "1"))
	require.NoError(t, deleteOnly(e.v, context.Background(), id))

	res, err := e.v.ListChanges(context.Background(), ReadOptions{})
	require.NoError(t, err)
	assert.Empty(t, res.Items)
}

func TestVault_List_ServerError(t *testing.T) {
	e := newEnv(t)
	e.srv.token = "rotated"
	_, err := e.v.List(context.Background(), domain.Filter{}, ReadOptions{})
	assert.ErrorIs(t, err, domain.ErrSessionExpired)
}

func TestVault_ListChanges_ServerError(t *testing.T) {
	e := newEnv(t)
	e.srv.token = "rotated"
	_, err := e.v.ListChanges(context.Background(), ReadOptions{})
	assert.ErrorIs(t, err, domain.ErrSessionExpired)
}

func TestVault_Resolve(t *testing.T) {
	e := newEnv(t)
	idUnique := mustAdd(t, e, textSecret("unique", "1"))
	idDup1 := mustAdd(t, e, textSecret("dup", "1"))
	idDup2 := mustAdd(t, e, textSecret("dup", "2"))
	// имя второй записи совпадает с id первой: id должен победить
	idTricky := mustAdd(t, e, textSecret(idUnique, "3"))

	tests := []struct {
		name     string
		ref      string
		wantID   string
		wantErr  error
		wantAmbi []string
	}{
		{name: "by id", ref: idDup1, wantID: idDup1},
		{name: "by unique name", ref: "unique", wantID: idUnique},
		{name: "id wins over name", ref: idUnique, wantID: idUnique},
		{name: "name equal to another id is still resolvable by id", ref: idTricky, wantID: idTricky},
		{name: "name is case sensitive", ref: "UNIQUE", wantErr: domain.ErrNotFound},
		{name: "not a substring match", ref: "uniq", wantErr: domain.ErrNotFound},
		{name: "regexp is not interpreted", ref: "uni.*", wantErr: domain.ErrNotFound},
		{name: "empty ref", ref: "", wantErr: domain.ErrNotFound},
		{name: "ambiguous", ref: "dup", wantAmbi: []string{idDup1, idDup2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item, err := e.v.Resolve(context.Background(), tt.ref, ReadOptions{})
			switch {
			case tt.wantAmbi != nil:
				var amb *AmbiguousError
				require.ErrorAs(t, err, &amb)
				got := append([]string(nil), amb.IDs...)
				sort.Strings(got)
				want := append([]string(nil), tt.wantAmbi...)
				sort.Strings(want)
				assert.Equal(t, want, got)
				assert.Equal(t, tt.ref, amb.Name)
			case tt.wantErr != nil:
				assert.ErrorIs(t, err, tt.wantErr)
			default:
				require.NoError(t, err)
				assert.Equal(t, tt.wantID, item.ID)
			}
		})
	}
}

func TestVault_Get_ByName(t *testing.T) {
	e := newEnv(t)
	id := mustAdd(t, e, textSecret("by-name", "hello"))

	entry, err := e.v.Get(context.Background(), "by-name", ReadOptions{})
	require.NoError(t, err)
	assert.Equal(t, id, entry.ID)
	assert.Equal(t, domain.Text("hello"), entry.Secret.Content)
}

func TestVault_Get_Failures(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		e := newEnv(t)
		_, err := e.v.Get(context.Background(), "nope", ReadOptions{})
		assert.ErrorIs(t, err, domain.ErrNotFound)
	})
	t.Run("body swapped between records is caught by AAD", func(t *testing.T) {
		e := newEnv(t)
		idA := mustAdd(t, e, textSecret("a", "1"))
		idB := mustAdd(t, e, textSecret("b", "2"))
		recA := e.srv.recs[idA]
		recA.Body = e.srv.recs[idB].Body
		e.srv.recs[idA] = recA
		e.dropCache(t)

		_, err := e.v.Get(context.Background(), idA, ReadOptions{})
		assert.ErrorIs(t, err, crypto.ErrDecrypt)
	})
	t.Run("flipped bit in body", func(t *testing.T) {
		e := newEnv(t)
		id := mustAdd(t, e, textSecret("a", "1"))
		rec := e.srv.recs[id]
		rec.Body.Ciphertext = append([]byte(nil), rec.Body.Ciphertext...)
		rec.Body.Ciphertext[0] ^= 1
		e.srv.recs[id] = rec
		e.dropCache(t)

		_, err := e.v.Get(context.Background(), id, ReadOptions{})
		assert.ErrorIs(t, err, crypto.ErrDecrypt)
	})
	t.Run("other user's session cannot open", func(t *testing.T) {
		e := newEnv(t)
		id := mustAdd(t, e, textSecret("a", "1"))
		e.store.sess.UserID = "user-2" // тот же ключ, другой user_id в AAD

		_, err := e.v.Get(context.Background(), id, ReadOptions{})
		assert.Error(t, err)
	})
	t.Run("expired token", func(t *testing.T) {
		e := newEnv(t)
		id := mustAdd(t, e, textSecret("a", "1"))
		e.srv.token = "rotated"
		_, err := e.v.Get(context.Background(), id, ReadOptions{})
		assert.ErrorIs(t, err, domain.ErrSessionExpired)
	})
}

func TestVault_Update(t *testing.T) {
	e := newEnv(t)
	id := mustAdd(t, e, textSecret("note", "v1"))

	require.NoError(t, updateOnly(e.v, context.Background(), id, 1, textSecret("note", "v2")))

	entry, err := e.v.Get(context.Background(), id, ReadOptions{})
	require.NoError(t, err)
	assert.Equal(t, int64(2), entry.Version)
	assert.Equal(t, domain.Text("v2"), entry.Secret.Content)
}

func TestVault_Update_CanRename(t *testing.T) {
	e := newEnv(t)
	id := mustAdd(t, e, textSecret("old", "v1"))
	require.NoError(t, updateOnly(e.v, context.Background(), id, 1, textSecret("new", "v1")))

	_, err := e.v.Resolve(context.Background(), "old", ReadOptions{})
	assert.ErrorIs(t, err, domain.ErrNotFound)
	item, err := e.v.Resolve(context.Background(), "new", ReadOptions{})
	require.NoError(t, err)
	assert.Equal(t, id, item.ID)
}

func TestVault_Update_Failures(t *testing.T) {
	tooBig := domain.Secret{
		Header:  domain.Header{Type: domain.TypeBinary, Name: "big"},
		Content: domain.Binary{Data: make([]byte, testBodyLimit+1)},
	}
	tests := []struct {
		name     string
		bump     bool   // другой клиент уже обновил запись до версии 2
		id       string // "" — взять id созданной записи
		expected int64
		secret   domain.Secret
		wantPuts int // сколько раз запрос дошёл до сервера: отказ сервера — 1, отказ на клиенте — 0
		wantErr  error
	}{
		{name: "stale expected version", bump: true, expected: 1, secret: textSecret("n", "x"), wantPuts: 1, wantErr: domain.ErrConflict},
		{name: "expected from the future", expected: 5, secret: textSecret("n", "x"), wantPuts: 1, wantErr: domain.ErrConflict},
		{name: "unknown id", id: "nope", expected: 1, secret: textSecret("n", "x"), wantPuts: 1, wantErr: domain.ErrNotFound},
		{name: "invalid secret", expected: 1, secret: textSecret("", "x"), wantErr: domain.ErrInvalidData},
		{name: "binary over limit", expected: 1, secret: tooBig, wantErr: domain.ErrTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			id := mustAdd(t, e, textSecret("n", "v1"))
			if tt.bump {
				require.NoError(t, updateOnly(e.v, context.Background(), id, 1, textSecret("n", "other-client")))
			}
			if tt.id != "" {
				id = tt.id
			}
			before := e.srv.putCalls

			err := updateOnly(e.v, context.Background(), id, tt.expected, tt.secret)
			assert.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, before+tt.wantPuts, e.srv.putCalls)
		})
	}
}

func TestVault_Update_PreservesOtherClientsData(t *testing.T) {
	e := newEnv(t)
	id := mustAdd(t, e, textSecret("n", "v1"))
	require.NoError(t, updateOnly(e.v, context.Background(), id, 1, textSecret("n", "other-client")))

	err := updateOnly(e.v, context.Background(), id, 1, textSecret("n", "mine"))
	require.ErrorIs(t, err, domain.ErrConflict)

	entry, err := e.v.Get(context.Background(), id, ReadOptions{})
	require.NoError(t, err)
	assert.Equal(t, domain.Text("other-client"), entry.Secret.Content)
}

func TestVault_Delete(t *testing.T) {
	e := newEnv(t)
	idByName := mustAdd(t, e, textSecret("by-name", "1"))
	idByID := mustAdd(t, e, textSecret("by-id", "2"))

	require.NoError(t, deleteOnly(e.v, context.Background(), "by-name"))
	require.NoError(t, deleteOnly(e.v, context.Background(), idByID))

	assert.True(t, e.srv.recs[idByName].Deleted)
	assert.True(t, e.srv.recs[idByID].Deleted)
	res, err := e.v.ListChanges(context.Background(), ReadOptions{})
	require.NoError(t, err)
	assert.Empty(t, res.Items)

	_, err = e.v.Get(context.Background(), idByID, ReadOptions{})
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestVault_Delete_UsesVersionFromList(t *testing.T) {
	e := newEnv(t)
	id := mustAdd(t, e, textSecret("n", "v1"))
	require.NoError(t, updateOnly(e.v, context.Background(), id, 1, textSecret("n", "v2")))

	// fakeVault.Delete проверяет expected_version == текущей версии
	require.NoError(t, deleteOnly(e.v, context.Background(), id))
}

func TestVault_Delete_Failures(t *testing.T) {
	e := newEnv(t)
	mustAdd(t, e, textSecret("dup", "1"))
	mustAdd(t, e, textSecret("dup", "2"))

	err := deleteOnly(e.v, context.Background(), "nope")
	assert.ErrorIs(t, err, domain.ErrNotFound)

	var amb *AmbiguousError
	assert.ErrorAs(t, deleteOnly(e.v, context.Background(), "dup"), &amb)
	for _, r := range e.srv.recs {
		assert.False(t, r.Deleted, "при неоднозначности ничего не удаляется")
	}

	e.store.sess = nil
	assert.ErrorIs(t, deleteOnly(e.v, context.Background(), "dup"), domain.ErrNoSession)
}

func TestSealBody(t *testing.T) {
	sl, err := crypto.NewSealer(bytes.Repeat([]byte{1}, crypto.KeySize))
	require.NoError(t, err)
	s := textSecret("name", "body")
	v := newEnv(t).v

	body, err := v.seal(sl, "u", "rec", s)
	require.NoError(t, err)

	bb, err := sl.Open("u", "rec", crypto.PartBody, body)
	require.NoError(t, err)
	got, err := domain.Unmarshal(s.Header, bb)
	require.NoError(t, err)
	assert.Equal(t, s, got)

	tests := []struct {
		name           string
		userID, record string
	}{
		{"wrong user", "other", "rec"},
		{"wrong record id", "u", "other"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sl.Open(tt.userID, tt.record, crypto.PartBody, body)
			assert.ErrorIs(t, err, crypto.ErrDecrypt)
		})
	}
}

func TestSeal_InvalidSecret(t *testing.T) {
	sl, err := crypto.NewSealer(bytes.Repeat([]byte{1}, crypto.KeySize))
	require.NoError(t, err)
	_, err = newEnv(t).v.seal(sl, "u", "rec", textSecret("", "x"))
	assert.ErrorIs(t, err, domain.ErrInvalidData)
}

// TestVault_Add_LimitAppliesToSealedBody проверяет, что лимит относится к зашифрованному телу (как на сервере)
// и не зависит от типа секрета: растим текст, пока Add не откажет, и сверяем границу.
func TestVault_Add_LimitAppliesToSealedBody(t *testing.T) {
	e := newEnv(t)
	// кэш здесь не проверяется, а fsync на каждом из ~1000 Add делает тест очень медленным
	e.v.openCache = func(string, string) (Cache, error) { return nil, errors.New("cache disabled in this test") }
	var lastOK string
	for n := 1; n <= testBodyLimit+1; n++ {
		id, err := addOnly(e.v, context.Background(), textSecret("n", strings.Repeat("x", n)))
		if err != nil {
			require.ErrorIs(t, err, domain.ErrTooLarge)
			require.NotEmpty(t, lastOK, "отказ уже на первом размере")
			assert.Len(t, e.srv.recs[lastOK].Body.Ciphertext, testBodyLimit, "последний принятый шифртекст ровно в лимит")
			return
		}
		lastOK = id
	}
	t.Fatal("Add не отказал, хотя текст превысил лимит")
}
