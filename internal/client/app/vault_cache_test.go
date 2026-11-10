package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/cache"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/crypto"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
)

var ctx = context.Background()

// latest читает ревизию кэша напрямую, открывая его заново.
func (e *env) latest(t *testing.T) int64 {
	t.Helper()
	c, err := e.openCache(testAddr, testUserID)
	require.NoError(t, err)
	return c.LatestRevision()
}

func TestVault_Get_BodyServedFromCache(t *testing.T) {
	e := newEnv(t)
	id := mustAdd(t, e, textSecret("note", "v1"))

	_, err := e.v.Get(ctx, id, ReadOptions{})
	require.NoError(t, err)
	// тело, отправленное самим клиентом, уже в кэше: Get на сервер не ходил
	assert.Zero(t, e.srv.getCalls)

	// другой клиент обновил запись: версия в заголовке изменилась, тело надо скачать
	e.srv.mu.Lock()
	cur := e.srv.recs[id]
	other, err := e.v.seal(mustSealer(t), testUserID, id, textSecret("note", "v2"))
	require.NoError(t, err)
	e.srv.revision++
	e.srv.recs[id] = domain.Record{ID: id, Header: cur.Header, Body: other, Version: cur.Version + 1, Revision: e.srv.revision}
	e.srv.mu.Unlock()

	entry, err := e.v.Get(ctx, id, ReadOptions{})
	require.NoError(t, err)
	assert.Equal(t, domain.Text("v2"), entry.Secret.Content)
	assert.Equal(t, 1, e.srv.getCalls)

	_, err = e.v.Get(ctx, id, ReadOptions{})
	require.NoError(t, err)
	assert.Equal(t, 1, e.srv.getCalls, "второй Get берёт тело из кэша")
}

func mustSealer(t *testing.T) *crypto.Sealer {
	t.Helper()
	s, err := crypto.NewSealer(sessionFor(testAddr).EncKey)
	require.NoError(t, err)
	return s
}

func TestVault_Get_RefetchesBrokenCachedBody(t *testing.T) {
	e := newEnv(t)
	id := mustAdd(t, e, textSecret("note", "v1"))
	// портим файл тела так, что JSON остаётся валидным, а AEAD не проходит
	files, err := os.ReadDir(filepath.Join(e.cacheDir, "bodies"))
	require.NoError(t, err)
	require.Len(t, files, 1)
	path := filepath.Join(e.cacheDir, "bodies", files[0].Name())
	require.NoError(t, os.WriteFile(path, fmt.Appendf(nil, `{"version":1,"nonce":"%s","ciphertext":"AAAA"}`, "AAAAAAAAAAAAAAAA"), 0o600))

	entry, err := e.v.Get(ctx, id, ReadOptions{})
	require.NoError(t, err)
	assert.Equal(t, domain.Text("v1"), entry.Secret.Content)
	assert.Equal(t, 1, e.srv.getCalls)
}

func TestVault_Sync_UsesLatestRevision(t *testing.T) {
	e := newEnv(t)
	mustAdd(t, e, textSecret("a", "1"))

	_, err := e.v.ListChanges(ctx, ReadOptions{})
	require.NoError(t, err)
	_, err = e.v.ListChanges(ctx, ReadOptions{})
	require.NoError(t, err)

	assert.Equal(t, []int64{0, 1}, e.srv.sinces, "второй sync продолжает с ревизии первого")
	assert.Zero(t, e.srv.listCalls, "RPC List клиент не вызывает")
}

func TestVault_List_Filter(t *testing.T) {
	e := newEnv(t)
	withMeta := func(name string, typ domain.RecType, content domain.Content, meta ...domain.MetaItem) string {
		id, err := addOnly(e.v, ctx, domain.Secret{Header: domain.Header{Type: typ, Name: name, Meta: meta}, Content: content})
		require.NoError(t, err)
		return id
	}
	idGit := withMeta("GitHub", domain.TypeText, domain.Text("x"), domain.MetaItem{Key: "Env", Value: "prod"})
	idLab := withMeta("gitlab", domain.TypeLogin, domain.Login{Username: "u", Password: "p"})
	idBank := withMeta("bank", domain.TypeText, domain.Text("y"))
	gone := withMeta("git-old", domain.TypeText, domain.Text("z"))
	require.NoError(t, deleteOnly(e.v, ctx, gone))

	tests := []struct {
		name   string
		filter domain.Filter
		want   []string
	}{
		{"no filter", domain.Filter{}, []string{idGit, idLab, idBank}},
		{"name is case-insensitive substring", domain.Filter{NameFragment: "GIT"}, []string{idGit, idLab}},
		{"type", domain.Filter{Type: domain.TypeText}, []string{idGit, idBank}},
		{"meta key is exact and case-sensitive", domain.Filter{MetaKey: "Env"}, []string{idGit}},
		{"meta key other case", domain.Filter{MetaKey: "env"}, nil},
		{"filters are ANDed", domain.Filter{Type: domain.TypeText, NameFragment: "git"}, []string{idGit}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := e.v.List(ctx, tt.filter, ReadOptions{})
			require.NoError(t, err)
			var got []string
			for _, it := range res.Items {
				got = append(got, it.ID)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestVault_Resolve_NoListRPC(t *testing.T) {
	e := newEnv(t)
	id := mustAdd(t, e, textSecret("n", "1"))
	item, err := e.v.Resolve(ctx, "n", ReadOptions{})
	require.NoError(t, err)
	assert.Equal(t, id, item.ID)
	assert.Zero(t, e.srv.listCalls)
}

func TestVault_Writes_DoNotAdvanceRevision(t *testing.T) {
	e := newEnv(t)
	id := mustAdd(t, e, textSecret("n", "1"))
	assert.Zero(t, e.latest(t), "Add не двигает latestRevision")

	_, err := e.v.ListChanges(ctx, ReadOptions{})
	require.NoError(t, err)
	synced := e.latest(t)
	require.NotZero(t, synced)

	require.NoError(t, updateOnly(e.v, ctx, id, 1, textSecret("n", "2")))
	assert.Equal(t, synced, e.latest(t), "Update не двигает latestRevision")
	entry, err := e.v.Get(ctx, id, ReadOptions{Offline: true})
	require.NoError(t, err)
	assert.Equal(t, domain.Text("2"), entry.Secret.Content, "после Update свежее тело уже в кэше")
	assert.Equal(t, int64(2), entry.Version)

	// Delete сам делает sync перед разрешением ref, поэтому ждём ревизию сервера до удаления, а не после
	beforeDelete := e.srv.revision
	require.NoError(t, deleteOnly(e.v, ctx, id))
	assert.Equal(t, beforeDelete, e.latest(t), "Delete не двигает latestRevision")
	_, err = e.v.Resolve(ctx, id, ReadOptions{Offline: true})
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

// brokenCache — Cache, у которого запись всегда падает.
type brokenCache struct{ Cache }

func (brokenCache) Put(cache.Entry, *crypto.Sealed) error { return errors.New("disk full") }
func (brokenCache) Remove(string) error                   { return errors.New("disk full") }

func TestVault_Writes_CacheFailureIsWarning(t *testing.T) {
	e := newEnv(t)
	id := mustAdd(t, e, textSecret("n", "1"))
	_, err := e.v.ListChanges(ctx, ReadOptions{}) // sync, чтобы Delete смог разрешить ref
	require.NoError(t, err)

	realE := e.v.openCache
	e.v.openCache = func(a, u string) (Cache, error) {
		c, err := realE(a, u)
		return brokenCache{c}, err
	}

	_, w, err := e.v.Add(ctx, textSecret("m", "1"))
	require.NoError(t, err)
	assert.Len(t, w, 1)
	w, err = e.v.Update(ctx, id, 1, textSecret("n", "2"))
	require.NoError(t, err)
	assert.Len(t, w, 1)
	w, err = e.v.Delete(ctx, id)
	require.NoError(t, err)
	assert.Len(t, w, 1)
	assert.True(t, e.srv.recs[id].Deleted)
}

func TestVault_Writes_OpenCacheFailureIsWarning(t *testing.T) {
	e := newEnv(t)
	e.v.openCache = func(string, string) (Cache, error) { return nil, errors.New("no dir") }
	_, w, err := e.v.Add(ctx, textSecret("n", "1"))
	require.NoError(t, err)
	assert.Len(t, w, 1)
}

func TestVault_Fallback(t *testing.T) {
	tests := []struct {
		name      string
		netErr    error
		offline   bool
		expiredAt time.Duration // сдвиг ExpiresAt от now
		wantErr   error
		wantStale bool
		wantCalls int
	}{
		{name: "unavailable falls back", netErr: domain.ErrUnavailable, wantStale: true, wantCalls: 1},
		{name: "deadline mapped to unavailable falls back", netErr: fmt.Errorf("x: %w", domain.ErrUnavailable), wantStale: true, wantCalls: 1},
		{name: "session error is not masked", netErr: domain.ErrSessionExpired, wantErr: domain.ErrSessionExpired, wantCalls: 1},
		{name: "other error is not masked", netErr: errors.New("boom"), wantErr: errors.New("boom"), wantCalls: 1},
		{name: "offline makes no calls", offline: true, wantStale: true},
		{name: "offline works with expired token", offline: true, expiredAt: -time.Hour, wantStale: true},
		{name: "expired token without offline", expiredAt: -time.Hour, wantErr: domain.ErrSessionExpired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			id := mustAdd(t, e, textSecret("n", "1"))
			_, err := e.v.ListChanges(ctx, ReadOptions{}) // наполняем кэш
			require.NoError(t, err)
			before := e.srv.listChangesCalls
			e.srv.netErr = tt.netErr
			if tt.expiredAt != 0 {
				e.store.sess.ExpiresAt = time.Now().Add(tt.expiredAt)
			}
			ro := ReadOptions{Offline: tt.offline}

			list, lerr := e.v.List(ctx, domain.Filter{}, ro)
			entry, gerr := e.v.Get(ctx, "n", ro)

			if tt.wantErr != nil {
				require.Error(t, lerr)
				require.Error(t, gerr)
				if errors.Is(tt.wantErr, domain.ErrSessionExpired) {
					assert.ErrorIs(t, lerr, tt.wantErr)
					assert.ErrorIs(t, gerr, tt.wantErr)
				}
				return
			}
			require.NoError(t, lerr)
			require.NoError(t, gerr)
			assert.Equal(t, tt.wantStale, list.Stale)
			assert.Equal(t, tt.wantStale, entry.Stale)
			require.Len(t, list.Items, 1)
			assert.Equal(t, id, list.Items[0].ID)
			assert.Equal(t, domain.Text("1"), entry.Secret.Content)
			assert.Equal(t, tt.wantCalls*2, e.srv.listChangesCalls-before, "ListChanges вызван для list и get")
			if tt.offline {
				assert.Zero(t, e.srv.getCalls)
			}
		})
	}
}

func TestVault_Get_BodyNotCached(t *testing.T) {
	for _, tt := range []struct {
		name string
		ro   ReadOptions
		net  error
	}{
		{"offline", ReadOptions{Offline: true}, nil},
		{"unavailable", ReadOptions{}, domain.ErrUnavailable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			id := mustAdd(t, e, textSecret("n", "1"))
			// другой клиент записал заголовок новой версии: наше тело устарело
			e.srv.mu.Lock()
			rec := e.srv.recs[id]
			rec.Version++
			e.srv.revision++
			rec.Revision = e.srv.revision
			e.srv.recs[id] = rec
			e.srv.mu.Unlock()
			_, err := e.v.ListChanges(ctx, ReadOptions{}) // кэш узнаёт о новой версии, тела этой версии в нём нет
			require.NoError(t, err)
			e.srv.netErr = tt.net

			_, err = e.v.Get(ctx, id, tt.ro)
			assert.ErrorIs(t, err, domain.ErrBodyNotCached)
		})
	}
}

func TestVault_WritesNeverFallBack(t *testing.T) {
	e := newEnv(t)
	id := mustAdd(t, e, textSecret("n", "1"))
	_, err := e.v.ListChanges(ctx, ReadOptions{})
	require.NoError(t, err)
	e.srv.netErr = domain.ErrUnavailable

	_, _, err = e.v.Add(ctx, textSecret("m", "1"))
	assert.ErrorIs(t, err, domain.ErrUnavailable)
	_, err = e.v.Update(ctx, id, 1, textSecret("n", "2"))
	assert.ErrorIs(t, err, domain.ErrUnavailable)
	_, err = e.v.Delete(ctx, id)
	assert.ErrorIs(t, err, domain.ErrUnavailable)

	// кэш не изменился
	e.srv.netErr = nil
	entry, err := e.v.Get(ctx, id, ReadOptions{Offline: true})
	require.NoError(t, err)
	assert.Equal(t, domain.Text("1"), entry.Secret.Content)
}

func TestVault_ServerReset(t *testing.T) {
	e := newEnv(t)
	mustAdd(t, e, textSecret("old", "1"))
	mustAdd(t, e, textSecret("old2", "1"))
	_, err := e.v.ListChanges(ctx, ReadOptions{})
	require.NoError(t, err)

	// сервер восстановили с нуля: ревизия ниже закэшированной, записи другие
	e.srv.mu.Lock()
	e.srv.recs = map[string]domain.Record{}
	e.srv.revision = 0
	e.srv.mu.Unlock()
	id := mustAdd(t, e, textSecret("fresh", "1"))
	e.srv.sinces = nil

	res, err := e.v.ListChanges(ctx, ReadOptions{})
	require.NoError(t, err)
	require.Len(t, res.Items, 1)
	assert.Equal(t, id, res.Items[0].ID)
	assert.Equal(t, []int64{2, 0}, e.srv.sinces, "после сброса запрос повторяется с нуля")
}

func TestVault_CacheBoundToSessionUser(t *testing.T) {
	e := newEnv(t)
	mustAdd(t, e, textSecret("n", "1"))
	_, err := e.v.ListChanges(ctx, ReadOptions{})
	require.NoError(t, err)

	e.store.sess.UserID = "user-2"
	e.srv.mu.Lock()
	e.srv.recs = map[string]domain.Record{}
	e.srv.revision = 0
	e.srv.mu.Unlock()

	res, err := e.v.ListChanges(ctx, ReadOptions{Offline: true})
	require.NoError(t, err)
	assert.Empty(t, res.Items, "кэш другого пользователя не виден")
	assert.Equal(t, "user-2", e.opens[len(e.opens)-1])
}

func TestVault_CorruptIndexWarns(t *testing.T) {
	e := newEnv(t)
	mustAdd(t, e, textSecret("n", "1"))
	require.NoError(t, os.WriteFile(filepath.Join(e.cacheDir, "cache.json"), []byte("garbage"), 0o600))

	res, err := e.v.ListChanges(ctx, ReadOptions{})
	require.NoError(t, err)
	assert.Len(t, res.Items, 1, "кэш пересобран с сервера")
	assert.Len(t, res.Warnings, 1)
}

func TestVault_RequireOnline(t *testing.T) {
	e := newEnv(t)
	mustAdd(t, e, textSecret("n", "1"))
	_, err := e.v.ListChanges(ctx, ReadOptions{})
	require.NoError(t, err)
	e.srv.netErr = domain.ErrUnavailable

	_, err = e.v.Get(ctx, "n", ReadOptions{RequireOnline: true})
	assert.ErrorIs(t, err, domain.ErrUnavailable, "для записи кэш не подменяет сервер")
}
