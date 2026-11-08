package vault

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/LifeforDream/pract-gophkeeper/internal/server/domain"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/repository/memory"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/userid"
)

func newService(t *testing.T) *Service {
	t.Helper()
	return newServiceLimits(t, DefaultHeaderSizeLimit(), DefaultBodySizeLimit())
}

func newServiceLimits(t *testing.T, header, body int) *Service {
	t.Helper()
	svc, err := NewService(memory.NewRecordsRepo(), header, body)
	require.NoError(t, err)
	return svc
}

func ctxOf(user string) context.Context {
	return userid.NewContext(context.Background(), user)
}

func newRecord(id string) domain.Record {
	return domain.Record{
		ID:        id,
		Type:      domain.TypeLogin,
		Name:      "name",
		Meta:      []domain.MetaItem{{Key: "k", Value: "v"}},
		Body:      []byte("body"),
		BodyNonce: []byte("bn"),
	}
}

// TestNoUserID проверяет, что без user_id в контексте (или с пустым) отказывают все методы.
func TestNoUserID(t *testing.T) {
	svc := newService(t)

	contexts := []struct {
		name string
		ctx  context.Context
	}{
		{"missing", context.Background()},
		{"empty", ctxOf("")},
	}
	calls := []struct {
		name string
		call func(ctx context.Context) error
	}{
		{"put", func(ctx context.Context) error { _, err := svc.Put(ctx, newRecord("r1")); return err }},
		{"delete", func(ctx context.Context) error { _, err := svc.Delete(ctx, "r1", 1); return err }},
		{"get", func(ctx context.Context) error { _, err := svc.GetRecord(ctx, "r1"); return err }},
		{"list changes", func(ctx context.Context) error { _, _, err := svc.ListChanges(ctx, 0); return err }},
		{"list", func(ctx context.Context) error { _, err := svc.List(ctx, domain.Filter{}); return err }},
	}
	for _, c := range contexts {
		for _, tt := range calls {
			t.Run(c.name+"/"+tt.name, func(t *testing.T) {
				assert.ErrorIs(t, tt.call(c.ctx), domain.ErrNoUserID)
			})
		}
	}
}

func TestPut_SizeLimits(t *testing.T) {
	tests := []struct {
		name   string
		header int // размер заголовка: тип + имя (метаданных нет)
		body   int
		want   error
	}{
		{"default limits at the edge", 4 * 1024, 1024 * 1024, nil},
		{"header too large", 4*1024 + 1, 1, domain.ErrPayloadTooLarge},
		{"body too large", 10, 1024*1024 + 1, domain.ErrPayloadTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := newRecord("r1")
			rec.Meta = nil
			rec.Name = strings.Repeat("h", tt.header-len(rec.Type))
			rec.Body = bytes.Repeat([]byte("b"), tt.body)
			_, err := newService(t).Put(ctxOf("u1"), rec)
			if tt.want == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tt.want)
			}
		})
	}

	t.Run("custom limits", func(t *testing.T) {
		svc := newServiceLimits(t, 10, 3)
		rec := newRecord("r1") // тип "login" (5) + имя (5) = 10
		rec.Meta = nil
		rec.Name, rec.Body = "hhhhh", []byte("bbb")
		_, err := svc.Put(ctxOf("u1"), rec)
		assert.NoError(t, err)

		rec = newRecord("r2")
		rec.Meta = nil
		rec.Name = "hhhhhh"
		_, err = svc.Put(ctxOf("u1"), rec)
		assert.ErrorIs(t, err, domain.ErrPayloadTooLarge)

		rec = newRecord("r3") // метаданные тоже входят в размер заголовка
		rec.Name = "h"
		rec.Meta = []domain.MetaItem{{Key: "kkkkk", Value: "v"}}
		_, err = svc.Put(ctxOf("u1"), rec)
		assert.ErrorIs(t, err, domain.ErrPayloadTooLarge)
	})

	t.Run("rejected record is not stored", func(t *testing.T) {
		svc := newServiceLimits(t, DefaultHeaderSizeLimit(), 1)
		_, err := svc.Put(ctxOf("u1"), newRecord("r1"))
		require.ErrorIs(t, err, domain.ErrPayloadTooLarge)
		_, err = svc.GetRecord(ctxOf("u1"), "r1")
		assert.ErrorIs(t, err, domain.ErrNotFound)
	})
}

func TestPut_CreateAndUpdate(t *testing.T) {
	svc := newService(t)
	ctx := ctxOf("u1")

	created, err := svc.Put(ctx, newRecord("r1"))
	require.NoError(t, err)
	assert.Equal(t, int64(1), created.Version)
	assert.Equal(t, "u1", created.UserID)

	upd := newRecord("r1")
	upd.Version = created.Version
	upd.Body = []byte("new-body")
	updated, err := svc.Put(ctx, upd)
	require.NoError(t, err)
	assert.Equal(t, int64(2), updated.Version)
	assert.Greater(t, updated.Revision, created.Revision)

	got, err := svc.GetRecord(ctx, "r1")
	require.NoError(t, err)
	assert.Equal(t, []byte("new-body"), got.Body)
}

func TestPut_Errors(t *testing.T) {
	svc := newService(t)
	ctx := ctxOf("u1")
	_, err := svc.Put(ctx, newRecord("r1"))
	require.NoError(t, err)

	tests := []struct {
		name    string
		id      string
		version int64
		want    error
	}{
		{"create existing id", "r1", 0, domain.ErrConflict},
		{"stale version", "r1", 5, domain.ErrStaleVersion},
		{"update missing", "nope", 1, domain.ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := newRecord(tt.id)
			rec.Version = tt.version
			_, err := svc.Put(ctx, rec)
			assert.ErrorIs(t, err, tt.want)
		})
	}
}

func TestPut_UserIDComesFromContext(t *testing.T) {
	svc := newService(t)

	rec := newRecord("r1")
	rec.UserID = "victim"
	created, err := svc.Put(ctxOf("attacker"), rec)
	require.NoError(t, err)
	assert.Equal(t, "attacker", created.UserID)

	_, err = svc.GetRecord(ctxOf("victim"), "r1")
	assert.ErrorIs(t, err, domain.ErrNotFound)
	got, _, err := svc.ListChanges(ctxOf("victim"), 0)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestUserIsolation(t *testing.T) {
	svc := newService(t)
	_, err := svc.Put(ctxOf("u1"), newRecord("r1"))
	require.NoError(t, err)
	other := ctxOf("u2")

	_, err = svc.GetRecord(other, "r1")
	assert.ErrorIs(t, err, domain.ErrNotFound)

	_, err = svc.Delete(other, "r1", 1)
	assert.ErrorIs(t, err, domain.ErrNotFound)

	upd := newRecord("r1")
	upd.Version = 1
	_, err = svc.Put(other, upd)
	assert.ErrorIs(t, err, domain.ErrNotFound)

	// запись владельца не пострадала
	got, err := svc.GetRecord(ctxOf("u1"), "r1")
	require.NoError(t, err)
	assert.False(t, got.Deleted)
	assert.Equal(t, int64(1), got.Version)
}

func TestDelete(t *testing.T) {
	svc := newService(t)
	ctx := ctxOf("u1")
	created, err := svc.Put(ctx, newRecord("r1"))
	require.NoError(t, err)

	_, err = svc.Delete(ctx, "r1", created.Version+3)
	assert.ErrorIs(t, err, domain.ErrStaleVersion)

	_, err = svc.Delete(ctx, "nope", 1)
	assert.ErrorIs(t, err, domain.ErrNotFound)

	_, err = svc.Delete(ctx, "r1", created.Version)
	require.NoError(t, err)
	// Get не отдаёт надгробие; его состояние видно только через ListChanges.
	_, err = svc.GetRecord(ctx, "r1")
	assert.ErrorIs(t, err, domain.ErrNotFound)
	tombstones, _, err := svc.ListChanges(ctx, created.Revision)
	require.NoError(t, err)
	require.Len(t, tombstones, 1)
	assert.True(t, tombstones[0].Deleted)
	assert.Equal(t, created.Version+1, tombstones[0].Version)

	// Обновить удалённую запись нельзя.
	upd := newRecord("r1")
	upd.Version = tombstones[0].Version
	_, err = svc.Put(ctx, upd)
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestListChanges(t *testing.T) {
	svc := newService(t)
	ctx := ctxOf("u1")
	for _, id := range []string{"a", "b", "c"} {
		_, err := svc.Put(ctx, newRecord(id))
		require.NoError(t, err)
	}
	_, err := svc.Delete(ctx, "b", 1)
	require.NoError(t, err) // revision 4

	t.Run("since 0 omits tombstones and bodies", func(t *testing.T) {
		got, rev, err := svc.ListChanges(ctx, 0)
		require.NoError(t, err)
		require.Len(t, got, 2)
		assert.Equal(t, int64(4), rev)
		for _, r := range got {
			assert.NotEqual(t, "b", r.ID)
			assert.False(t, r.Deleted)
			assert.Empty(t, r.Body)
			assert.NotEmpty(t, r.Name)
			assert.Equal(t, newRecord(r.ID).Meta, r.Meta)
		}
	})

	t.Run("since revision includes tombstones", func(t *testing.T) {
		got, rev, err := svc.ListChanges(ctx, 3)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, int64(4), rev)
		assert.Equal(t, "b", got[0].ID)
		assert.True(t, got[0].Deleted)
	})

	t.Run("nothing new", func(t *testing.T) {
		got, rev, err := svc.ListChanges(ctx, 4)
		assert.Equal(t, int64(4), rev)
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("other user sees nothing", func(t *testing.T) {
		got, rev, err := svc.ListChanges(ctxOf("u2"), 0)
		require.NoError(t, err)
		assert.Equal(t, int64(0), rev)
		assert.Empty(t, got)
	})
}

func TestPut_ConcurrentUpdatesSingleWinner(t *testing.T) {
	svc := newService(t)
	ctx := ctxOf("u1")
	_, err := svc.Put(ctx, newRecord("r1"))
	require.NoError(t, err)

	const workers = 50
	var (
		wg        sync.WaitGroup
		wins      atomic.Int32
		conflicts atomic.Int32
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			upd := newRecord("r1")
			upd.Version = 1
			_, err := svc.Put(ctx, upd)
			switch {
			case err == nil:
				wins.Add(1)
			case assert.ErrorIs(t, err, domain.ErrStaleVersion):
				conflicts.Add(1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), wins.Load())
	assert.Equal(t, int32(workers-1), conflicts.Load())
}

func TestPut_InvalidArgument(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(r *domain.Record)
	}{
		{"empty id", func(r *domain.Record) { r.ID = "" }},
		{"empty name", func(r *domain.Record) { r.Name = "" }},
		{"unknown type", func(r *domain.Record) { r.Type = "bogus" }},
		{"empty type", func(r *domain.Record) { r.Type = "" }},
		{"too long id", func(r *domain.Record) { r.ID = strings.Repeat("i", 37) }},
		{"too long meta key", func(r *domain.Record) { r.Meta = []domain.MetaItem{{Key: strings.Repeat("k", 256), Value: "v"}} }},
		{"empty meta key", func(r *domain.Record) { r.Meta = []domain.MetaItem{{Key: "", Value: "v"}} }},
		{"duplicate meta key", func(r *domain.Record) {
			r.Meta = []domain.MetaItem{{Key: "k", Value: "1"}, {Key: "k", Value: "2"}}
		}},
		{"empty body", func(r *domain.Record) { r.Body = nil }},
		{"negative version", func(r *domain.Record) { r.Version = -1 }},
		{"deleted flag", func(r *domain.Record) { r.Deleted = true }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newService(t)
			rec := newRecord("r1")
			tt.mutate(&rec)

			_, err := svc.Put(ctxOf("u1"), rec)
			assert.ErrorIs(t, err, domain.ErrInvalidArgument)

			// Отклонённая запись не должна попасть в хранилище.
			_, err = svc.GetRecord(ctxOf("u1"), "r1")
			assert.ErrorIs(t, err, domain.ErrNotFound)
		})
	}
}

func TestNewService_InvalidLimits(t *testing.T) {
	tests := []struct {
		name         string
		header, body int
	}{
		{"zero header", 0, 1},
		{"zero body", 1, 0},
		{"negative header", -1, 1},
		{"negative body", 1, -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewService(memory.NewRecordsRepo(), tt.header, tt.body)
			assert.Error(t, err)
		})
	}
}

func TestPut_MetaSortedByKey(t *testing.T) {
	svc := newService(t)
	rec := newRecord("r1")
	rec.Meta = []domain.MetaItem{{Key: "b", Value: "2"}, {Key: "a", Value: "1"}}
	input := slices.Clone(rec.Meta)

	_, err := svc.Put(ctxOf("u1"), rec)
	require.NoError(t, err)

	got, err := svc.GetRecord(ctxOf("u1"), "r1")
	require.NoError(t, err)
	assert.Equal(t, []domain.MetaItem{{Key: "a", Value: "1"}, {Key: "b", Value: "2"}}, got.Meta)
	assert.Equal(t, input, rec.Meta, "срез вызывающего не должен меняться")
}

func TestList_InvalidFilter(t *testing.T) {
	tests := []struct {
		name   string
		filter domain.Filter
	}{
		{"unknown type", domain.Filter{Type: "bogus"}},
		{"too long meta key", domain.Filter{MetaKey: strings.Repeat("k", 256)}},
		{"too long name fragment", domain.Filter{NameFragment: strings.Repeat("n", DefaultHeaderSizeLimit()+1)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newService(t).List(ctxOf("u1"), tt.filter)
			assert.ErrorIs(t, err, domain.ErrInvalidArgument)
		})
	}
}

func TestList(t *testing.T) {
	svc := newService(t)
	ctx := ctxOf("u1")
	a := newRecord("a")
	a.Name = "GitHub"
	b := newRecord("b")
	b.Type = domain.TypeText
	for _, r := range []domain.Record{a, b} {
		_, err := svc.Put(ctx, r)
		require.NoError(t, err)
	}
	b, err := svc.GetRecord(ctx, "b")
	require.NoError(t, err)
	_, err = svc.Delete(ctx, "b", b.Version)
	require.NoError(t, err)

	got, err := svc.List(ctx, domain.Filter{})
	require.NoError(t, err)
	require.Len(t, got, 1, "надгробия не попадают в выдачу")
	assert.Equal(t, "a", got[0].ID)
	assert.Empty(t, got[0].Body)

	got, err = svc.List(ctx, domain.Filter{Type: domain.TypeLogin, MetaKey: "k", NameFragment: "hub"})
	require.NoError(t, err)
	assert.Len(t, got, 1)

	got, err = svc.List(ctxOf("u2"), domain.Filter{})
	require.NoError(t, err)
	assert.NotNil(t, got)
	assert.Empty(t, got)
}
