package vault

import (
	"bytes"
	"context"
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
		ID:          id,
		Header:      []byte("header"),
		HeaderNonce: []byte("hn"),
		Body:        []byte("body"),
		BodyNonce:   []byte("bn"),
	}
}

func TestNoUserID(t *testing.T) {
	svc := newService(t)
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
	}{
		{"put", func() error { _, err := svc.Put(ctx, newRecord("r1")); return err }},
		{"delete", func() error { return svc.Delete(ctx, "r1", 1) }},
		{"get", func() error { _, err := svc.GetRecord(ctx, "r1"); return err }},
		{"list", func() error { _, _, err := svc.ListChanges(ctx, 0); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, tt.call(), domain.ErrNoUserID)
		})
	}
}

func TestPut_SizeLimits(t *testing.T) {
	tests := []struct {
		name   string
		header int
		body   int
		want   error
	}{
		{"default limits at the edge", 4 * 1024, 1024 * 1024, nil},
		{"header too large", 4*1024 + 1, 1, domain.ErrPayloadTooLarge},
		{"body too large", 1, 1024*1024 + 1, domain.ErrPayloadTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := newRecord("r1")
			rec.Header = bytes.Repeat([]byte("h"), tt.header)
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
		svc := newServiceLimits(t, 2, 3)
		rec := newRecord("r1")
		rec.Header, rec.Body = []byte("hh"), []byte("bbb")
		_, err := svc.Put(ctxOf("u1"), rec)
		assert.NoError(t, err)

		rec = newRecord("r2")
		rec.Header = []byte("hhh")
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
	assert.ErrorIs(t, svc.Delete(other, "r1", 1), domain.ErrNotFound)

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

	assert.ErrorIs(t, svc.Delete(ctx, "r1", created.Version+3), domain.ErrStaleVersion)
	assert.ErrorIs(t, svc.Delete(ctx, "nope", 1), domain.ErrNotFound)

	require.NoError(t, svc.Delete(ctx, "r1", created.Version))
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
	require.NoError(t, svc.Delete(ctx, "b", 1)) // revision 4

	t.Run("since 0 omits tombstones and bodies", func(t *testing.T) {
		got, rev, err := svc.ListChanges(ctx, 0)
		require.NoError(t, err)
		require.Len(t, got, 2)
		assert.Equal(t, int64(4), rev)
		for _, r := range got {
			assert.NotEqual(t, "b", r.ID)
			assert.False(t, r.Deleted)
			assert.Empty(t, r.Body)
			assert.NotEmpty(t, r.Header)
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
		{"empty header", func(r *domain.Record) { r.Header = nil }},
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

func TestNoUserID_EmptyUserID(t *testing.T) {
	svc := newService(t)
	ctx := ctxOf("")

	_, err := svc.Put(ctx, newRecord("r1"))
	assert.ErrorIs(t, err, domain.ErrNoUserID)
	assert.ErrorIs(t, svc.Delete(ctx, "r1", 1), domain.ErrNoUserID)
	_, err = svc.GetRecord(ctx, "r1")
	assert.ErrorIs(t, err, domain.ErrNoUserID)
	_, _, err = svc.ListChanges(ctx, 0)
	assert.ErrorIs(t, err, domain.ErrNoUserID)
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
