// Package repotest содержит общий контрактный набор тестов для реализаций репозитория записей.
// Один и тот же набор запускается против всех бэкендов (memory, postgres).
package repotest

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/LifeforDream/pract-gophkeeper/internal/server/domain"
)

// RecordsRepo описывает контракт репозитория записей, который проверяет набор тестов.
type RecordsRepo interface {
	Create(context.Context, domain.Record) (domain.Record, error)
	Update(context.Context, domain.Record) (domain.Record, error)
	Delete(ctx context.Context, userID, recordID string, expectedVersion int64) error
	Get(ctx context.Context, userID, recordID string) (domain.Record, error)
	List(ctx context.Context, userID string, sinceRevision int64) ([]domain.Record, int64, error)
}

// RecordsFactory создаёт чистый (пустой) репозиторий для каждого теста.
type RecordsFactory func(t *testing.T) RecordsRepo

// RunRecords запускает контрактный набор тестов против репозитория, созданного factory.
//
// Контракт версий: Create сохраняет запись с Version = 1; Update получает в record.Version
// ОЖИДАЕМУЮ версию, принимает её только при точном совпадении с сохранённой и сохраняет запись
// с версией на единицу больше; Delete работает так же и увеличивает версию на единицу.
func RunRecords(t *testing.T, factory RecordsFactory) {
	tests := []struct {
		name string
		run  func(t *testing.T, repo RecordsRepo)
	}{
		{"create sets version and revision", testCreate},
		{"create duplicate id", testCreateDuplicate},
		{"revisions are per user", testRevisionPerUser},
		{"same record id for different users", testSameIDDifferentUsers},
		{"input slices are copied", testInputCopies},
		{"update", testUpdate},
		{"update version mismatch", testUpdateVersionMismatch},
		{"update missing and foreign", testUpdateNotFound},
		{"update tombstone", testUpdateDeleted},
		{"delete", testDelete},
		{"delete version mismatch", testDeleteVersionMismatch},
		{"delete missing and foreign", testDeleteNotFound},
		{"delete is idempotent", testDeleteIdempotent},
		{"tombstone keeps header, drops body", testTombstoneKeepsHeader},
		{"get missing and foreign", testGetNotFound},
		{"list", testList},
		{"list is scoped by user", testListScoped},
		{"list empty", testListEmpty},
		{"concurrent creates give unique revisions", testConcurrentCreates},
		{"concurrent updates: single winner", testConcurrentUpdates},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.run(t, factory(t))
		})
	}
}

func rec(user, id string) domain.Record {
	return domain.Record{
		UserID:      user,
		ID:          id,
		Header:      []byte("header-" + id),
		HeaderNonce: []byte("hn-" + id),
		Body:        []byte("body-" + id),
		BodyNonce:   []byte("bn-" + id),
	}
}

func mustCreate(t *testing.T, repo RecordsRepo, user, id string) domain.Record {
	t.Helper()
	created, err := repo.Create(context.Background(), rec(user, id))
	require.NoError(t, err)
	return created
}

func testCreate(t *testing.T, repo RecordsRepo) {
	ctx := context.Background()
	created := mustCreate(t, repo, "u1", "r1")

	assert.Equal(t, int64(1), created.Version)
	assert.Equal(t, int64(1), created.Revision)
	assert.False(t, created.Deleted)
	assert.False(t, created.UpdatedAt.IsZero())

	got, err := repo.Get(ctx, "u1", "r1")
	require.NoError(t, err)
	assert.Equal(t, created.Version, got.Version)
	assert.Equal(t, created.Revision, got.Revision)
	assert.Equal(t, []byte("header-r1"), got.Header)
	assert.Equal(t, []byte("hn-r1"), got.HeaderNonce)
	assert.Equal(t, []byte("body-r1"), got.Body)
	assert.Equal(t, []byte("bn-r1"), got.BodyNonce)

	second := mustCreate(t, repo, "u1", "r2")
	assert.Equal(t, int64(2), second.Revision)
}

func testCreateDuplicate(t *testing.T, repo RecordsRepo) {
	mustCreate(t, repo, "u1", "r1")

	_, err := repo.Create(context.Background(), rec("u1", "r1"))
	assert.ErrorIs(t, err, domain.ErrConflict)

	// Неудачный Create не должен расходовать ревизию.
	next := mustCreate(t, repo, "u1", "r2")
	assert.Equal(t, int64(2), next.Revision)
}

func testRevisionPerUser(t *testing.T, repo RecordsRepo) {
	mustCreate(t, repo, "u1", "a")
	mustCreate(t, repo, "u1", "b")
	other := mustCreate(t, repo, "u2", "a")
	assert.Equal(t, int64(1), other.Revision)
}

func testSameIDDifferentUsers(t *testing.T, repo RecordsRepo) {
	ctx := context.Background()
	a := rec("u1", "same")
	a.Body = []byte("u1-body")
	b := rec("u2", "same")
	b.Body = []byte("u2-body")
	_, err := repo.Create(ctx, a)
	require.NoError(t, err)
	_, err = repo.Create(ctx, b)
	require.NoError(t, err)

	got, err := repo.Get(ctx, "u1", "same")
	require.NoError(t, err)
	assert.Equal(t, []byte("u1-body"), got.Body)
	got, err = repo.Get(ctx, "u2", "same")
	require.NoError(t, err)
	assert.Equal(t, []byte("u2-body"), got.Body)
}

func testUpdate(t *testing.T, repo RecordsRepo) {
	ctx := context.Background()
	created := mustCreate(t, repo, "u1", "r1")

	upd := rec("u1", "r1")
	upd.Version = created.Version
	upd.Body = []byte("new-body")
	updated, err := repo.Update(ctx, upd)
	require.NoError(t, err)
	assert.Equal(t, int64(2), updated.Version)
	assert.Greater(t, updated.Revision, created.Revision)

	got, err := repo.Get(ctx, "u1", "r1")
	require.NoError(t, err)
	assert.Equal(t, int64(2), got.Version)
	assert.Equal(t, []byte("new-body"), got.Body)
	assert.Equal(t, updated.Revision, got.Revision)
}

func testUpdateVersionMismatch(t *testing.T, repo RecordsRepo) {
	ctx := context.Background()
	mustCreate(t, repo, "u1", "r1") // version 1

	tests := []struct {
		name    string
		version int64
	}{
		{"zero", 0},
		{"from the future", 2},
		{"far ahead", 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upd := rec("u1", "r1")
			upd.Version = tt.version
			_, err := repo.Update(ctx, upd)
			assert.ErrorIs(t, err, domain.ErrStaleVersion)
		})
	}

	got, err := repo.Get(ctx, "u1", "r1")
	require.NoError(t, err)
	assert.Equal(t, int64(1), got.Version, "отклонённые обновления не меняют запись")
	assert.Equal(t, int64(1), got.Revision)
}

func testUpdateNotFound(t *testing.T, repo RecordsRepo) {
	ctx := context.Background()
	mustCreate(t, repo, "u1", "r1")

	missing := rec("u1", "nope")
	missing.Version = 1
	_, err := repo.Update(ctx, missing)
	assert.ErrorIs(t, err, domain.ErrNotFound)

	foreign := rec("u2", "r1")
	foreign.Version = 1
	_, err = repo.Update(ctx, foreign)
	assert.ErrorIs(t, err, domain.ErrNotFound)

	_, err = repo.Update(ctx, domain.Record{ID: "r1", Version: 1})
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func testUpdateDeleted(t *testing.T, repo RecordsRepo) {
	ctx := context.Background()
	created := mustCreate(t, repo, "u1", "r1")
	require.NoError(t, repo.Delete(ctx, "u1", "r1", created.Version))

	upd := rec("u1", "r1")
	upd.Version = created.Version + 1 // актуальная версия надгробия
	_, err := repo.Update(ctx, upd)
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func testDelete(t *testing.T, repo RecordsRepo) {
	ctx := context.Background()
	created := mustCreate(t, repo, "u1", "r1")

	require.NoError(t, repo.Delete(ctx, "u1", "r1", created.Version))

	_, err := repo.Get(ctx, "u1", "r1")
	assert.ErrorIs(t, err, domain.ErrNotFound, "Get не отдаёт надгробие")

	tombstones, _, err := repo.List(ctx, "u1", created.Revision)
	require.NoError(t, err)
	require.Len(t, tombstones, 1)
	assert.True(t, tombstones[0].Deleted)
	assert.Equal(t, created.Version+1, tombstones[0].Version)
	assert.Greater(t, tombstones[0].Revision, created.Revision)
}

func testDeleteVersionMismatch(t *testing.T, repo RecordsRepo) {
	ctx := context.Background()
	created := mustCreate(t, repo, "u1", "r1")
	upd := rec("u1", "r1")
	upd.Version = created.Version
	_, err := repo.Update(ctx, upd)
	require.NoError(t, err) // сохранённая версия = 2

	tests := []struct {
		name    string
		version int64
	}{
		{"stale", created.Version},
		{"from the future", 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, repo.Delete(ctx, "u1", "r1", tt.version), domain.ErrStaleVersion)
		})
	}

	got, err := repo.Get(ctx, "u1", "r1")
	require.NoError(t, err)
	assert.False(t, got.Deleted)
	assert.Equal(t, int64(2), got.Version)
}

func testDeleteNotFound(t *testing.T, repo RecordsRepo) {
	ctx := context.Background()
	mustCreate(t, repo, "u1", "r1")

	assert.ErrorIs(t, repo.Delete(ctx, "u1", "nope", 1), domain.ErrNotFound)
	assert.ErrorIs(t, repo.Delete(ctx, "u2", "r1", 1), domain.ErrNotFound)

	got, err := repo.Get(ctx, "u1", "r1")
	require.NoError(t, err)
	assert.False(t, got.Deleted)
}

func testDeleteIdempotent(t *testing.T, repo RecordsRepo) {
	ctx := context.Background()
	created := mustCreate(t, repo, "u1", "r1")
	require.NoError(t, repo.Delete(ctx, "u1", "r1", created.Version))
	firstList, firstRev, err := repo.List(ctx, "u1", 0)
	require.NoError(t, err)
	require.Len(t, firstList, 1)
	afterFirst := firstList[0]

	// Повторное удаление с актуальной версией ничего не меняет и не падает.
	require.NoError(t, repo.Delete(ctx, "u1", "r1", afterFirst.Version))
	secondList, secondRev, err := repo.List(ctx, "u1", 0)
	require.NoError(t, err)
	require.Len(t, secondList, 1)
	assert.Equal(t, afterFirst.Version, secondList[0].Version)
	assert.Equal(t, afterFirst.Revision, secondList[0].Revision)
	assert.Equal(t, firstRev, secondRev)
}

func testGetNotFound(t *testing.T, repo RecordsRepo) {
	ctx := context.Background()
	mustCreate(t, repo, "u1", "r1")

	_, err := repo.Get(ctx, "u1", "nope")
	assert.ErrorIs(t, err, domain.ErrNotFound)
	_, err = repo.Get(ctx, "u2", "r1")
	assert.ErrorIs(t, err, domain.ErrNotFound)
	_, err = repo.Get(ctx, "nobody", "r1")
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func ids(records []domain.Record) []string {
	res := make([]string, 0, len(records))
	for _, r := range records {
		res = append(res, r.ID)
	}
	sort.Strings(res)
	return res
}

func testList(t *testing.T, repo RecordsRepo) {
	ctx := context.Background()
	mustCreate(t, repo, "u1", "a")                             // revision 1
	b := mustCreate(t, repo, "u1", "b")                        // revision 2
	mustCreate(t, repo, "u1", "c")                             // revision 3
	require.NoError(t, repo.Delete(ctx, "u1", "b", b.Version)) // revision 4

	all, rev, err := repo.List(ctx, "u1", 0)
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b", "c"}, ids(all))
	assert.Equal(t, int64(4), rev)
	for _, r := range all {
		assert.Empty(t, r.Body, "List не возвращает тело")
		assert.Empty(t, r.BodyNonce)
		assert.NotEmpty(t, r.Header)
	}

	// Надгробие, изменённое после sinceRevision, должно попасть в выдачу.
	since, rev, err := repo.List(ctx, "u1", 3)
	require.NoError(t, err)
	require.Len(t, since, 1)
	assert.Equal(t, int64(4), rev)
	assert.Equal(t, "b", since[0].ID)
	assert.True(t, since[0].Deleted)

	none, rev, err := repo.List(ctx, "u1", 4)
	require.NoError(t, err)
	assert.Empty(t, none)
	assert.Equal(t, int64(4), rev)

	// Тело не должно пропасть из хранилища из-за List.
	got, err := repo.Get(ctx, "u1", "a")
	require.NoError(t, err)
	assert.Equal(t, []byte("body-a"), got.Body)
}

func testListScoped(t *testing.T, repo RecordsRepo) {
	ctx := context.Background()
	mustCreate(t, repo, "u1", "a")
	mustCreate(t, repo, "u2", "b")

	got, rev, err := repo.List(ctx, "u1", 0)
	require.NoError(t, err)
	assert.Equal(t, int64(1), rev, "ревизия u1 не зависит от записей u2")
	assert.Equal(t, []string{"a"}, ids(got))
}

func testListEmpty(t *testing.T, repo RecordsRepo) {
	got, rev, err := repo.List(context.Background(), "nobody", 0)
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.Equal(t, int64(0), rev)
}

func testConcurrentCreates(t *testing.T, repo RecordsRepo) {
	ctx := context.Background()
	const workers = 50

	var wg sync.WaitGroup
	revisions := make([]int64, workers)
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			created, err := repo.Create(ctx, rec("u1", fmt.Sprintf("r%d", i)))
			if assert.NoError(t, err) {
				revisions[i] = created.Revision
			}
		}()
	}
	wg.Wait()

	sort.Slice(revisions, func(i, j int) bool { return revisions[i] < revisions[j] })
	for i, rev := range revisions {
		assert.Equal(t, int64(i+1), rev, "ревизии должны быть уникальны и без пропусков")
	}
}

func testConcurrentUpdates(t *testing.T, repo RecordsRepo) {
	ctx := context.Background()
	mustCreate(t, repo, "u1", "r1")
	const workers = 50

	var (
		wg        sync.WaitGroup
		success   atomic.Int32
		conflicts atomic.Int32
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			upd := rec("u1", "r1")
			upd.Version = 1
			_, err := repo.Update(ctx, upd)
			switch {
			case err == nil:
				success.Add(1)
			case assert.ErrorIs(t, err, domain.ErrStaleVersion):
				conflicts.Add(1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), success.Load())
	assert.Equal(t, int32(workers-1), conflicts.Load())
}

func testInputCopies(t *testing.T, repo RecordsRepo) {
	ctx := context.Background()
	in := rec("u1", "r1")
	created, err := repo.Create(ctx, in)
	require.NoError(t, err)

	// Изменение входных срезов и результата не должно влиять на хранилище.
	in.Header[0], in.Body[0] = 'X', 'X'
	created.Header[1], created.Body[1] = 'Y', 'Y'
	got, err := repo.Get(ctx, "u1", "r1")
	require.NoError(t, err)
	assert.Equal(t, []byte("header-r1"), got.Header)
	assert.Equal(t, []byte("body-r1"), got.Body)

	upd := rec("u1", "r1")
	upd.Version = created.Version
	_, err = repo.Update(ctx, upd)
	require.NoError(t, err)
	upd.Header[0], upd.Body[0] = 'Z', 'Z'
	got, err = repo.Get(ctx, "u1", "r1")
	require.NoError(t, err)
	assert.Equal(t, []byte("header-r1"), got.Header)
	assert.Equal(t, []byte("body-r1"), got.Body)
}

func testTombstoneKeepsHeader(t *testing.T, repo RecordsRepo) {
	ctx := context.Background()
	created := mustCreate(t, repo, "u1", "r1")
	require.NoError(t, repo.Delete(ctx, "u1", "r1", created.Version))

	tombstones, _, err := repo.List(ctx, "u1", created.Revision)
	require.NoError(t, err)
	require.Len(t, tombstones, 1)
	assert.NotEmpty(t, tombstones[0].Header, "заголовок нужен ListChanges")
	assert.Empty(t, tombstones[0].Body)
	assert.Empty(t, tombstones[0].BodyNonce)
}
