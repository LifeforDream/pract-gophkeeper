// Package memory реализует хранение в памяти.
package memory

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/LifeforDream/pract-gophkeeper/internal/server/domain"
)

// RecordsRepo реализует хранилище записей с секретами.
type RecordsRepo struct {
	mu             sync.RWMutex
	usersRecords   map[string]map[string]domain.Record
	usersRevisions map[string]int64
}

// NewRecordsRepo создаёт новое хранилище записей.
func NewRecordsRepo() *RecordsRepo {
	return &RecordsRepo{
		usersRecords:   make(map[string]map[string]domain.Record),
		usersRevisions: make(map[string]int64),
	}
}

// Create создаёт новую запись, заполняя в ней Revision.
func (r *RecordsRepo) Create(_ context.Context, record domain.Record) (domain.Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	currentRevision := int64(1)
	userRecords, ok := r.usersRecords[record.UserID]
	if !ok {
		userRecords = make(map[string]domain.Record)
		r.usersRecords[record.UserID] = userRecords
	} else {
		currentRevision = r.usersRevisions[record.UserID] + 1
	}

	_, exist := userRecords[record.ID]
	if exist {
		return domain.Record{}, domain.ErrConflict
	}

	r.usersRevisions[record.UserID] = currentRevision

	record.Revision = currentRevision
	record.UpdatedAt = time.Now()
	record.Version = 1

	userRecords[record.ID] = cloneRecord(record)
	return cloneRecord(record), nil
}

// Update обновляет существующую запись.
func (r *RecordsRepo) Update(_ context.Context, record domain.Record) (domain.Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	userRecords, ok := r.usersRecords[record.UserID]
	if !ok {
		return domain.Record{}, domain.ErrNotFound
	}

	existingRecord, ok := userRecords[record.ID]
	if !ok || existingRecord.Deleted {
		return domain.Record{}, domain.ErrNotFound
	}
	if existingRecord.Version != record.Version {
		return domain.Record{}, domain.ErrStaleVersion
	}
	r.usersRevisions[record.UserID] = r.usersRevisions[record.UserID] + 1

	record.Revision = r.usersRevisions[record.UserID]
	record.UpdatedAt = time.Now()
	record.Version = record.Version + 1

	userRecords[record.ID] = cloneRecord(record)
	return cloneRecord(record), nil
}

// Delete помечает запись как "удалённую", не удаляя реально.
//
// Повторный Delete с устаревшей версией вернёт ErrStaleVersion.
// Повторный Delete с актуальной версией вернёт успех, но ничего не сделает.
func (r *RecordsRepo) Delete(_ context.Context, userID, recordID string, expectedVersion int64) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	currentRevision := r.usersRevisions[userID]

	userRecords, ok := r.usersRecords[userID]
	if !ok {
		return currentRevision, domain.ErrNotFound
	}

	existingRecord, ok := userRecords[recordID]
	if !ok {
		return currentRevision, domain.ErrNotFound
	}
	if existingRecord.Version != expectedVersion {
		return currentRevision, domain.ErrStaleVersion
	}
	if existingRecord.Deleted {
		// ничего не обновляем, но и не падаем в ошибку
		return currentRevision, nil
	}
	currentRevision = currentRevision + 1
	r.usersRevisions[userID] = currentRevision

	existingRecord.Revision = currentRevision
	existingRecord.Deleted = true
	existingRecord.UpdatedAt = time.Now()
	// обнулим Body, заголовок (тип, имя, метаданные) оставим как есть
	existingRecord.Body = []byte{}
	existingRecord.BodyNonce = []byte{}
	existingRecord.Version = existingRecord.Version + 1

	userRecords[recordID] = existingRecord
	return currentRevision, nil
}

// Get возвращает запись целиком.
func (r *RecordsRepo) Get(_ context.Context, userID, recordID string) (domain.Record, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	userRecords, ok := r.usersRecords[userID]
	if !ok {
		return domain.Record{}, domain.ErrNotFound
	}

	existingRecord, ok := userRecords[recordID]
	if !ok || existingRecord.Deleted {
		return domain.Record{}, domain.ErrNotFound
	}

	return cloneRecord(existingRecord), nil
}

// ListChanges возвращает записи пользователя userID, имеющие Revision > sinceRevision, а также последнюю ревизию пользователя.
func (r *RecordsRepo) ListChanges(_ context.Context, userID string, sinceRevision int64) ([]domain.Record, int64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	res := r.collect(userID, func(record domain.Record) bool {
		return record.Revision > sinceRevision
	})
	return res, r.usersRevisions[userID], nil
}

// List возвращает живые записи пользователя userID, подходящие под filter, в том же порядке, что и ListChanges.
// Body и BodyNonce не заполняются.
func (r *RecordsRepo) List(_ context.Context, userID string, filter domain.Filter) ([]domain.Record, error) {
	fragment := strings.ToLower(filter.NameFragment)

	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.collect(userID, func(record domain.Record) bool {
		if record.Deleted {
			return false
		}
		if filter.Type != "" && record.Type != filter.Type {
			return false
		}
		if fragment != "" && !strings.Contains(strings.ToLower(record.Name), fragment) {
			return false
		}
		if filter.MetaKey != "" && !slices.ContainsFunc(record.Meta, func(m domain.MetaItem) bool {
			return m.Key == filter.MetaKey
		}) {
			return false
		}
		return true
	}), nil
}

// collect возвращает копии записей пользователя, подходящих под keep, без Body и BodyNonce,
// отсортированные по ревизии по возрастанию. Вызывающий код должен держать r.mu.
func (r *RecordsRepo) collect(userID string, keep func(domain.Record) bool) []domain.Record {
	userRecords := r.usersRecords[userID]
	res := make([]domain.Record, 0, len(userRecords))
	for _, record := range userRecords {
		if !keep(record) {
			continue
		}
		record.Body = []byte{}
		record.BodyNonce = []byte{}
		res = append(res, cloneRecord(record))
	}
	slices.SortFunc(res, func(a, b domain.Record) int {
		return cmp.Compare(a.Revision, b.Revision)
	})
	return res
}

// cloneRecord копирует слайсы в данных записи, чтобы вызывающий код не мог изменить хранимые данные.
func cloneRecord(r domain.Record) domain.Record {
	r.Meta = slices.SortedFunc(slices.Values(r.Meta), func(a, b domain.MetaItem) int {
		return cmp.Compare(a.Key, b.Key)
	})
	r.Body = slices.Clone(r.Body)
	r.BodyNonce = slices.Clone(r.BodyNonce)
	return r
}
