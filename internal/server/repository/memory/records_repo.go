// Package memory реализует хранение в памяти.
package memory

import (
	"cmp"
	"context"
	"slices"
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
func (r *RecordsRepo) Delete(_ context.Context, userID, recordID string, expectedVersion int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	userRecords, ok := r.usersRecords[userID]
	if !ok {
		return domain.ErrNotFound
	}

	existingRecord, ok := userRecords[recordID]
	if !ok {
		return domain.ErrNotFound
	}
	if existingRecord.Version != expectedVersion {
		return domain.ErrStaleVersion
	}
	if existingRecord.Deleted {
		// ничего не обновляем, но и не падаем в ошибку
		return nil
	}

	r.usersRevisions[userID] = r.usersRevisions[userID] + 1

	existingRecord.Revision = r.usersRevisions[userID]
	existingRecord.Deleted = true
	existingRecord.UpdatedAt = time.Now()
	// обнулим Body, header оставим как есть
	existingRecord.Body = []byte{}
	existingRecord.BodyNonce = []byte{}
	existingRecord.Version = existingRecord.Version + 1

	userRecords[recordID] = existingRecord
	return nil
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

// List возвращает записи пользователя userID, имеющие Revision > sinceRevision, а также последнюю ревизию пользователя.
func (r *RecordsRepo) List(_ context.Context, userID string, sinceRevision int64) ([]domain.Record, int64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	userRecords, ok := r.usersRecords[userID]
	if !ok {
		return []domain.Record{}, 0, nil
	}

	res := make([]domain.Record, 0, len(userRecords))
	for _, record := range userRecords {
		if record.Revision <= sinceRevision {
			continue
		}
		recordCopy := record
		recordCopy.Body = []byte{}
		recordCopy.BodyNonce = []byte{}
		res = append(res, cloneRecord(recordCopy))
	}
	// сортируем по ревизии по возрастанию
	slices.SortFunc(res, func(a, b domain.Record) int {
		return cmp.Compare(a.Revision, b.Revision)
	})

	return res, r.usersRevisions[userID], nil
}

// cloneRecord копирует слайсы в данных записи, чтобы вызывающий код не мог изменить хранимые данные.
func cloneRecord(r domain.Record) domain.Record {
	r.Header = slices.Clone(r.Header)
	r.HeaderNonce = slices.Clone(r.HeaderNonce)
	r.Body = slices.Clone(r.Body)
	r.BodyNonce = slices.Clone(r.BodyNonce)
	return r
}
