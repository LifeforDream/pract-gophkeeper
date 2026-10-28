// Package vault хранит методы работы с хранилищем записей.
package vault

import (
	"context"
	"fmt"

	"github.com/LifeforDream/pract-gophkeeper/internal/server/domain"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/userid"
)

// Repo описывает необходимые от репозитория методы.
type Repo interface {
	Create(ctx context.Context, record domain.Record) (domain.Record, error)
	Update(ctx context.Context, record domain.Record) (domain.Record, error)
	Delete(ctx context.Context, userID string, recordID string, expectedVersion int64) (int64, error)
	Get(ctx context.Context, userID string, recordID string) (domain.Record, error)
	List(ctx context.Context, userID string, sinceRevision int64) ([]domain.Record, int64, error)
}

// Service хранит логику работы с хранилищем.
type Service struct {
	repo            Repo
	headerSizeLimit int
	bodySizeLimit   int
}

// DefaultHeaderSizeLimit предлагает значение "по умолчанию" предела размера заголовка.
func DefaultHeaderSizeLimit() int {
	return 4 * 1024 // 4 KiB
}

// DefaultBodySizeLimit предлагает значение "по умолчанию" предела размера контента.
func DefaultBodySizeLimit() int {
	return 1024 * 1024 // 1 MiB
}

// NewService создаёт и возвращает новый сервис с лимитами по умолчанию для работы с хранилищем.
func NewService(repo Repo, headerSizeLimit, bodySizeLimit int) (*Service, error) {
	if headerSizeLimit <= 0 || bodySizeLimit <= 0 {
		return nil, fmt.Errorf("size limits should be positive")
	}
	return &Service{
		repo:            repo,
		headerSizeLimit: headerSizeLimit,
		bodySizeLimit:   bodySizeLimit,
	}, nil
}

// Put создаёт запись (Version == 0) или обновляет (Version > 0).
func (s *Service) Put(ctx context.Context, record domain.Record) (domain.Record, error) {
	if len(record.Header) > s.headerSizeLimit || len(record.Body) > s.bodySizeLimit {
		return domain.Record{}, domain.ErrPayloadTooLarge
	}
	userID, exist := userid.FromContext(ctx)
	if !exist || userID == "" {
		return domain.Record{}, domain.ErrNoUserID
	}

	// перезаписываем всегда.
	record.UserID = userID

	err := validateRecord(record)
	if err != nil {
		return domain.Record{}, err
	}

	var newRecord domain.Record
	if record.Version == 0 {
		rec, err := s.repo.Create(ctx, record)
		if err != nil {
			return domain.Record{}, fmt.Errorf("vault service: %w", err)
		}
		newRecord = rec
	} else {
		rec, err := s.repo.Update(ctx, record)
		if err != nil {
			return domain.Record{}, fmt.Errorf("vault service: %w", err)
		}
		newRecord = rec
	}
	return newRecord, nil
}

func validateRecord(record domain.Record) error {
	if record.Version < 0 {
		return fmt.Errorf("record version cannot be below zero %w", domain.ErrInvalidArgument)
	}
	if record.ID == "" {
		return fmt.Errorf("record ID cannot be empty %w", domain.ErrInvalidArgument)
	}
	if len(record.Body) == 0 || len(record.Header) == 0 {
		return fmt.Errorf("record header and body cannot be empty %w", domain.ErrInvalidArgument)
	}
	if record.Deleted {
		return fmt.Errorf("cannot create deleted record %w", domain.ErrInvalidArgument)
	}
	if record.UserID == "" {
		return fmt.Errorf("userID cannot be empty %w", domain.ErrInvalidArgument)
	}
	return nil
}

// Delete выполняет "мягкое удаление", помечая запись как удалённую для последующих версий.
//
// Повторный Delete с устаревшей версией вернёт ErrStaleVersion.
// Повторный Delete с актуальной версией вернёт успех, но ничего не сделает.
func (s *Service) Delete(ctx context.Context, recordID string, expectedVersion int64) (int64, error) {
	userID, exist := userid.FromContext(ctx)
	if !exist || userID == "" {
		return 0, domain.ErrNoUserID
	}

	rev, err := s.repo.Delete(ctx, userID, recordID, expectedVersion)
	if err != nil {
		return 0, fmt.Errorf("vault service: %w", err)
	}
	return rev, nil
}

// GetRecord получает запись целиком (включая Body) по recordID + userID.
func (s *Service) GetRecord(ctx context.Context, recordID string) (domain.Record, error) {
	userID, exist := userid.FromContext(ctx)
	if !exist || userID == "" {
		return domain.Record{}, domain.ErrNoUserID
	}

	record, err := s.repo.Get(ctx, userID, recordID)
	if err != nil {
		return domain.Record{}, fmt.Errorf("vault service: %w", err)
	}
	return record, nil
}

// ListChanges получает записи с изменениями, произошедшие после sinceRevision. В записях не заполнены Body.
func (s *Service) ListChanges(ctx context.Context, sinceRevision int64) ([]domain.Record, int64, error) {
	if sinceRevision < 0 {
		return nil, 0, fmt.Errorf("sinceRevision must not be negative %w", domain.ErrInvalidArgument)
	}
	result := make([]domain.Record, 0)
	userID, exist := userid.FromContext(ctx)
	if !exist || userID == "" {
		return nil, 0, domain.ErrNoUserID
	}
	records, latestRevision, err := s.repo.List(ctx, userID, sinceRevision)
	if err != nil {
		return nil, 0, fmt.Errorf("vault service: %w", err)
	}
	for _, record := range records {
		if sinceRevision == 0 && record.Deleted {
			continue
		}
		result = append(result, record)
	}
	return result, latestRevision, nil
}
