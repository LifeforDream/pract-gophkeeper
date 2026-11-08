package dbrepo

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/LifeforDream/pract-gophkeeper/internal/server/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RecordsRepository реализует методы для работы с записями в БД.
type RecordsRepository struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewRecordsRepository возвращает ссылку на новый репозиторий с пулом pool.
func NewRecordsRepository(pool *pgxpool.Pool, logger *slog.Logger) *RecordsRepository {
	return &RecordsRepository{pool: pool, logger: logger}
}

func (r *RecordsRepository) rollback(ctx context.Context, tx pgx.Tx) {
	ctx = context.WithoutCancel(ctx)
	err := tx.Rollback(ctx)
	if err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		r.logger.Warn("error on txn rollback", "error", err)
	}
}

// Create создаёт запись с версией 1.
func (r *RecordsRepository) Create(ctx context.Context, record domain.Record) (domain.Record, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.Record{}, fmt.Errorf("acquire transaction in create: %w", err)
	}
	defer r.rollback(ctx, tx)

	revision, err := r.getNewUserRevision(ctx, tx, record.UserID)
	if err != nil {
		return domain.Record{}, fmt.Errorf("create record: %w", err)
	}
	var rec domain.Record
	err = tx.QueryRow(ctx,
		`INSERT INTO records (user_id, id, version, revision, header, header_nonce, body, body_nonce, updated_at)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING user_id, id, version, revision, deleted, header, header_nonce, body, body_nonce, updated_at`,
		record.UserID, record.ID, 1, revision, record.Header, record.HeaderNonce, record.Body, record.BodyNonce, time.Now()).
		Scan(&rec.UserID, &rec.ID, &rec.Version, &rec.Revision, &rec.Deleted, &rec.Header, &rec.HeaderNonce, &rec.Body, &rec.BodyNonce, &rec.UpdatedAt)
	if err != nil {
		return domain.Record{}, fmt.Errorf("create record: %w", mapUniqueViolation(err, "records_pkey", domain.ErrConflict))
	}
	err = tx.Commit(ctx)
	if err != nil {
		return domain.Record{}, fmt.Errorf("error committing create: %w", err)
	}
	return rec, nil
}

// Update обновляет запись.
func (r *RecordsRepository) Update(ctx context.Context, record domain.Record) (domain.Record, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.Record{}, fmt.Errorf("acquire transaction in update: %w", err)
	}
	defer r.rollback(ctx, tx)

	oldRec, err := r.getRecordData(ctx, tx, record.ID, record.UserID)
	if err != nil {
		return domain.Record{}, fmt.Errorf("error retrieving record for update: %w", err)
	}

	if oldRec.Version != record.Version {
		return domain.Record{}, domain.ErrStaleVersion
	}

	if oldRec.Deleted {
		// нельзя обновлять удалённое.
		return domain.Record{}, domain.ErrNotFound
	}

	revision, err := r.getNewUserRevision(ctx, tx, record.UserID)
	if err != nil {
		return domain.Record{}, fmt.Errorf("update record: %w", err)
	}

	var rec domain.Record
	err = tx.QueryRow(ctx,
		`UPDATE records SET
		version = version + 1,
		header = $1,
		header_nonce = $2,
		body = $3,
		body_nonce = $4,
		revision = $5,
		updated_at = $6
		WHERE id = $7 AND user_id = $8 AND version = $9 AND deleted = false
		RETURNING user_id, id, version, revision, deleted, header, header_nonce, body, body_nonce, updated_at`,
		record.Header, record.HeaderNonce, record.Body, record.BodyNonce, revision, time.Now(), record.ID, record.UserID, record.Version).
		Scan(&rec.UserID, &rec.ID, &rec.Version, &rec.Revision, &rec.Deleted, &rec.Header, &rec.HeaderNonce, &rec.Body, &rec.BodyNonce, &rec.UpdatedAt)
	if err != nil {
		return domain.Record{}, fmt.Errorf("update record: %w", mapNoRows(err, domain.ErrNotFound))
	}
	err = tx.Commit(ctx)
	if err != nil {
		return domain.Record{}, fmt.Errorf("error committing update: %w", err)
	}
	return rec, nil
}

// getRecordData получает общую информацию о записи. Например, для сравнения версий.
func (r *RecordsRepository) getRecordData(ctx context.Context, tx pgx.Tx, recordID, userID string) (domain.Record, error) {
	var rec domain.Record
	err := tx.QueryRow(ctx,
		`SELECT user_id, id, version, revision, deleted
		FROM records
		WHERE id = $1 AND user_id = $2
		FOR UPDATE`,
		recordID, userID).
		Scan(&rec.UserID, &rec.ID, &rec.Version, &rec.Revision, &rec.Deleted)
	if err != nil {
		return domain.Record{}, mapNoRows(err, domain.ErrNotFound)
	}
	return rec, nil
}

// Delete помечает запись как удалённую, при этом фактически не удаляя.
//
// Повторный Delete с устаревшей версией вернёт ErrStaleVersion.
// Повторный Delete с актуальной версией вернёт успех, но ничего не сделает.
func (r *RecordsRepository) Delete(ctx context.Context, userID string, recordID string, expectedVersion int64) (int64, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("acquire transaction in delete: %w", err)
	}
	defer r.rollback(ctx, tx)

	oldRec, err := r.getRecordData(ctx, tx, recordID, userID)
	if err != nil {
		return 0, fmt.Errorf("error retrieving record for delete: %w", err)
	}

	if oldRec.Version != expectedVersion {
		return 0, domain.ErrStaleVersion
	}

	if oldRec.Deleted {
		// идемпотентно возвращаем текущую ревизию.
		rev, err := r.getUserRevision(ctx, tx, userID)
		if err != nil {
			return 0, fmt.Errorf("error retrieving user revision for delete: %w", err)
		}
		return rev, nil
	}

	revision, err := r.getNewUserRevision(ctx, tx, userID)
	if err != nil {
		return 0, fmt.Errorf("update record: %w", err)
	}

	tag, err := tx.Exec(ctx,
		`UPDATE records SET deleted = true, body = (''::bytea), body_nonce = (''::bytea), revision = $4, version = version + 1, updated_at = $5
		WHERE id = $1 AND user_id = $2 AND version = $3`,
		oldRec.ID, oldRec.UserID, expectedVersion, revision, time.Now())
	if err != nil {
		return 0, fmt.Errorf("error deleting record: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return 0, domain.ErrNotFound
	}
	err = tx.Commit(ctx)
	if err != nil {
		return 0, fmt.Errorf("error committing delete: %w", err)
	}
	return revision, nil
}

// Get получает запись целиком
func (r *RecordsRepository) Get(ctx context.Context, userID string, recordID string) (domain.Record, error) {
	var rec domain.Record
	err := r.pool.QueryRow(ctx,
		`SELECT user_id, id, version, revision, deleted, header, header_nonce, body, body_nonce, updated_at
		FROM records
		WHERE id = $1 AND user_id = $2 AND deleted = false`,
		recordID, userID).
		Scan(&rec.UserID, &rec.ID, &rec.Version, &rec.Revision, &rec.Deleted, &rec.Header, &rec.HeaderNonce, &rec.Body, &rec.BodyNonce, &rec.UpdatedAt)
	if err != nil {
		return domain.Record{}, fmt.Errorf("get record: %w", mapNoRows(err, domain.ErrNotFound))
	}
	return rec, nil
}

// List возвращает записи пользователя userID, имеющие Revision > sinceRevision, а также последнюю ревизию пользователя.
// Не заполняет Body и BodyNonce
func (r *RecordsRepository) List(ctx context.Context, userID string, sinceRevision int64) ([]domain.Record, int64, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("acquire transaction in list: %w", err)
	}
	defer r.rollback(ctx, tx)

	revision, err := r.getUserRevision(ctx, tx, userID)
	if err != nil {
		return nil, 0, fmt.Errorf("error getting user revision in list: %w", err)
	}

	rows, err := tx.Query(ctx,
		`SELECT user_id, id, version, revision, deleted, header, header_nonce, updated_at
		FROM records
		WHERE user_id = $1 AND revision > $2
		ORDER BY revision ASC`,
		userID, sinceRevision)
	if err != nil {
		return nil, 0, fmt.Errorf("error fetching rows in list: %w", err)
	}

	records, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (domain.Record, error) {
		var rec domain.Record
		err := row.Scan(&rec.UserID, &rec.ID, &rec.Version, &rec.Revision, &rec.Deleted,
			&rec.Header, &rec.HeaderNonce, &rec.UpdatedAt)
		return rec, err
	})
	if err != nil {
		return nil, 0, fmt.Errorf("scan records: %w", err)
	}

	maxRevision := revision
	for _, rec := range records {
		maxRevision = max(maxRevision, rec.Revision)
	}

	return records, maxRevision, nil
}

func (r *RecordsRepository) getNewUserRevision(ctx context.Context, tx pgx.Tx, userID string) (int64, error) {
	var rev int64
	err := tx.QueryRow(ctx,
		`UPDATE users SET revision = revision +1 WHERE id = $1 RETURNING revision`, userID).Scan(&rev)
	if err != nil {
		return 0, fmt.Errorf("update revision: %w", mapNoRows(err, domain.ErrNotFound))
	}
	return rev, nil
}

func (r *RecordsRepository) getUserRevision(ctx context.Context, tx pgx.Tx, userID string) (int64, error) {
	var rev int64
	err := tx.QueryRow(ctx,
		`SELECT revision from users WHERE id = $1`, userID).Scan(&rev)
	if err != nil {
		return 0, mapNoRows(err, domain.ErrNotFound)
	}
	return rev, nil
}
