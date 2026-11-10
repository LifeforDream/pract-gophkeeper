package dbrepo

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
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
		`INSERT INTO records (user_id, id, version, revision, type, name, body, body_nonce, updated_at)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING user_id, id, version, revision, deleted, type, name, body, body_nonce, updated_at`,
		record.UserID, record.ID, 1, revision, record.Type, record.Name, record.Body, record.BodyNonce, time.Now()).
		Scan(&rec.UserID, &rec.ID, &rec.Version, &rec.Revision, &rec.Deleted, &rec.Type, &rec.Name, &rec.Body, &rec.BodyNonce, &rec.UpdatedAt)
	if err != nil {
		return domain.Record{}, fmt.Errorf("create record: %w", mapUniqueViolation(err, "records_pkey", domain.ErrConflict))
	}
	if err = r.insertMeta(ctx, tx, record.UserID, record.ID, record.Meta); err != nil {
		return domain.Record{}, fmt.Errorf("create record: %w", err)
	}
	rec.Meta = slices.Clone(record.Meta)
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
		type = $1,
		name = $2,
		body = $3,
		body_nonce = $4,
		revision = $5,
		updated_at = $6
		WHERE id = $7 AND user_id = $8 AND version = $9 AND deleted = false
		RETURNING user_id, id, version, revision, deleted, type, name, body, body_nonce, updated_at`,
		record.Type, record.Name, record.Body, record.BodyNonce, revision, time.Now(), record.ID, record.UserID, record.Version).
		Scan(&rec.UserID, &rec.ID, &rec.Version, &rec.Revision, &rec.Deleted, &rec.Type, &rec.Name, &rec.Body, &rec.BodyNonce, &rec.UpdatedAt)
	if err != nil {
		return domain.Record{}, fmt.Errorf("update record: %w", mapNoRows(err, domain.ErrNotFound))
	}
	// метаданные заменяются целиком.
	if _, err = tx.Exec(ctx, `DELETE FROM record_meta WHERE user_id = $1 AND record_id = $2`, record.UserID, record.ID); err != nil {
		return domain.Record{}, fmt.Errorf("error deleting old meta in update: %w", err)
	}
	if err = r.insertMeta(ctx, tx, record.UserID, record.ID, record.Meta); err != nil {
		return domain.Record{}, fmt.Errorf("update record: %w", err)
	}
	rec.Meta = slices.Clone(record.Meta)
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

	err = r.deleteMeta(ctx, tx, recordID)
	if err != nil {
		return 0, fmt.Errorf("delete record meta: %w", err)
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
	tx, err := r.beginRead(ctx)
	if err != nil {
		return domain.Record{}, fmt.Errorf("acquire transaction in get: %w", err)
	}
	defer r.rollback(ctx, tx)

	var rec domain.Record
	err = tx.QueryRow(ctx,
		`SELECT user_id, id, version, revision, deleted, type, name, body, body_nonce, updated_at
		FROM records
		WHERE id = $1 AND user_id = $2 AND deleted = false`,
		recordID, userID).
		Scan(&rec.UserID, &rec.ID, &rec.Version, &rec.Revision, &rec.Deleted, &rec.Type, &rec.Name, &rec.Body, &rec.BodyNonce, &rec.UpdatedAt)
	if err != nil {
		return domain.Record{}, fmt.Errorf("get record: %w", mapNoRows(err, domain.ErrNotFound))
	}

	metaByRecord, err := r.loadMeta(ctx, tx, userID, recordID, 0)
	if err != nil {
		return domain.Record{}, fmt.Errorf("get record: %w", err)
	}
	rec.Meta = metaByRecord[rec.ID]
	return rec, nil
}

// ListChanges возвращает записи пользователя userID, имеющие Revision > sinceRevision, а также последнюю ревизию пользователя.
// Не заполняет Body и BodyNonce
func (r *RecordsRepository) ListChanges(ctx context.Context, userID string, sinceRevision int64) ([]domain.Record, int64, error) {
	tx, err := r.beginRead(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("acquire transaction in list changes: %w", err)
	}
	defer r.rollback(ctx, tx)

	revision, err := r.getUserRevision(ctx, tx, userID)
	if err != nil {
		return nil, 0, fmt.Errorf("error getting user revision in list changes: %w", err)
	}

	rows, err := tx.Query(ctx,
		`SELECT user_id, id, version, revision, deleted, type, name, updated_at
		FROM records
		WHERE user_id = $1 AND revision > $2
		ORDER BY revision ASC`,
		userID, sinceRevision)
	if err != nil {
		return nil, 0, fmt.Errorf("error fetching rows in list: %w", err)
	}

	records, err := scanHeaders(rows)
	if err != nil {
		return nil, 0, fmt.Errorf("scan records: %w", err)
	}

	metaByRecord, err := r.loadMeta(ctx, tx, userID, "", sinceRevision)
	if err != nil {
		return nil, 0, fmt.Errorf("error loading meta in list: %w", err)
	}

	maxRevision := revision
	for i := range records {
		maxRevision = max(maxRevision, records[i].Revision)
		records[i].Meta = metaByRecord[records[i].ID]
	}

	return records, maxRevision, nil
}

// List возвращает живые записи пользователя userID, подходящие под filter, в том же порядке, что и ListChanges.
// Не заполняет Body и BodyNonce.
func (r *RecordsRepository) List(ctx context.Context, userID string, filter domain.Filter) ([]domain.Record, error) {
	tx, err := r.beginRead(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire transaction in search: %w", err)
	}
	defer r.rollback(ctx, tx)

	// Пустой фильтр отключает условие: $2 = '' и т.д. Фрагмент экранируем, чтобы %, _ и \ искались буквально.
	rows, err := tx.Query(ctx,
		`SELECT user_id, id, version, revision, deleted, type, name, updated_at
		FROM records
		WHERE user_id = $1 AND deleted = false
		  AND ($2 = '' OR type = $2)
		  AND ($3 = '' OR name ILIKE '%' || $3 || '%' ESCAPE '\')
		  AND ($4 = '' OR EXISTS (
		        SELECT 1 FROM record_meta m
		        WHERE m.user_id = records.user_id AND m.record_id = records.id AND m.key = $4))
		ORDER BY revision ASC`,
		userID, string(filter.Type), escapeLike(filter.NameFragment), filter.MetaKey)
	if err != nil {
		return nil, fmt.Errorf("error fetching rows in search: %w", err)
	}

	records, err := scanHeaders(rows)
	if err != nil {
		return nil, fmt.Errorf("scan records in search: %w", err)
	}

	metaByRecord, err := r.loadMeta(ctx, tx, userID, "", 0)
	if err != nil {
		return nil, fmt.Errorf("error loading meta in search: %w", err)
	}
	for i := range records {
		records[i].Meta = metaByRecord[records[i].ID]
	}
	return records, nil
}

// escapeLike экранирует служебные символы шаблона LIKE (\, % и _), чтобы они искались как обычные.
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// scanHeaders читает строки с заголовками записей (без тела и метаданных).
func scanHeaders(rows pgx.Rows) ([]domain.Record, error) {
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (domain.Record, error) {
		var rec domain.Record
		err := row.Scan(&rec.UserID, &rec.ID, &rec.Version, &rec.Revision, &rec.Deleted,
			&rec.Type, &rec.Name, &rec.UpdatedAt)
		return rec, err
	})
}

// beginRead открывает транзакцию только на чтение с повторяемым чтением, чтобы запись и её метаданные читались согласованно.
func (r *RecordsRepository) beginRead(ctx context.Context) (pgx.Tx, error) {
	return r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
}

// insertMeta сохраняет метаданные записи.
func (r *RecordsRepository) insertMeta(ctx context.Context, tx pgx.Tx, userID, recordID string, meta []domain.MetaItem) error {
	if len(meta) == 0 {
		return nil
	}
	rows := make([][]any, 0, len(meta))
	for _, item := range meta {
		rows = append(rows, []any{userID, recordID, item.Key, item.Value})
	}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"record_meta"}, []string{"user_id", "record_id", "key", "value"}, pgx.CopyFromRows(rows))
	if err != nil {
		return fmt.Errorf("error inserting meta: %w", err)
	}
	return nil
}

// loadMeta читает метаданные записей пользователя, сгруппированные по ID записи и отсортированные по ключу.
// Если задан recordID, возвращает метаданные только этой записи; иначе - всех записей с ревизией больше sinceRevision.
func (r *RecordsRepository) loadMeta(ctx context.Context, tx pgx.Tx, userID, recordID string, sinceRevision int64) (map[string][]domain.MetaItem, error) {
	rows, err := tx.Query(ctx,
		`SELECT m.record_id, m.key, m.value
		FROM record_meta m
		JOIN records r ON r.user_id = m.user_id AND r.id = m.record_id
		WHERE m.user_id = $1 AND ($2 = '' OR m.record_id = $2) AND r.revision > $3
		ORDER BY m.record_id, m.key`,
		userID, recordID, sinceRevision)
	if err != nil {
		return nil, fmt.Errorf("error fetching meta: %w", err)
	}
	result := make(map[string][]domain.MetaItem)
	var id string
	var item domain.MetaItem
	_, err = pgx.ForEachRow(rows, []any{&id, &item.Key, &item.Value}, func() error {
		result[id] = append(result[id], item)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("error scanning meta: %w", err)
	}
	return result, nil
}

func (r *RecordsRepository) deleteMeta(ctx context.Context, tx pgx.Tx, recordID string) error {
	_, err := tx.Exec(ctx,
		`DELETE FROM record_meta m
	WHERE m.record_id = $1`,
		recordID)
	if err != nil {
		return fmt.Errorf("deleting meta: %w", err)
	}
	return nil
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
