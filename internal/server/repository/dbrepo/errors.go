package dbrepo

import (
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// mapUniqueViolation превращает ошибку уникальности постгреса в sentinel, если название constraint совпадает с заданным.
// все остальные ошибки будут возвращены как есть.
func mapUniqueViolation(err error, constraint string, sentinel error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == constraint { // unique violation
		return sentinel
	}
	return err
}

// mapNoRows переводит pgx.ErrNoRows в sentinel,
// чтобы ниже по исполнению кода не нужно было знать про pgx-ошибки.
// остальные ошибки возвращаются как есть.
func mapNoRows(err error, sentinel error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return sentinel
	}
	return err
}
