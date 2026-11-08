package dbrepo

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
)

// TestMapUniqueViolation — sentinel подставляется только при нарушении уникальности (SQLSTATE 23505)
// именно заданного constraint, в том числе когда PgError завёрнут в другую ошибку;
// всё остальное (другой constraint, другой код, не-pg ошибка) возвращается тем же значением.
func TestMapUniqueViolation(t *testing.T) {
	const constraint = "records_pkey"
	sentinel := errors.New("sentinel")
	otherConstraint := &pgconn.PgError{Code: "23505", ConstraintName: "uq_records_user_revision"}
	foreignKey := &pgconn.PgError{Code: "23503", ConstraintName: constraint}
	plain := errors.New("plain")

	tests := []struct {
		name string
		in   error
		want error
	}{
		{"unique violation", &pgconn.PgError{Code: "23505", ConstraintName: constraint}, sentinel},
		{"wrapped unique violation", fmt.Errorf("insert: %w", &pgconn.PgError{Code: "23505", ConstraintName: constraint}), sentinel},
		{"other constraint is kept", otherConstraint, otherConstraint},
		{"other pg error is kept", foreignKey, foreignKey},
		{"non-pg error is kept", plain, plain},
		{"nil stays nil", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapUniqueViolation(tt.in, constraint, sentinel)

			assert.Equal(t, tt.want, got)
		})
	}
}

// TestMapNoRows — только pgx.ErrNoRows (в том числе завёрнутый) заменяется sentinel;
// остальные ошибки возвращаются тем же значением.
func TestMapNoRows(t *testing.T) {
	sentinel := errors.New("sentinel")
	plain := errors.New("plain")
	pgErr := &pgconn.PgError{Code: "23505"}

	tests := []struct {
		name string
		in   error
		want error
	}{
		{"no rows", pgx.ErrNoRows, sentinel},
		{"wrapped no rows", fmt.Errorf("scan: %w", pgx.ErrNoRows), sentinel},
		{"non-pg error is kept", plain, plain},
		{"pg error is kept", pgErr, pgErr},
		{"nil stays nil", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapNoRows(tt.in, sentinel)

			assert.Equal(t, tt.want, got)
		})
	}
}
