package grpcsrv

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/LifeforDream/pract-gophkeeper/internal/kdfparams"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/domain"
)

// TestMapErrors проверяет, что каждая известная ошибка (в том числе обёрнутая) превращается в нужный код,
// а клиенту не уходит ни текст внутренней ошибки, ни цепочка обёрток.
func TestMapErrors(t *testing.T) {
	const internalText = "vault service: secret internal detail"

	tests := []struct {
		name    string
		err     error
		want    codes.Code
		wantMsg string
	}{
		{"canceled", context.Canceled, codes.Canceled, "request canceled"},
		{"deadline exceeded", context.DeadlineExceeded, codes.DeadlineExceeded, "deadline exceeded"},
		{"not found", domain.ErrNotFound, codes.NotFound, "not found"},
		{"stale version", domain.ErrStaleVersion, codes.Aborted, "version conflict"},
		{"conflict", domain.ErrConflict, codes.Aborted, "version conflict"},
		{"login taken", domain.ErrLoginTaken, codes.AlreadyExists, "login already in use"},
		{"bad credentials", domain.ErrBadCredentials, codes.Unauthenticated, "unauthenticated"},
		{"no user id", domain.ErrNoUserID, codes.Unauthenticated, "unauthenticated"},
		{"invalid argument", domain.ErrInvalidArgument, codes.InvalidArgument, "invalid argument"},
		{"invalid kdf params", kdfparams.ErrInvalidParams, codes.InvalidArgument, "invalid argument"},
		{"payload too large", domain.ErrPayloadTooLarge, codes.ResourceExhausted, "payload too large"},
		{"unknown error", errors.New(internalText), codes.Internal, "unexpected server error"},
		{"wrapped canceled", fmt.Errorf("vault service: %w", context.Canceled), codes.Canceled, "request canceled"},
		{"wrapped not found", fmt.Errorf("vault service: %w", domain.ErrNotFound), codes.NotFound, "not found"},
		{"wrapped login taken", fmt.Errorf("auth service: %w", domain.ErrLoginTaken), codes.AlreadyExists, "login already in use"},
		{"wrapped invalid params", fmt.Errorf("register: %w", kdfparams.ErrInvalidParams), codes.InvalidArgument, "invalid argument"},
		{"joined known error", errors.Join(errors.New("extra"), domain.ErrPayloadTooLarge), codes.ResourceExhausted, "payload too large"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapErrors(tt.err)

			st, ok := status.FromError(got)
			require.True(t, ok, "ошибка должна нести gRPC-статус")
			assert.Equal(t, tt.want, st.Code())
			assert.Equal(t, tt.wantMsg, st.Message(), "клиент видит только стабильный текст")
			assert.NotContains(t, st.Message(), "vault service")
			assert.NotContains(t, st.Message(), "secret internal detail")

			// Для логов причина должна сохраняться и быть доступна через errors.Is.
			assert.ErrorIs(t, got, tt.err)
		})
	}
}
