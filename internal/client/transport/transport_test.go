package transport

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/LifeforDream/pract-gophkeeper/api/gophkeeper/v1"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestMapErr(t *testing.T) {
	st := func(c codes.Code) error { return status.Error(c, "raw grpc text") }
	tests := []struct {
		name   string
		method string
		err    error
		want   error // nil — ожидается обёртка исходной ошибки
	}{
		{"nil", "Put", nil, nil},
		{"login unauthenticated", "Login", st(codes.Unauthenticated), domain.ErrInvalidCredentials},
		{"register unauthenticated", "Register", st(codes.Unauthenticated), domain.ErrInvalidCredentials},
		{"put unauthenticated", "Put", st(codes.Unauthenticated), domain.ErrSessionExpired},
		{"list unauthenticated", "ListChanges", st(codes.Unauthenticated), domain.ErrSessionExpired},
		{"already exists", "Register", st(codes.AlreadyExists), domain.ErrLoginTaken},
		{"aborted", "Put", st(codes.Aborted), domain.ErrConflict},
		{"not found", "Get", st(codes.NotFound), domain.ErrNotFound},
		{"resource exhausted", "Put", st(codes.ResourceExhausted), domain.ErrTooLarge},
		{"other code is wrapped", "Get", st(codes.Internal), nil},
		{"non-grpc error is wrapped", "Get", context.Canceled, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapErr(tt.method, tt.err)
			switch {
			case tt.err == nil:
				assert.NoError(t, got)
			case tt.want != nil:
				assert.ErrorIs(t, got, tt.want)
				assert.NotContains(t, got.Error(), "raw grpc text", "сырой текст gRPC не должен доходить до пользователя")
			default:
				assert.ErrorIs(t, got, tt.err)
				assert.Contains(t, got.Error(), tt.method)
			}
		})
	}
}

func TestRecordFromProto(t *testing.T) {
	rec := pb.Record_builder{
		Id:          "id",
		Header:      []byte("h"),
		HeaderNonce: []byte("hn"),
		Body:        []byte("b"),
		BodyNonce:   []byte("bn"),
		Version:     3,
		Revision:    7,
		Deleted:     true,
	}.Build()

	got := recordFromProto(rec)
	assert.Equal(t, "id", got.ID)
	assert.Equal(t, []byte("h"), got.Header.Ciphertext)
	assert.Equal(t, []byte("hn"), got.Header.Nonce)
	assert.Equal(t, []byte("b"), got.Body.Ciphertext)
	assert.Equal(t, []byte("bn"), got.Body.Nonce)
	assert.EqualValues(t, 3, got.Version)
	assert.EqualValues(t, 7, got.Revision)
	assert.True(t, got.Deleted)

	// запись из ListChanges приходит без тела
	empty := recordFromProto(pb.Record_builder{Id: "x"}.Build())
	assert.Empty(t, empty.Body.Ciphertext)
}

func TestNewClient_CACert(t *testing.T) {
	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage.pem")
	require.NoError(t, os.WriteFile(garbage, []byte("not a pem"), 0o600))
	empty := filepath.Join(dir, "empty.pem")
	require.NoError(t, os.WriteFile(empty, nil, 0o600))
	logger := slog.New(slog.DiscardHandler)

	tests := []struct {
		name string
		path string
	}{
		{"no CA path", ""},
		{"missing file", filepath.Join(dir, "missing.pem")},
		{"empty file", empty},
		{"garbage PEM", garbage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient("localhost:1", tt.path, logger)
			require.Error(t, err, "нельзя молча откатываться на plaintext")
			assert.Nil(t, c)
			assert.NotContains(t, err.Error(), "%!w", "в тексте ошибки не должно быть форматной ошибки")
		})
	}
}
