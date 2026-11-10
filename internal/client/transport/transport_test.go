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
		{"search unauthenticated", "List", st(codes.Unauthenticated), domain.ErrSessionExpired},
		{"already exists", "Register", st(codes.AlreadyExists), domain.ErrLoginTaken},
		{"aborted", "Put", st(codes.Aborted), domain.ErrConflict},
		{"not found", "Get", st(codes.NotFound), domain.ErrNotFound},
		{"resource exhausted", "Put", st(codes.ResourceExhausted), domain.ErrTooLarge},
		{"unavailable", "ListChanges", st(codes.Unavailable), domain.ErrUnavailable},
		{"deadline exceeded", "Get", st(codes.DeadlineExceeded), domain.ErrUnavailable},
		{"tls handshake failure is not a network failure", "ListChanges",
			status.Error(codes.Unavailable, "connection error: desc = \"transport: authentication handshake failed: x509: certificate signed by unknown authority\""), nil},
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
		Id:        "id",
		Type:      pb.RecordType_RECORD_TYPE_LOGIN,
		Name:      "mail",
		Meta:      []*pb.Meta{pb.Meta_builder{Key: "url", Value: "example.com"}.Build()},
		Body:      []byte("b"),
		BodyNonce: []byte("bn"),
		Version:   3,
		Revision:  7,
		Deleted:   true,
	}.Build()

	got, err := recordFromProto(rec)
	require.NoError(t, err)
	assert.Equal(t, "id", got.ID)
	assert.Equal(t, domain.Header{
		Type: domain.TypeLogin,
		Name: "mail",
		Meta: []domain.MetaItem{{Key: "url", Value: "example.com"}},
	}, got.Header)
	assert.Equal(t, []byte("b"), got.Body.Ciphertext)
	assert.Equal(t, []byte("bn"), got.Body.Nonce)
	assert.EqualValues(t, 3, got.Version)
	assert.EqualValues(t, 7, got.Revision)
	assert.True(t, got.Deleted)

	// запись из ListChanges приходит без тела
	empty, err := recordFromProto(pb.Record_builder{Id: "x", Type: pb.RecordType_RECORD_TYPE_TEXT}.Build())
	require.NoError(t, err)
	assert.Empty(t, empty.Body.Ciphertext)

	// неуказанный или неизвестный тип с сервера - ошибка, а не тип по умолчанию
	for _, bad := range []pb.RecordType{pb.RecordType_RECORD_TYPE_UNSPECIFIED, pb.RecordType(99)} {
		_, err = recordFromProto(pb.Record_builder{Id: "x", Type: bad}.Build())
		assert.ErrorIs(t, err, domain.ErrInvalidData)
	}
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

func TestFilterToProto(t *testing.T) {
	got, err := filterToProto(domain.Filter{Type: domain.TypeText, MetaKey: "k", NameFragment: "n"})
	require.NoError(t, err)
	assert.Equal(t, pb.RecordType_RECORD_TYPE_TEXT, got.GetType())
	assert.Equal(t, "k", got.GetMetaKey())
	assert.Equal(t, "n", got.GetNameFragment())

	got, err = filterToProto(domain.Filter{})
	require.NoError(t, err)
	assert.Equal(t, pb.RecordType_RECORD_TYPE_UNSPECIFIED, got.GetType(), "пустой тип - без фильтра по типу")

	_, err = filterToProto(domain.Filter{Type: "bogus"})
	assert.ErrorIs(t, err, domain.ErrInvalidData)
}
