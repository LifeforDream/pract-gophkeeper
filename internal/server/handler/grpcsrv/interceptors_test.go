package grpcsrv

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/LifeforDream/pract-gophkeeper/api/gophkeeper/v1"
	"github.com/LifeforDream/pract-gophkeeper/internal/auth"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/userid"
)

// fakeJWT принимает только токен "good" и сопоставляет его с пользователем "user-1".
type fakeJWT struct{}

func (fakeJWT) ValidateJWT(token string) (string, error) {
	if token == "good" {
		return "user-1", nil
	}
	return "", errors.New("bad token")
}

// TestAuthInterceptor проверяет исключения из аутентификации и передачу user_id в контекст.
func TestAuthInterceptor(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		md         metadata.MD
		wantCalled bool
		wantUser   string
		wantCode   codes.Code
	}{
		{"vault method with valid token", pb.VaultService_Put_FullMethodName, metadata.Pairs(auth.TokenKey, "good"), true, "user-1", codes.OK},
		{"token with surrounding spaces", pb.VaultService_Get_FullMethodName, metadata.Pairs(auth.TokenKey, "  good "), true, "user-1", codes.OK},
		{"vault method without metadata", pb.VaultService_Put_FullMethodName, nil, false, "", codes.Unauthenticated},
		{"vault method without token", pb.VaultService_Get_FullMethodName, metadata.Pairs("other", "x"), false, "", codes.Unauthenticated},
		{"vault method with empty token", pb.VaultService_Delete_FullMethodName, metadata.Pairs(auth.TokenKey, ""), false, "", codes.Unauthenticated},
		{"vault method with bad token", pb.VaultService_ListChanges_FullMethodName, metadata.Pairs(auth.TokenKey, "bad"), false, "", codes.Unauthenticated},
		{"Register exempt", pb.AuthService_Register_FullMethodName, nil, true, "", codes.OK},
		{"Login exempt", pb.AuthService_Login_FullMethodName, nil, true, "", codes.OK},
		{"GetKDFParams exempt", pb.AuthService_GetKDFParams_FullMethodName, nil, true, "", codes.OK},
		{"exempt method ignores bad token", pb.AuthService_Login_FullMethodName, metadata.Pairs(auth.TokenKey, "bad"), true, "", codes.OK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.md != nil {
				ctx = metadata.NewIncomingContext(ctx, tt.md)
			}

			called := false
			var gotUser string
			handler := func(ctx context.Context, _ any) (any, error) {
				called = true
				gotUser, _ = userid.FromContext(ctx)
				return "ok", nil
			}

			resp, err := AuthInterceptor(fakeJWT{})(ctx, "req", &grpc.UnaryServerInfo{FullMethod: tt.method}, handler)

			assert.Equal(t, tt.wantCalled, called)
			assert.Equal(t, tt.wantUser, gotUser)
			if tt.wantCode == codes.OK {
				require.NoError(t, err)
				assert.Equal(t, "ok", resp)
				return
			}
			assert.Equal(t, tt.wantCode, status.Code(err))
			assert.Nil(t, resp)
		})
	}
}

// TestLoggingInterceptor проверяет, что вызов логируется с нужным уровнем и без чувствительных данных.
func TestLoggingInterceptor(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantLevel string
		wantCode  string
	}{
		{"ok", nil, "DEBUG", "OK"},
		{"client error", status.Error(codes.NotFound, "no record"), "WARN", "NotFound"},
		{"unauthenticated", status.Error(codes.Unauthenticated, "bad"), "WARN", "Unauthenticated"},
		{"internal", status.Error(codes.Internal, "boom"), "ERROR", "Internal"},
		{"non-status error", errors.New("plain"), "ERROR", "Unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

			ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(auth.TokenKey, "secret-token"))
			handler := func(context.Context, any) (any, error) { return "resp", tt.err }

			resp, err := LoggingInterceptor(logger)(ctx, "secret-body", &grpc.UnaryServerInfo{FullMethod: pb.VaultService_Put_FullMethodName}, handler)

			assert.Equal(t, "resp", resp, "ответ и ошибка должны пройти без изменений")
			assert.Equal(t, tt.err, err)

			out := buf.String()
			assert.Contains(t, out, "level="+tt.wantLevel)
			assert.Contains(t, out, "code="+tt.wantCode)
			assert.Contains(t, out, "method="+pb.VaultService_Put_FullMethodName)
			assert.Contains(t, out, "duration=")
			assert.NotContains(t, out, "secret-token")
			assert.NotContains(t, out, "secret-body")
		})
	}
}

// TestRecoveryInterceptor проверяет, что паника превращается в Internal без утечки значения клиенту,
// а значение и стек попадают в лог.
func TestRecoveryInterceptor(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	info := &grpc.UnaryServerInfo{FullMethod: pb.VaultService_Get_FullMethodName}

	t.Run("panic in handler", func(t *testing.T) {
		buf.Reset()
		handler := func(context.Context, any) (any, error) { panic("secret internals") }

		resp, err := RecoveryInterceptor(logger)(context.Background(), "req", info, handler)

		assert.Nil(t, resp)
		assert.Equal(t, codes.Internal, status.Code(err))
		assert.NotContains(t, err.Error(), "secret internals", "значение паники не должно попасть клиенту")
		assert.Contains(t, buf.String(), "secret internals")
		assert.Contains(t, buf.String(), "stack=")
		assert.Contains(t, buf.String(), "method="+pb.VaultService_Get_FullMethodName)
	})

	t.Run("panic in inner interceptor", func(t *testing.T) {
		buf.Reset()
		inner := func(context.Context, any, *grpc.UnaryServerInfo, grpc.UnaryHandler) (any, error) {
			panic("boom")
		}
		wrapped := func(ctx context.Context, req any) (any, error) {
			return inner(ctx, req, info, nil)
		}

		_, err := RecoveryInterceptor(logger)(context.Background(), "req", info, wrapped)

		assert.Equal(t, codes.Internal, status.Code(err))
	})

	t.Run("no panic passes through", func(t *testing.T) {
		buf.Reset()
		handler := func(context.Context, any) (any, error) { return "ok", nil }

		resp, err := RecoveryInterceptor(logger)(context.Background(), "req", info, handler)

		require.NoError(t, err)
		assert.Equal(t, "ok", resp)
		assert.Empty(t, buf.String())
	})
}
