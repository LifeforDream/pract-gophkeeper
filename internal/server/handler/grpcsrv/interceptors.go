package grpcsrv

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"time"

	pb "github.com/LifeforDream/pract-gophkeeper/api/gophkeeper/v1"
	"github.com/LifeforDream/pract-gophkeeper/internal/auth"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/userid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// JWTService описывает необходимые методы для валидации JWT.
type JWTService interface {
	ValidateJWT(token string) (string, error)
}

// isPublicMethod проверяет, что метод доступен без токена.
func isPublicMethod(fullMethod string) bool {
	switch fullMethod {
	case pb.AuthService_GetKDFParams_FullMethodName,
		pb.AuthService_Register_FullMethodName,
		pb.AuthService_Login_FullMethodName,
		healthpb.Health_Check_FullMethodName:
		return true
	default:
		return false
	}
}

// AuthInterceptor проверяет аутентификацию на маршрутах, не исключенных из проверок.
func AuthInterceptor(svc JWTService) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		if isPublicMethod(info.FullMethod) {
			return handler(ctx, req)
		}
		md, ok := metadata.FromIncomingContext(ctx)
		var token string
		if ok {
			tokenmd := md.Get(auth.TokenKey)
			for _, val := range tokenmd {
				if val != "" {
					token = strings.TrimSpace(val)
					break
				}
			}
		} else {
			return nil, status.Error(codes.Unauthenticated, "no token in metadata")
		}
		if token == "" {
			return nil, status.Error(codes.Unauthenticated, "empty token")
		}
		userID, err := svc.ValidateJWT(token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid JWT")
		}
		ctx = userid.NewContext(ctx, userID)
		return handler(ctx, req)
	}
}

// RecoveryInterceptor перехватывает панику в нижестоящих interceptor-ах и обработчике и превращает её в ошибку Internal.
//
// Должен стоять в цепочке первым (самым внешним), чтобы защищать и остальные interceptor-ы. Паника проходит
// сквозь них, поэтому LoggingInterceptor её не видит: значение паники и стек вызовов пишутся в лог здесь.
// Клиенту значение паники не отдаётся, чтобы не раскрывать внутренности сервера.
func RecoveryInterceptor(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (_ any, err error) {
		defer func() {
			if p := recover(); p != nil {
				logger.ErrorContext(ctx, "panic in grpc call",
					"method", info.FullMethod,
					"panic", fmt.Sprint(p),
					"stack", string(debug.Stack()),
				)
				err = status.Error(codes.Internal, "unexpected server error")
			}
		}()

		return handler(ctx, req)
	}
}

// LoggingInterceptor логирует каждый унарный вызов: метод, код ответа, длительность и адрес клиента.
//
// Уровень зависит от кода: успех и ошибки клиента (NotFound, Aborted, Unauthenticated и т.п.) — Debug и Warn,
// внутренние ошибки сервера — Error. Тела запросов и ответов, токены и метаданные не логируются.
func LoggingInterceptor(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)

		code := status.Code(err)
		attrs := []any{
			"method", info.FullMethod,
			"code", code.String(),
			"duration", time.Since(start),
		}
		if err != nil {
			attrs = append(attrs, "error", err)
		}
		if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
			attrs = append(attrs, "peer", p.Addr.String())
		}
		logger.Log(ctx, logLevel(code), "grpc call", attrs...)
		return resp, err
	}
}

// logLevel сопоставляет код gRPC уровню логирования.
func logLevel(code codes.Code) slog.Level {
	switch code {
	case codes.OK:
		return slog.LevelDebug
	case codes.Unknown, codes.Internal, codes.DataLoss, codes.Unimplemented, codes.Unavailable:
		return slog.LevelError
	default:
		return slog.LevelWarn
	}
}
