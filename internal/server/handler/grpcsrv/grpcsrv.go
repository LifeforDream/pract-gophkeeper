// Package grpcsrv содержит эндпоинты gRPC-сервера.
package grpcsrv

import (
	"context"
	"errors"
	"log/slog"
	"math"

	pb "github.com/LifeforDream/pract-gophkeeper/api/gophkeeper/v1"
	"github.com/LifeforDream/pract-gophkeeper/internal/kdfparams"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/domain"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// rpcError - обёртка для ошибок. Клиенту виден только st. cause - для логирования.
type rpcError struct {
	st    *status.Status
	cause error
}

// Error - метод для соответствия интерфейсу error.
func (e *rpcError) Error() string { return e.st.Message() + ": " + e.cause.Error() }

// GRPCStatus отдаёт статус для хендлера
func (e *rpcError) GRPCStatus() *status.Status { return e.st }

// Unwrap нужен для логирования.
func (e *rpcError) Unwrap() error { return e.cause }

func mapErrors(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return &rpcError{status.New(codes.Canceled, "request canceled"), err}
	case errors.Is(err, context.DeadlineExceeded):
		return &rpcError{status.New(codes.DeadlineExceeded, "deadline exceeded"), err}
	case errors.Is(err, domain.ErrNotFound):
		return &rpcError{status.New(codes.NotFound, "not found"), err}
	case errors.Is(err, domain.ErrStaleVersion), errors.Is(err, domain.ErrConflict):
		return &rpcError{status.New(codes.Aborted, "version conflict"), err}
	case errors.Is(err, domain.ErrLoginTaken):
		return &rpcError{status.New(codes.AlreadyExists, "login already in use"), err}
	case errors.Is(err, domain.ErrBadCredentials), errors.Is(err, domain.ErrNoUserID):
		return &rpcError{status.New(codes.Unauthenticated, "unauthenticated"), err}
	case errors.Is(err, domain.ErrInvalidArgument), errors.Is(err, kdfparams.ErrInvalidParams):
		return &rpcError{status.New(codes.InvalidArgument, "invalid argument"), err}
	case errors.Is(err, domain.ErrPayloadTooLarge):
		return &rpcError{status.New(codes.ResourceExhausted, "payload too large"), err}
	default:
		return &rpcError{status.New(codes.Internal, "unexpected server error"), err}
	}
}

// AuthService описывает методы, необходимые для реализации auth-методов сервера.
type AuthService interface {
	Register(ctx context.Context, login string, authKey, salt []byte, params kdfparams.Params) (string, error)
	Login(ctx context.Context, login string, authKey []byte) (string, error)
	GetKDFParams(ctx context.Context, login string) ([]byte, kdfparams.Params, error)
}

// AuthServer реализует методы аутентификации на сервере.
type AuthServer struct {
	pb.UnimplementedAuthServiceServer
	svc AuthService
}

// Register осуществляет регистрацию пользователя и сохраняет его параметры шифрования.
func (s *AuthServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	argonParams, err := paramsFromProto(req.GetParams())
	if err != nil {
		return nil, mapErrors(err)
	}
	token, err := s.svc.Register(ctx, req.GetLogin(), req.GetAuthKey(), req.GetSalt(), argonParams)
	if err != nil {
		return nil, mapErrors(err)
	}
	resp := pb.RegisterResponse_builder{Token: token}.Build()
	return resp, nil
}

// Login принимает пару login + authKey и возвращает JWT.
func (s *AuthServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	token, err := s.svc.Login(ctx, req.GetLogin(), req.GetAuthKey())
	if err != nil {
		return nil, mapErrors(err)
	}
	return pb.LoginResponse_builder{Token: token}.Build(), nil
}

// GetKDFParams возвращает параметры шифрования пользователя, если такой login существует.
// Если login не существует, будет возвращены фейковые параметры, вычисленные для конкретного логина.
func (s *AuthServer) GetKDFParams(ctx context.Context, req *pb.GetKDFParamsRequest) (*pb.GetKDFParamsResponse, error) {
	salt, params, err := s.svc.GetKDFParams(ctx, req.GetLogin())
	if err != nil {
		return nil, mapErrors(err)
	}
	return pb.GetKDFParamsResponse_builder{
		Salt:   salt,
		Params: paramsToProto(params),
	}.Build(), nil
}

func paramsFromProto(params *pb.Argon2Params) (kdfparams.Params, error) {
	p := kdfparams.Params{
		Iterations: params.GetIterations(),
		MemoryKiB:  params.GetMemoryKib(),
	}

	if params.GetParallelism() > math.MaxUint8 {
		return p, kdfparams.ErrInvalidParams
	}

	p.Parallelism = uint8(params.GetParallelism())
	return p, nil
}

func paramsToProto(params kdfparams.Params) *pb.Argon2Params {
	return pb.Argon2Params_builder{
		MemoryKib:   params.MemoryKiB,
		Parallelism: uint32(params.Parallelism),
		Iterations:  params.Iterations,
	}.Build()
}

// VaultService описывает методы, необходимые для реализации хранилища секретов.
type VaultService interface {
	Put(ctx context.Context, record domain.Record) (domain.Record, error)
	Delete(ctx context.Context, recordID string, expectedVersion int64) (int64, error)
	GetRecord(ctx context.Context, recordID string) (domain.Record, error)
	ListChanges(ctx context.Context, sinceRevision int64) ([]domain.Record, int64, error)
}

// VaultServer реализует методы работы с хранилищем на сервере.
type VaultServer struct {
	pb.UnimplementedVaultServiceServer
	svc VaultService
}

func recordFromProtoPut(record *pb.RecordPut) domain.Record {
	return domain.Record{
		ID:          record.GetId(),
		Version:     record.GetExpectedVersion(),
		Header:      record.GetHeader(),
		HeaderNonce: record.GetHeaderNonce(),
		Body:        record.GetBody(),
		BodyNonce:   record.GetBodyNonce(),
	}
}

func recordToProto(record domain.Record) *pb.Record {
	return pb.Record_builder{
		Id:          record.ID,
		Header:      record.Header,
		HeaderNonce: record.HeaderNonce,
		Body:        record.Body,
		BodyNonce:   record.BodyNonce,
		Version:     record.Version,
		Revision:    record.Revision,
		Deleted:     record.Deleted,
	}.Build()
}

// Put создаёт запись (Version == 0) или обновляет (Version > 0).
// Возвращает версию обновлённой записи и номер актуальной ревизии данных пользователя.
func (s *VaultServer) Put(ctx context.Context, req *pb.PutRequest) (*pb.PutResponse, error) {
	rec, err := s.svc.Put(ctx, recordFromProtoPut(req.GetRecord()))
	if err != nil {
		return nil, mapErrors(err)
	}
	return pb.PutResponse_builder{Version: rec.Version, Revision: rec.Revision}.Build(), nil
}

// Delete помечает секрет как удалённый.
func (s *VaultServer) Delete(ctx context.Context, req *pb.DeleteRequest) (*pb.DeleteResponse, error) {
	rev, err := s.svc.Delete(ctx, req.GetId(), req.GetExpectedVersion())
	if err != nil {
		return nil, mapErrors(err)
	}
	return pb.DeleteResponse_builder{Revision: rev}.Build(), nil
}

// Get возвращает запись целиком.
func (s *VaultServer) Get(ctx context.Context, req *pb.GetRequest) (*pb.GetResponse, error) {
	rec, err := s.svc.GetRecord(ctx, req.GetId())
	if err != nil {
		return nil, mapErrors(err)
	}
	return pb.GetResponse_builder{Record: recordToProto(rec)}.Build(), nil
}

// ListChanges возвращает список записей без body. Body можно получить отдельно через Get.
func (s *VaultServer) ListChanges(ctx context.Context, req *pb.ListChangesRequest) (*pb.ListChangesResponse, error) {
	records, revision, err := s.svc.ListChanges(ctx, req.GetSinceRevision())
	if err != nil {
		return nil, mapErrors(err)
	}
	recl := make([]*pb.Record, 0)
	for _, rec := range records {
		recl = append(recl, recordToProto(rec))
	}
	return pb.ListChangesResponse_builder{
		Revision: revision,
		Records:  recl,
	}.Build(), nil
}

// Server нужен, чтобы вернуть два сервера: с бизнес-функционалом и с хелсчеком.
// По сути это обёртка над grpc.Server.
type Server struct {
	*grpc.Server
	health *health.Server
}

// Shutdown вызывает процедуры остановки сервиса.
func (s *Server) Shutdown() {
	s.health.Shutdown()
}

// New создаёт grpc-сервер для обработки запросов и health-сервер для диагностики.
// Возвращаются оба.
// Запуск и остановка должны производиться извне.
func New(authSvc AuthService, vaultSvc VaultService, jwtSvc JWTService, logger *slog.Logger, creds credentials.TransportCredentials) *Server {
	if creds == nil {
		creds = insecure.NewCredentials()
		logger.Warn("TLS ENCRYPTION NOT SET, USING PLAINTEXT")
	}

	s := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			RecoveryInterceptor(logger),
			LoggingInterceptor(logger),
			AuthInterceptor(jwtSvc),
		),
		grpc.Creds(creds),
		grpc.WaitForHandlers(true),
	)
	pb.RegisterAuthServiceServer(s, &AuthServer{svc: authSvc})
	pb.RegisterVaultServiceServer(s, &VaultServer{svc: vaultSvc})

	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(s, healthServer)
	return &Server{s, healthServer}
}
