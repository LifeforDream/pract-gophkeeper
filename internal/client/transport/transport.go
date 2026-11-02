// Package transport хранит логику работы клиента с транспортом.
// На текущем этапе это только gRPC.
package transport

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"

	pb "github.com/LifeforDream/pract-gophkeeper/api/gophkeeper/v1"
	"github.com/LifeforDream/pract-gophkeeper/internal/auth"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/crypto"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
	"github.com/LifeforDream/pract-gophkeeper/internal/kdfparams"
	"github.com/LifeforDream/pract-gophkeeper/internal/kdfparams/pbconv"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Client хранит в себе соединение с сервером
type Client struct {
	conn        *grpc.ClientConn
	logger      *slog.Logger
	authClient  pb.AuthServiceClient
	vaultClient pb.VaultServiceClient
}

// NewClient создаёт подключение к серверу и возвращает его в клиенте.
func NewClient(addr, caCertPath string, logger *slog.Logger) (*Client, error) {
	if logger == nil {
		return nil, errors.New("nil logger is unacceptable")
	}
	var creds credentials.TransportCredentials
	if caCertPath != "" {
		certPEM, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("error reading cert file %s: %w", caCertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(certPEM) {
			return nil, fmt.Errorf("error appending cert %s to pool", caCertPath)
		}

		creds = credentials.NewClientTLSFromCert(pool, "")
	} else {
		logger.Warn("NO CA CERTIFICATE FOUND, USING PLAINTEXT ON CLIENT")
		creds = insecure.NewCredentials()
	}

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("error creating grpc client: %w", err)
	}
	return &Client{
		conn:        conn,
		logger:      logger,
		authClient:  pb.NewAuthServiceClient(conn),
		vaultClient: pb.NewVaultServiceClient(conn),
	}, nil
}

// GetKDFParams получает данные для шифрования на клиенте по логину.
// Возвращает соль и параметры для шифрования.
func (c *Client) GetKDFParams(ctx context.Context, login string) ([]byte, kdfparams.Params, error) {
	req := pb.GetKDFParamsRequest_builder{Login: login}.Build()
	resp, err := c.authClient.GetKDFParams(ctx, req)
	if err != nil {
		return nil, kdfparams.Params{}, mapErr("GetKDFParams", err)
	}
	p, err := pbconv.FromProto(resp.GetParams())
	if err != nil {
		return nil, kdfparams.Params{}, fmt.Errorf("invalid params from server: %w", err)
	}
	return resp.GetSalt(), p, nil
}

// Register регистрирует пользователя на сервере и возвращает токен.
func (c *Client) Register(ctx context.Context, login string, authKey, salt []byte, p kdfparams.Params) (string, error) {
	req := pb.RegisterRequest_builder{
		Login:   login,
		AuthKey: authKey,
		Salt:    salt,
		Params:  pbconv.ToProto(p),
	}.Build()
	resp, err := c.authClient.Register(ctx, req)
	if err != nil {
		return "", mapErr("Register", err)
	}
	return resp.GetToken(), nil
}

// Login аутентифицирует пользователя на сервере и возвращает токен.
func (c *Client) Login(ctx context.Context, login string, authKey []byte) (string, error) {
	req := pb.LoginRequest_builder{Login: login, AuthKey: authKey}.Build()
	resp, err := c.authClient.Login(ctx, req)
	if err != nil {
		return "", mapErr("Login", err)
	}
	return resp.GetToken(), nil
}

// Put отправляет запись на сервер и возвращает новую версию записи.
func (c *Client) Put(ctx context.Context, token, id string, expectedVersion int64, header, body crypto.Sealed) (version int64, err error) {
	req := pb.PutRequest_builder{
		Record: pb.RecordPut_builder{
			Id:              id,
			ExpectedVersion: expectedVersion,
			Header:          header.Ciphertext,
			HeaderNonce:     header.Nonce,
			Body:            body.Ciphertext,
			BodyNonce:       body.Nonce,
		}.Build(),
	}.Build()
	ctx = metadata.AppendToOutgoingContext(ctx, auth.TokenKey, token)
	resp, err := c.vaultClient.Put(ctx, req)
	if err != nil {
		return 0, mapErr("Put", err)
	}
	return resp.GetVersion(), nil
}

// Delete удаляет запись на сервере.
func (c *Client) Delete(ctx context.Context, token, id string, expectedVersion int64) error {
	req := pb.DeleteRequest_builder{Id: id, ExpectedVersion: expectedVersion}.Build()
	ctx = metadata.AppendToOutgoingContext(ctx, auth.TokenKey, token)
	_, err := c.vaultClient.Delete(ctx, req)
	return mapErr("Delete", err)

}

// Get получает запись целиком (с Body).
func (c *Client) Get(ctx context.Context, token, id string) (domain.Record, error) {
	req := pb.GetRequest_builder{Id: id}.Build()
	ctx = metadata.AppendToOutgoingContext(ctx, auth.TokenKey, token)
	resp, err := c.vaultClient.Get(ctx, req)
	if err != nil {
		return domain.Record{}, mapErr("Get", err)
	}
	return recordFromProto(resp.GetRecord()), err
}

// ListChanges получает список записей без тела.
func (c *Client) ListChanges(ctx context.Context, token string, sinceRevision int64) (int64, []domain.Record, error) {
	req := pb.ListChangesRequest_builder{SinceRevision: sinceRevision}.Build()
	ctx = metadata.AppendToOutgoingContext(ctx, auth.TokenKey, token)
	resp, err := c.vaultClient.ListChanges(ctx, req)
	if err != nil {
		return 0, nil, mapErr("ListChanges", err)
	}
	recs := make([]domain.Record, 0)
	for _, rec := range resp.GetRecords() {
		recs = append(recs, recordFromProto(rec))
	}
	return resp.GetRevision(), recs, nil
}

// Close закрывает нижележащее gRPC-соединение.
func (c *Client) Close() error {
	return c.conn.Close()
}

func mapErr(method string, err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		// не gRPC-ошибка (например, ошибка контекста до отправки): оборачиваем как есть
		return fmt.Errorf("%s: %w", method, err)
	}
	switch st.Code() {
	case codes.Unauthenticated:
		if method == "Login" || method == "Register" {
			return domain.ErrInvalidCredentials
		}
		return domain.ErrSessionExpired
	case codes.AlreadyExists:
		return domain.ErrLoginTaken
	case codes.Aborted:
		return domain.ErrConflict
	case codes.NotFound:
		return domain.ErrNotFound
	case codes.ResourceExhausted:
		return domain.ErrTooLarge
	default:
		return fmt.Errorf("%s: %w", method, err)
	}
}

// recordFromProto преобразовывает proto-модель в доменную.
// Он не имеет особой обработки на случай пустого тела Record (из ListChanges).
func recordFromProto(rec *pb.Record) domain.Record {
	return domain.Record{
		ID:       rec.GetId(),
		Header:   crypto.Sealed{Ciphertext: rec.GetHeader(), Nonce: rec.GetHeaderNonce()},
		Body:     crypto.Sealed{Ciphertext: rec.GetBody(), Nonce: rec.GetBodyNonce()},
		Version:  rec.GetVersion(),
		Revision: rec.GetRevision(),
		Deleted:  rec.GetDeleted(),
	}
}
