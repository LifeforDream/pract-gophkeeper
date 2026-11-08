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

// NewClient создаёт подключение к серверу по TLS и возвращает его в клиенте.
// Путь к сертификату CA обязателен: без него возвращается ошибка, а не соединение без шифрования.
func NewClient(addr, caCertPath string, logger *slog.Logger) (*Client, error) {
	if logger == nil {
		return nil, errors.New("nil logger is unacceptable")
	}
	if caCertPath == "" {
		return nil, errors.New("CA certificate path is required")
	}
	certPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("error reading cert file %s: %w", caCertPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		return nil, fmt.Errorf("error appending cert %s to pool", caCertPath)
	}

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(pool, "")))
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
func (c *Client) Put(ctx context.Context, token, id string, expectedVersion int64, header domain.Header, body crypto.Sealed) (version int64, err error) {
	recType, err := recordTypeToProto(header.Type)
	if err != nil {
		return 0, fmt.Errorf("Put: %w", err)
	}
	req := pb.PutRequest_builder{
		Record: pb.RecordPut_builder{
			Id:              id,
			ExpectedVersion: expectedVersion,
			Type:            recType,
			Name:            header.Name,
			Meta:            metaToProto(header.Meta),
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
	rec, err := recordFromProto(resp.GetRecord())
	if err != nil {
		return domain.Record{}, fmt.Errorf("Get: %w", err)
	}
	return rec, nil
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
		r, err := recordFromProto(rec)
		if err != nil {
			return 0, nil, fmt.Errorf("ListChanges: %w", err)
		}
		recs = append(recs, r)
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
	case codes.Canceled:
		return context.Canceled
	default:
		return fmt.Errorf("%s: %w", method, err)
	}
}

// recordFromProto преобразовывает proto-модель в доменную.
// Он не имеет особой обработки на случай пустого тела Record (из ListChanges).
// Неизвестный тип записи - ошибка.
func recordFromProto(rec *pb.Record) (domain.Record, error) {
	recType, err := recordTypeFromProto(rec.GetType())
	if err != nil {
		return domain.Record{}, fmt.Errorf("record %s: %w", rec.GetId(), err)
	}
	header := domain.Header{Type: recType, Name: rec.GetName()}
	for _, m := range rec.GetMeta() {
		header.Meta = append(header.Meta, domain.MetaItem{Key: m.GetKey(), Value: m.GetValue()})
	}
	return domain.Record{
		ID:       rec.GetId(),
		Header:   header,
		Body:     crypto.Sealed{Ciphertext: rec.GetBody(), Nonce: rec.GetBodyNonce()},
		Version:  rec.GetVersion(),
		Revision: rec.GetRevision(),
		Deleted:  rec.GetDeleted(),
	}, nil
}

func metaToProto(meta []domain.MetaItem) []*pb.Meta {
	items := make([]*pb.Meta, 0, len(meta))
	for _, m := range meta {
		items = append(items, pb.Meta_builder{Key: m.Key, Value: m.Value}.Build())
	}
	return items
}

func recordTypeFromProto(t pb.RecordType) (domain.RecType, error) {
	switch t {
	case pb.RecordType_RECORD_TYPE_LOGIN:
		return domain.TypeLogin, nil
	case pb.RecordType_RECORD_TYPE_TEXT:
		return domain.TypeText, nil
	case pb.RecordType_RECORD_TYPE_BINARY:
		return domain.TypeBinary, nil
	case pb.RecordType_RECORD_TYPE_CARD:
		return domain.TypeCard, nil
	}
	return "", fmt.Errorf("unexpected record type %s: %w", t, domain.ErrInvalidData)
}

func recordTypeToProto(t domain.RecType) (pb.RecordType, error) {
	switch t {
	case domain.TypeLogin:
		return pb.RecordType_RECORD_TYPE_LOGIN, nil
	case domain.TypeText:
		return pb.RecordType_RECORD_TYPE_TEXT, nil
	case domain.TypeBinary:
		return pb.RecordType_RECORD_TYPE_BINARY, nil
	case domain.TypeCard:
		return pb.RecordType_RECORD_TYPE_CARD, nil
	}
	return pb.RecordType_RECORD_TYPE_UNSPECIFIED, fmt.Errorf("unexpected record type %q: %w", t, domain.ErrInvalidData)
}
