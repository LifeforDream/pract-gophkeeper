package grpcsrv_test

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/LifeforDream/pract-gophkeeper/api/gophkeeper/v1"
	"github.com/LifeforDream/pract-gophkeeper/internal/auth"
	"github.com/LifeforDream/pract-gophkeeper/internal/kdfparams"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/domain"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/handler/grpcsrv"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/jwtauth"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/repository/memory"
	authcase "github.com/LifeforDream/pract-gophkeeper/internal/server/usecase/auth"
	vaultcase "github.com/LifeforDream/pract-gophkeeper/internal/server/usecase/vault"
)

var jwtSecret = []byte("test-jwt-secret")

// testEnv — сервер на реальных use case и memory-репозиториях, доступный клиенту через bufconn.
type testEnv struct {
	conn  *grpc.ClientConn
	auth  pb.AuthServiceClient
	vault pb.VaultServiceClient
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// startServer поднимает gRPC-сервер на bufconn и возвращает клиентское соединение.
// Сервер останавливается в t.Cleanup, горутина Serve дожидается завершения.
func startServer(t *testing.T, authSvc grpcsrv.AuthService, vaultSvc grpcsrv.VaultService) (*grpc.Server, *grpc.ClientConn) {
	t.Helper()

	jwtSvc, err := jwtauth.NewJWTService(jwtSecret, time.Hour)
	require.NoError(t, err)
	return startServerWithJWT(t, authSvc, vaultSvc, jwtSvc)
}

// startServerWithJWT — то же, что startServer, но с заданным сервисом проверки JWT.
func startServerWithJWT(t *testing.T, authSvc grpcsrv.AuthService, vaultSvc grpcsrv.VaultService, jwtSvc grpcsrv.JWTService) (*grpc.Server, *grpc.ClientConn) {
	t.Helper()

	srv := grpcsrv.New(authSvc, vaultSvc, jwtSvc, discardLogger(), nil)
	lis := bufconn.Listen(1 << 20)

	var wg sync.WaitGroup
	wg.Go(func() {
		_ = srv.Serve(lis)
	})

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
		wg.Wait()
	})
	return srv.Server, conn
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()

	jwtSvc, err := jwtauth.NewJWTService(jwtSecret, time.Hour)
	require.NoError(t, err)
	authSvc := authcase.NewService(memory.NewUsersRepo(), jwtSvc, []byte("fake-salt-secret"))
	vaultSvc, err := vaultcase.NewService(memory.NewRecordsRepo(),
		vaultcase.DefaultHeaderSizeLimit(), vaultcase.DefaultBodySizeLimit())
	require.NoError(t, err)

	_, conn := startServer(t, authSvc, vaultSvc)
	return &testEnv{conn: conn, auth: pb.NewAuthServiceClient(conn), vault: pb.NewVaultServiceClient(conn)}
}

func validParams() *pb.Argon2Params {
	return pb.Argon2Params_builder{MemoryKib: kdfparams.MemoryLowerLimitKiB, Iterations: 1, Parallelism: 1}.Build()
}

func authKeyOf(login string) []byte { return []byte("auth-key-for-" + login) }

func saltOf(login string) []byte {
	s := []byte(login + strings.Repeat("-", kdfparams.SaltSize))
	return s[:kdfparams.SaltSize]
}

// register регистрирует пользователя и возвращает его токен.
func (e *testEnv) register(t *testing.T, login string) string {
	t.Helper()
	resp, err := e.auth.Register(context.Background(), pb.RegisterRequest_builder{
		Login: login, AuthKey: authKeyOf(login), Salt: saltOf(login), Params: validParams(),
	}.Build())
	require.NoError(t, err)
	require.NotEmpty(t, resp.GetToken())
	return resp.GetToken()
}

func withToken(token string) context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), auth.TokenKey, token)
}

func putReq(id string, expectedVersion int64, header, body string) *pb.PutRequest {
	return pb.PutRequest_builder{Record: pb.RecordPut_builder{
		Id:              id,
		ExpectedVersion: expectedVersion,
		Header:          []byte(header),
		HeaderNonce:     []byte("header-nonce"),
		Body:            []byte(body),
		BodyNonce:       []byte("body-nonce"),
	}.Build()}.Build()
}

func requireCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	require.Error(t, err)
	assert.Equal(t, want, status.Code(err), "err: %v", err)
}

// TestFullFlow проходит register → login → put → list → get → конфликт версий → delete → list.
func TestFullFlow(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	e.register(t, "alice")

	loginResp, err := e.auth.Login(ctx, pb.LoginRequest_builder{Login: "alice", AuthKey: authKeyOf("alice")}.Build())
	require.NoError(t, err)
	require.NotEmpty(t, loginResp.GetToken())
	uctx := withToken(loginResp.GetToken())

	kdf, err := e.auth.GetKDFParams(ctx, pb.GetKDFParamsRequest_builder{Login: "alice"}.Build())
	require.NoError(t, err)
	assert.Equal(t, saltOf("alice"), kdf.GetSalt())
	assert.Equal(t, uint32(kdfparams.MemoryLowerLimitKiB), kdf.GetParams().GetMemoryKib())

	// create
	created, err := e.vault.Put(uctx, putReq("rec-1", 0, "header-v1", "body-v1"))
	require.NoError(t, err)
	assert.NotZero(t, created.GetVersion())
	assert.NotZero(t, created.GetRevision())

	// list: только заголовки
	list, err := e.vault.ListChanges(uctx, pb.ListChangesRequest_builder{SinceRevision: 0}.Build())
	require.NoError(t, err)
	require.Len(t, list.GetRecords(), 1)
	assert.Equal(t, "rec-1", list.GetRecords()[0].GetId())
	assert.Equal(t, []byte("header-v1"), list.GetRecords()[0].GetHeader())
	assert.Empty(t, list.GetRecords()[0].GetBody(), "ListChanges не должен отдавать body")
	assert.Equal(t, created.GetRevision(), list.GetRevision())

	// get: заголовок и тело
	got, err := e.vault.Get(uctx, pb.GetRequest_builder{Id: "rec-1"}.Build())
	require.NoError(t, err)
	assert.Equal(t, []byte("header-v1"), got.GetRecord().GetHeader())
	assert.Equal(t, []byte("body-v1"), got.GetRecord().GetBody())
	assert.Equal(t, []byte("body-nonce"), got.GetRecord().GetBodyNonce())

	// update с актуальной версией
	updated, err := e.vault.Put(uctx, putReq("rec-1", created.GetVersion(), "header-v2", "body-v2"))
	require.NoError(t, err)
	assert.Greater(t, updated.GetVersion(), created.GetVersion())
	assert.Greater(t, updated.GetRevision(), created.GetRevision())

	// повторный update со старой версией — конфликт
	_, err = e.vault.Put(uctx, putReq("rec-1", created.GetVersion(), "header-v3", "body-v3"))
	requireCode(t, err, codes.Aborted)

	// конфликт не должен изменить данные
	got, err = e.vault.Get(uctx, pb.GetRequest_builder{Id: "rec-1"}.Build())
	require.NoError(t, err)
	assert.Equal(t, []byte("body-v2"), got.GetRecord().GetBody())

	// delete с устаревшей версией — конфликт, с актуальной — успех
	_, err = e.vault.Delete(uctx, pb.DeleteRequest_builder{Id: "rec-1", ExpectedVersion: created.GetVersion()}.Build())
	requireCode(t, err, codes.Aborted)
	del, err := e.vault.Delete(uctx, pb.DeleteRequest_builder{Id: "rec-1", ExpectedVersion: updated.GetVersion()}.Build())
	require.NoError(t, err)
	assert.Greater(t, del.GetRevision(), updated.GetRevision())

	// после удаления: полный список пуст, инкрементальный содержит надгробие
	list, err = e.vault.ListChanges(uctx, pb.ListChangesRequest_builder{SinceRevision: 0}.Build())
	require.NoError(t, err)
	assert.Empty(t, list.GetRecords())

	list, err = e.vault.ListChanges(uctx, pb.ListChangesRequest_builder{SinceRevision: updated.GetRevision()}.Build())
	require.NoError(t, err)
	require.Len(t, list.GetRecords(), 1)
	assert.True(t, list.GetRecords()[0].GetDeleted())
	assert.Equal(t, del.GetRevision(), list.GetRevision())

}

// TestAuthErrors проверяет коды ошибок AuthService.
func TestAuthErrors(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.register(t, "alice")

	tooLowMemory := pb.Argon2Params_builder{MemoryKib: kdfparams.MemoryLowerLimitKiB - 1, Iterations: 1, Parallelism: 1}.Build()
	hugeParallelism := pb.Argon2Params_builder{MemoryKib: kdfparams.MemoryLowerLimitKiB, Iterations: 1, Parallelism: 1 << 20}.Build()

	registerTests := []struct {
		name string
		req  *pb.RegisterRequest
		want codes.Code
	}{
		{"login taken", pb.RegisterRequest_builder{Login: "alice", AuthKey: authKeyOf("x"), Salt: saltOf("x"), Params: validParams()}.Build(), codes.AlreadyExists},
		{"empty login", pb.RegisterRequest_builder{Login: "", AuthKey: authKeyOf("x"), Salt: saltOf("x"), Params: validParams()}.Build(), codes.InvalidArgument},
		{"empty auth key", pb.RegisterRequest_builder{Login: "bob", Salt: saltOf("bob"), Params: validParams()}.Build(), codes.InvalidArgument},
		{"short salt", pb.RegisterRequest_builder{Login: "bob", AuthKey: authKeyOf("bob"), Salt: []byte("short"), Params: validParams()}.Build(), codes.InvalidArgument},
		{"memory below limit", pb.RegisterRequest_builder{Login: "bob", AuthKey: authKeyOf("bob"), Salt: saltOf("bob"), Params: tooLowMemory}.Build(), codes.InvalidArgument},
		{"parallelism overflows uint8", pb.RegisterRequest_builder{Login: "bob", AuthKey: authKeyOf("bob"), Salt: saltOf("bob"), Params: hugeParallelism}.Build(), codes.InvalidArgument},
		{"missing params", pb.RegisterRequest_builder{Login: "bob", AuthKey: authKeyOf("bob"), Salt: saltOf("bob")}.Build(), codes.InvalidArgument},
	}
	for _, tt := range registerTests {
		t.Run("register/"+tt.name, func(t *testing.T) {
			_, err := e.auth.Register(ctx, tt.req)
			requireCode(t, err, tt.want)
		})
	}

	t.Run("failed register does not create the user", func(t *testing.T) {
		_, err := e.auth.Login(ctx, pb.LoginRequest_builder{Login: "bob", AuthKey: authKeyOf("bob")}.Build())
		requireCode(t, err, codes.Unauthenticated)
	})

	t.Run("login empty fields", func(t *testing.T) {
		_, err := e.auth.Login(ctx, pb.LoginRequest_builder{}.Build())
		requireCode(t, err, codes.InvalidArgument)
	})
}

// TestLogin_UnknownLoginIndistinguishableFromWrongPassword — перечисление пользователей через Login невозможно.
func TestLogin_UnknownLoginIndistinguishableFromWrongPassword(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.register(t, "alice")

	_, errWrong := e.auth.Login(ctx, pb.LoginRequest_builder{Login: "alice", AuthKey: []byte("wrong")}.Build())
	_, errUnknown := e.auth.Login(ctx, pb.LoginRequest_builder{Login: "nobody", AuthKey: []byte("wrong")}.Build())

	requireCode(t, errWrong, codes.Unauthenticated)
	requireCode(t, errUnknown, codes.Unauthenticated)
	assert.Equal(t, status.Convert(errWrong).Message(), status.Convert(errUnknown).Message())
}

// TestGetKDFParams_UnknownLogin проверяет, что для неизвестного логина отдаётся устойчивая фейковая соль.
func TestGetKDFParams_UnknownLogin(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.register(t, "alice")

	get := func(login string) *pb.GetKDFParamsResponse {
		t.Helper()
		resp, err := e.auth.GetKDFParams(ctx, pb.GetKDFParamsRequest_builder{Login: login}.Build())
		require.NoError(t, err)
		return resp
	}

	first, second := get("nobody"), get("nobody")
	assert.Equal(t, first.GetSalt(), second.GetSalt(), "фейковая соль должна быть стабильной")
	assert.Len(t, first.GetSalt(), kdfparams.SaltSize)
	assert.NotEqual(t, first.GetSalt(), get("someone-else").GetSalt())

	real := get("alice")
	assert.Len(t, real.GetSalt(), len(first.GetSalt()), "длина соли не должна выдавать существование аккаунта")
	require.NoError(t, kdfparams.Params{
		MemoryKiB:   first.GetParams().GetMemoryKib(),
		Iterations:  first.GetParams().GetIterations(),
		Parallelism: uint8(first.GetParams().GetParallelism()),
	}.Validate(), "фейковые параметры должны быть допустимыми для клиента")
}

// TestVault_Unauthenticated — все методы VaultService требуют валидный токен.
func TestVault_Unauthenticated(t *testing.T) {
	e := newEnv(t)

	forged, err := jwtauth.NewJWTService([]byte("another-secret"), time.Hour)
	require.NoError(t, err)
	forgedToken, err := forged.CreateJWT("some-user")
	require.NoError(t, err)

	tests := []struct {
		name string
		ctx  context.Context
	}{
		{"no metadata", context.Background()},
		{"empty token", withToken("")},
		{"garbage token", withToken("not-a-jwt")},
		{"token signed with another secret", withToken(forgedToken)},
	}
	calls := map[string]func(ctx context.Context) error{
		"Put": func(ctx context.Context) error {
			_, err := e.vault.Put(ctx, putReq("r", 0, "h", "b"))
			return err
		},
		"Get": func(ctx context.Context) error {
			_, err := e.vault.Get(ctx, pb.GetRequest_builder{Id: "r"}.Build())
			return err
		},
		"Delete": func(ctx context.Context) error {
			_, err := e.vault.Delete(ctx, pb.DeleteRequest_builder{Id: "r", ExpectedVersion: 1}.Build())
			return err
		},
		"ListChanges": func(ctx context.Context) error {
			_, err := e.vault.ListChanges(ctx, pb.ListChangesRequest_builder{}.Build())
			return err
		},
	}
	for _, tt := range tests {
		for name, call := range calls {
			t.Run(tt.name+"/"+name, func(t *testing.T) {
				requireCode(t, call(tt.ctx), codes.Unauthenticated)
			})
		}
	}
}

// TestVault_ExpiredAndTamperedTokens — просроченные и подделанные токены отклоняются interceptor-ом
// с Unauthenticated, а неизменённый токен того же пользователя проходит.
func TestVault_ExpiredAndTamperedTokens(t *testing.T) {
	e := newEnv(t)
	aliceToken := e.register(t, "alice")
	bobToken := e.register(t, "bob")

	subOf := func(token string) string {
		claims := jwt.MapClaims{}
		_, _, err := jwt.NewParser().ParseUnverified(token, claims)
		require.NoError(t, err)
		sub, err := claims.GetSubject()
		require.NoError(t, err)
		return sub
	}
	// signedWith подписывает токен тем же секретом и издателем, что и сервер; различаются только время и субъект.
	signedWith := func(sub string, exp time.Time) string {
		tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"iss": "pract-gophkeeper",
			"sub": sub,
			"iat": jwt.NewNumericDate(exp.Add(-time.Hour)),
			"exp": jwt.NewNumericDate(exp),
		}).SignedString(jwtSecret)
		require.NoError(t, err)
		return tok
	}

	parts := strings.Split(aliceToken, ".")
	require.Len(t, parts, 3)
	// Подмена субъекта на Боба при прежней подписи Алисы.
	bobPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"pract-gophkeeper","sub":"` + subOf(bobToken) + `","exp":` +
		strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `}`))
	// Меняется символ в середине подписи: у последнего символа часть битов не используется, и замена могла бы не изменить подпись.
	sig := []byte(parts[2])
	sig[len(sig)/2] ^= 0x01

	tests := []struct {
		name  string
		token string
		valid bool
	}{
		{"valid control", aliceToken, true},
		{"expired", signedWith(subOf(aliceToken), time.Now().Add(-time.Minute)), false},
		{"tampered signature", parts[0] + "." + parts[1] + "." + string(sig), false},
		{"tampered subject", parts[0] + "." + bobPayload + "." + parts[2], false},
		{"truncated", aliceToken[:len(aliceToken)/2], false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := e.vault.ListChanges(withToken(tt.token), pb.ListChangesRequest_builder{}.Build())
			if tt.valid {
				require.NoError(t, err)
				return
			}
			requireCode(t, err, codes.Unauthenticated)

			_, err = e.vault.Get(withToken(tt.token), pb.GetRequest_builder{Id: "r"}.Build())
			requireCode(t, err, codes.Unauthenticated)
		})
	}
}

// TestVault_CrossUserIsolation — чужая запись недоступна, а тот же id у другого пользователя независим.
func TestVault_CrossUserIsolation(t *testing.T) {
	e := newEnv(t)
	alice, bob := withToken(e.register(t, "alice")), withToken(e.register(t, "bob"))

	created, err := e.vault.Put(alice, putReq("shared-id", 0, "alice-header", "alice-body"))
	require.NoError(t, err)

	_, err = e.vault.Get(bob, pb.GetRequest_builder{Id: "shared-id"}.Build())
	requireCode(t, err, codes.NotFound)

	_, err = e.vault.Delete(bob, pb.DeleteRequest_builder{Id: "shared-id", ExpectedVersion: created.GetVersion()}.Build())
	requireCode(t, err, codes.NotFound)

	_, err = e.vault.Put(bob, putReq("shared-id", created.GetVersion(), "bob-header", "bob-body"))
	requireCode(t, err, codes.NotFound)

	// Боб создаёт запись с чужим id независимо.
	_, err = e.vault.Put(bob, putReq("shared-id", 0, "bob-header", "bob-body"))
	require.NoError(t, err)

	got, err := e.vault.Get(alice, pb.GetRequest_builder{Id: "shared-id"}.Build())
	require.NoError(t, err)
	assert.Equal(t, []byte("alice-body"), got.GetRecord().GetBody())

	list, err := e.vault.ListChanges(bob, pb.ListChangesRequest_builder{}.Build())
	require.NoError(t, err)
	require.Len(t, list.GetRecords(), 1)
	assert.Equal(t, []byte("bob-header"), list.GetRecords()[0].GetHeader())
}

// TestVault_Validation проверяет коды ошибок при некорректных данных.
func TestVault_Validation(t *testing.T) {
	e := newEnv(t)
	ctx := withToken(e.register(t, "alice"))

	_, err := e.vault.Put(ctx, putReq("existing", 0, "h", "b"))
	require.NoError(t, err)

	hugeHeader := strings.Repeat("h", vaultcase.DefaultHeaderSizeLimit()+1)
	hugeBody := strings.Repeat("b", vaultcase.DefaultBodySizeLimit()+1)

	tests := []struct {
		name string
		req  *pb.PutRequest
		want codes.Code
	}{
		{"empty id", putReq("", 0, "h", "b"), codes.InvalidArgument},
		{"empty header", putReq("r", 0, "", "b"), codes.InvalidArgument},
		{"empty body", putReq("r", 0, "h", ""), codes.InvalidArgument},
		{"negative version", putReq("r", -1, "h", "b"), codes.InvalidArgument},
		{"header over limit", putReq("r", 0, hugeHeader, "b"), codes.ResourceExhausted},
		{"body over limit", putReq("r", 0, "h", hugeBody), codes.ResourceExhausted},
		{"create over existing id", putReq("existing", 0, "h2", "b2"), codes.Aborted},
		{"update missing record", putReq("missing", 5, "h", "b"), codes.NotFound},
	}
	for _, tt := range tests {
		t.Run("put/"+tt.name, func(t *testing.T) {
			_, err := e.vault.Put(ctx, tt.req)
			requireCode(t, err, tt.want)
		})
	}

	t.Run("create over existing id keeps data", func(t *testing.T) {
		got, err := e.vault.Get(ctx, pb.GetRequest_builder{Id: "existing"}.Build())
		require.NoError(t, err)
		assert.Equal(t, []byte("b"), got.GetRecord().GetBody())
	})

	t.Run("get missing", func(t *testing.T) {
		_, err := e.vault.Get(ctx, pb.GetRequest_builder{Id: "missing"}.Build())
		requireCode(t, err, codes.NotFound)
	})
	t.Run("delete missing", func(t *testing.T) {
		_, err := e.vault.Delete(ctx, pb.DeleteRequest_builder{Id: "missing", ExpectedVersion: 1}.Build())
		requireCode(t, err, codes.NotFound)
	})
	// Use case не проверяет пустой id у Get и Delete, поэтому клиент получает NotFound, а не InvalidArgument,
	// как у Put. Тесты фиксируют текущее поведение: главное, что вызов не падает и не затрагивает чужие данные.
	t.Run("get empty id", func(t *testing.T) {
		_, err := e.vault.Get(ctx, pb.GetRequest_builder{Id: ""}.Build())
		requireCode(t, err, codes.NotFound)
	})
	t.Run("delete empty id", func(t *testing.T) {
		_, err := e.vault.Delete(ctx, pb.DeleteRequest_builder{Id: "", ExpectedVersion: 1}.Build())
		requireCode(t, err, codes.NotFound)
	})
	t.Run("list negative revision", func(t *testing.T) {
		_, err := e.vault.ListChanges(ctx, pb.ListChangesRequest_builder{SinceRevision: -1}.Build())
		requireCode(t, err, codes.InvalidArgument)
	})
}

// TestVault_UpdateTombstone — обновление удалённой записи даёт определённый результат, а не панику.
func TestVault_UpdateTombstone(t *testing.T) {
	e := newEnv(t)
	ctx := withToken(e.register(t, "alice"))

	created, err := e.vault.Put(ctx, putReq("r", 0, "h", "b"))
	require.NoError(t, err)
	_, err = e.vault.Delete(ctx, pb.DeleteRequest_builder{Id: "r", ExpectedVersion: created.GetVersion()}.Build())
	require.NoError(t, err)

	_, err = e.vault.Put(ctx, putReq("r", created.GetVersion(), "h2", "b2"))
	require.Error(t, err)
	assert.Contains(t, []codes.Code{codes.NotFound, codes.Aborted}, status.Code(err), "err: %v", err)
}

// TestHealth — стандартный health-сервис зарегистрирован и отвечает SERVING.
// Токен передаётся, потому что план не относит Health к методам без аутентификации.
func TestHealth(t *testing.T) {
	e := newEnv(t)

	resp, err := healthpb.NewHealthClient(e.conn).Check(withToken(""), &healthpb.HealthCheckRequest{})
	require.NoError(t, err)
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
}

// panicVault — VaultService, паникующий на любом вызове.
type panicVault struct{}

func (panicVault) Put(context.Context, domain.Record) (domain.Record, error) { panic("boom") }
func (panicVault) Delete(context.Context, string, int64) (int64, error)      { panic("boom") }
func (panicVault) GetRecord(context.Context, string) (domain.Record, error)  { panic("boom") }
func (panicVault) ListChanges(context.Context, int64) ([]domain.Record, int64, error) {
	panic("boom")
}

// TestRecovery — паника в обработчике превращается в Internal и не валит сервер.
func TestRecovery(t *testing.T) {
	jwtSvc, err := jwtauth.NewJWTService(jwtSecret, time.Hour)
	require.NoError(t, err)
	token, err := jwtSvc.CreateJWT("user-1")
	require.NoError(t, err)

	_, conn := startServer(t, authcase.NewService(memory.NewUsersRepo(), jwtSvc, []byte("s")), panicVault{})
	vault := pb.NewVaultServiceClient(conn)

	_, err = vault.Get(withToken(token), pb.GetRequest_builder{Id: "r"}.Build())
	requireCode(t, err, codes.Internal)

	// сервер продолжает отвечать
	resp, err := healthpb.NewHealthClient(conn).Check(withToken(token), &healthpb.HealthCheckRequest{})
	require.NoError(t, err)
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
}

// blockingVault — VaultService, у которого ListChanges блокируется до сигнала release.
type blockingVault struct {
	panicVault
	entered chan struct{}
	release chan struct{}
}

func (b *blockingVault) ListChanges(context.Context, int64) ([]domain.Record, int64, error) {
	close(b.entered)
	<-b.release
	return nil, 42, nil
}

// TestGracefulStop_WaitsForInflightRequest — GracefulStop ждёт завершения запроса в полёте.
func TestGracefulStop_WaitsForInflightRequest(t *testing.T) {
	jwtSvc, err := jwtauth.NewJWTService(jwtSecret, time.Hour)
	require.NoError(t, err)
	token, err := jwtSvc.CreateJWT("user-1")
	require.NoError(t, err)

	bv := &blockingVault{entered: make(chan struct{}), release: make(chan struct{})}
	srv, conn := startServer(t, authcase.NewService(memory.NewUsersRepo(), jwtSvc, []byte("s")), bv)
	vault := pb.NewVaultServiceClient(conn)

	type result struct {
		resp *pb.ListChangesResponse
		err  error
	}
	rpcDone := make(chan result, 1)
	go func() {
		resp, err := vault.ListChanges(withToken(token), pb.ListChangesRequest_builder{}.Build())
		rpcDone <- result{resp, err}
	}()

	select {
	case <-bv.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("запрос не дошёл до обработчика")
	}

	stopped := make(chan struct{})
	go func() { srv.GracefulStop(); close(stopped) }()

	select {
	case <-stopped:
		t.Fatal("GracefulStop завершился, не дождавшись запроса в полёте")
	case <-time.After(200 * time.Millisecond):
	}

	close(bv.release)

	select {
	case r := <-rpcDone:
		require.NoError(t, r.err, "запрос в полёте должен завершиться успешно")
		assert.Equal(t, int64(42), r.resp.GetRevision())
	case <-time.After(5 * time.Second):
		t.Fatal("запрос в полёте не завершился")
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("GracefulStop не завершился после окончания запроса")
	}
}

// panicJWT — JWTService, паникующий при проверке любого токена.
type panicJWT struct{}

func (panicJWT) ValidateJWT(string) (string, error) { panic("jwt boom") }

// TestRecovery_PanicInAuthInterceptor — паника внутри auth interceptor (самого внутреннего в цепочке)
// перехватывается внешним RecoveryInterceptor: клиент получает Internal без текста паники,
// сервер продолжает отвечать, а методы без аутентификации по-прежнему работают.
func TestRecovery_PanicInAuthInterceptor(t *testing.T) {
	jwtSvc, err := jwtauth.NewJWTService(jwtSecret, time.Hour)
	require.NoError(t, err)
	authSvc := authcase.NewService(memory.NewUsersRepo(), jwtSvc, []byte("s"))
	vaultSvc, err := vaultcase.NewService(memory.NewRecordsRepo(),
		vaultcase.DefaultHeaderSizeLimit(), vaultcase.DefaultBodySizeLimit())
	require.NoError(t, err)

	_, conn := startServerWithJWT(t, authSvc, vaultSvc, panicJWT{})
	vault := pb.NewVaultServiceClient(conn)

	_, err = vault.Get(withToken("any-token"), pb.GetRequest_builder{Id: "r"}.Build())
	requireCode(t, err, codes.Internal)
	assert.NotContains(t, err.Error(), "jwt boom", "значение паники не должно попасть клиенту")

	// Повторный вызов: сервер пережил панику.
	_, err = vault.ListChanges(withToken("any-token"), pb.ListChangesRequest_builder{}.Build())
	requireCode(t, err, codes.Internal)

	// Публичный метод не доходит до проверки токена и работает.
	_, err = pb.NewAuthServiceClient(conn).GetKDFParams(context.Background(), pb.GetKDFParamsRequest_builder{Login: "alice"}.Build())
	require.NoError(t, err)
}
