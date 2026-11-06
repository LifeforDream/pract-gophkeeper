package transport

import (
	"context"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	pb "github.com/LifeforDream/pract-gophkeeper/api/gophkeeper/v1"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/app"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/crypto"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/session"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/handler/grpcsrv"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/jwtauth"
	"github.com/LifeforDream/pract-gophkeeper/internal/server/repository/memory"
	authcase "github.com/LifeforDream/pract-gophkeeper/internal/server/usecase/auth"
	vaultcase "github.com/LifeforDream/pract-gophkeeper/internal/server/usecase/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const wiringAddr = "bufnet"

// startWiringServer поднимает настоящий сервер (use case + memory-репозитории + интерцепторы) на bufconn
// и возвращает transport.Client, подключённый к нему. Сервер и соединение закрываются в t.Cleanup.
func startWiringServer(t *testing.T) *Client {
	t.Helper()

	jwtSvc, err := jwtauth.NewJWTService([]byte("wiring-secret"), time.Hour)
	require.NoError(t, err)
	authSvc := authcase.NewService(memory.NewUsersRepo(), jwtSvc, []byte("wiring-fake-salt"))
	vaultSvc, err := vaultcase.NewService(memory.NewRecordsRepo(),
		vaultcase.DefaultHeaderSizeLimit(), vaultcase.DefaultBodySizeLimit())
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := grpcsrv.New(authSvc, vaultSvc, jwtSvc, logger, nil)
	lis := bufconn.Listen(1 << 20)

	var wg sync.WaitGroup
	wg.Go(func() { _ = srv.Serve(lis) })

	conn, err := grpc.NewClient("passthrough:///"+wiringAddr,
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	c := &Client{
		conn:        conn,
		logger:      logger,
		authClient:  pb.NewAuthServiceClient(conn),
		vaultClient: pb.NewVaultServiceClient(conn),
	}
	t.Cleanup(func() {
		_ = c.Close()
		srv.Stop()
		wg.Wait()
	})
	return c
}

// device — один «клиентский компьютер»: свой файл сессии, свои Auth и Vault поверх общего транспорта.
type device struct {
	store *session.FileStore
	auth  *app.Auth
	vault *app.Vault
}

func newDevice(t *testing.T, c *Client, bodyLimit int) *device {
	t.Helper()
	store, err := session.NewFileStore(filepath.Join(t.TempDir(), "gophkeeper", "session.json"))
	require.NoError(t, err)
	v, err := app.NewVault(c, store, wiringAddr, bodyLimit)
	require.NoError(t, err)
	return &device{store: store, auth: app.NewAuth(c, store, wiringAddr), vault: v}
}

func loginSecret(name, password string) domain.Secret {
	return domain.Secret{
		Header:  domain.Header{Type: domain.TypeLogin, Name: name, Meta: []domain.MetaItem{{Key: "site", Value: "example.com"}}},
		Content: domain.Login{Username: "alice", Password: password},
	}
}

// TestWiring_FullFlow проводит настоящий transport через настоящий сервер:
// register → add → list → get → login с другого устройства → update (свежий и устаревший) → delete.
func TestWiring_FullFlow(t *testing.T) {
	ctx := t.Context()
	c := startWiringServer(t)
	a := newDevice(t, c, app.DefaultBodySizeLimit())
	// Register и Login зануляют переданный пароль, поэтому каждому вызову нужен свежий слайс
	pw := func() []byte { return []byte("correct horse battery staple") }

	require.NoError(t, a.auth.Register(ctx, "alice", pw()))
	assert.ErrorIs(t, newDevice(t, c, app.DefaultBodySizeLimit()).auth.Register(ctx, "alice", pw()), domain.ErrLoginTaken)

	secret := loginSecret("mail", "p1")
	id, err := a.vault.Add(ctx, secret)
	require.NoError(t, err)

	res, err := a.vault.List(ctx)
	require.NoError(t, err)
	require.Len(t, res.Items, 1)
	assert.Equal(t, id, res.Items[0].ID)
	assert.Equal(t, secret.Header, res.Items[0].Header)
	assert.Empty(t, res.Skipped)

	entry, err := a.vault.Get(ctx, "mail")
	require.NoError(t, err)
	assert.Equal(t, secret, entry.Secret)
	assert.EqualValues(t, 1, entry.Version)

	// второе устройство: тот же пароль даёт те же ключи, значит читает то же самое
	b := newDevice(t, c, app.DefaultBodySizeLimit())
	require.NoError(t, b.auth.Login(ctx, "alice", pw()))
	got, err := b.vault.Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, secret, got.Secret)

	// свежее обновление с первого устройства
	require.NoError(t, a.vault.Update(ctx, id, 1, loginSecret("mail", "p2")))

	// устаревшее обновление со второго: app отсекает по версии с сервера
	err = b.vault.Update(ctx, id, 1, loginSecret("mail", "stale"))
	assert.ErrorIs(t, err, domain.ErrConflict)

	// и ABORTED от самого сервера доходит до ErrConflict через mapErr
	sess, err := b.store.Load(wiringAddr)
	require.NoError(t, err)
	sl, err := crypto.NewSealer(sess.EncKey)
	require.NoError(t, err)
	hb, bb, err := loginSecret("mail", "stale").Marshal()
	require.NoError(t, err)
	h, err := sl.Seal(sess.UserID, id, crypto.PartHeader, hb)
	require.NoError(t, err)
	body, err := sl.Seal(sess.UserID, id, crypto.PartBody, bb)
	require.NoError(t, err)
	_, err = c.Put(ctx, sess.Token, id, 1, h, body)
	assert.ErrorIs(t, err, domain.ErrConflict)

	got, err = b.vault.Get(ctx, "mail")
	require.NoError(t, err)
	assert.Equal(t, domain.Login{Username: "alice", Password: "p2"}, got.Secret.Content)
	assert.EqualValues(t, 2, got.Version)

	require.NoError(t, b.vault.Delete(ctx, "mail"))
	res, err = a.vault.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, res.Items)
	_, err = a.vault.Get(ctx, id)
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestWiring_AuthErrors(t *testing.T) {
	ctx := t.Context()
	c := startWiringServer(t)
	require.NoError(t, newDevice(t, c, app.DefaultBodySizeLimit()).auth.Register(ctx, "alice", []byte("pw")))

	tests := []struct {
		name, login, password string
	}{
		{"wrong password", "alice", "other"},
		{"unknown login", "nobody", "pw"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newDevice(t, c, app.DefaultBodySizeLimit())
			err := d.auth.Login(ctx, tt.login, []byte(tt.password))
			assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
			_, loadErr := d.store.Load(wiringAddr)
			assert.ErrorIs(t, loadErr, domain.ErrNoSession, "сессия не должна сохраниться")
		})
	}
}

func TestWiring_VaultErrors(t *testing.T) {
	ctx := t.Context()
	c := startWiringServer(t)
	// лимит клиента заведомо выше серверного, чтобы ошибку вернул сервер, а не клиентская проверка
	d := newDevice(t, c, 16*vaultcase.DefaultBodySizeLimit())
	require.NoError(t, d.auth.Register(ctx, "alice", []byte("pw")))

	t.Run("body over server limit", func(t *testing.T) {
		_, err := d.vault.Add(ctx, domain.Secret{
			Header:  domain.Header{Type: domain.TypeBinary, Name: "big"},
			Content: domain.Binary{Filename: "f", Data: make([]byte, vaultcase.DefaultBodySizeLimit()+1)},
		})
		assert.ErrorIs(t, err, domain.ErrTooLarge)
	})

	t.Run("token rejected by server", func(t *testing.T) {
		sess, err := d.store.Load(wiringAddr)
		require.NoError(t, err)
		bad := sess
		bad.Token = "garbage"
		require.NoError(t, d.store.Save(bad))
		t.Cleanup(func() { require.NoError(t, d.store.Save(sess)) })

		_, err = d.vault.List(ctx)
		assert.ErrorIs(t, err, domain.ErrSessionExpired)
	})
}
