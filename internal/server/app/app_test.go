package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

const (
	waitTimeout = 10 * time.Second
	// shutdownBudget оставляет запас над жёстким лимитом GracefulStop в 15 с.
	shutdownBudget = shutdownTimeout + (5 * time.Second)
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// freeAddr возвращает свободный адрес на localhost.
func freeAddr(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := lis.Addr().String()
	require.NoError(t, lis.Close())
	return addr
}

// writeCert создаёт самоподписанный сертификат для 127.0.0.1 и возвращает пути к нему и ключу, а также пул с ним.
func writeCert(t *testing.T) (certPath, keyPath string, pool *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "gophkeeper-test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	dir := t.TempDir()
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	pool = x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(certPEM))
	return certPath, keyPath, pool
}

// memoryConfig — конфигурация memory-бэкенда с заданными секретами.
func memoryConfig(addr string) Config {
	return Config{
		RunAddr:        addr,
		JWTSecret:      "jwt-secret",
		JWTTTL:         60,
		FakeSaltSecret: "fake-salt-secret",
	}
}

// runResult — запущенный Run, за завершением которого следит тест.
type runResult struct {
	done   chan error
	cancel context.CancelFunc
}

// startRun запускает Run в горутине с отменяемым контекстом. Остановка сервера — отмена контекста (shutdown);
// если тест завершился раньше, контекст отменяется в t.Cleanup, чтобы не утекла горутина.
func startRun(t *testing.T, cfg Config) *runResult {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r := &runResult{done: make(chan error, 1), cancel: cancel}
	go func() { r.done <- Run(ctx, cfg, discardLogger()) }()
	return r
}

// waitListening ждёт, пока сервер начнёт принимать TCP-соединения, либо пока Run не вернёт ошибку.
func waitListening(t *testing.T, addr string, r *runResult) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-r.done:
			t.Fatalf("Run завершился до готовности сервера: %v", err)
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("сервер не начал слушать %s", addr)
}

// shutdown отменяет контекст Run, как это делает сигнал в main, и ждёт возврата Run.
func shutdown(t *testing.T, r *runResult) error {
	t.Helper()
	r.cancel()
	select {
	case err := <-r.done:
		return err
	case <-time.After(shutdownBudget):
		t.Fatal("Run не завершился после отмены контекста")
		return nil
	}
}

func healthCheck(ctx context.Context, conn *grpc.ClientConn) (healthpb.HealthCheckResponse_ServingStatus, error) {
	resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		return 0, err
	}
	return resp.GetStatus(), nil
}

// expectRunError проверяет, что Run сам вернул ошибку, не начав слушать порт.
func expectRunError(t *testing.T, cfg Config) {
	t.Helper()
	r := startRun(t, cfg)
	select {
	case err := <-r.done:
		require.Error(t, err)
	case <-time.After(3 * time.Second):
		// Сервер, который не должен был стартовать, остановлен, чтобы не утекла горутина.
		_ = shutdown(t, r)
		t.Fatal("Run должен был завершиться ошибкой при старте")
	}
	conn, err := net.DialTimeout("tcp", cfg.RunAddr, 200*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Fatal("сервер слушает порт, хотя Run вернул ошибку")
	}
}

// TestRun_TLSFlagMatrix — только один из --tls-cert/--tls-key — ошибка запуска, а не откат на plaintext.
func TestRun_TLSFlagMatrix_OneSetIsError(t *testing.T) {
	certPath, keyPath, _ := writeCert(t)

	tests := []struct {
		name      string
		cert, key string
	}{
		{"only cert", certPath, ""},
		{"only key", "", keyPath},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := memoryConfig(freeAddr(t))
			cfg.TLSCertPath, cfg.TLSKeyPath = tt.cert, tt.key
			expectRunError(t, cfg)
		})
	}
}

// TestRun_Plaintext — без TLS-флагов сервер работает без шифрования и чисто останавливается.
func TestRun_Plaintext(t *testing.T) {
	cfg := memoryConfig(freeAddr(t))
	r := startRun(t, cfg)
	waitListening(t, cfg.RunAddr, r)

	conn, err := grpc.NewClient(cfg.RunAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	defer cancel()
	_, err = healthCheck(ctx, conn)
	if err != nil {
		assert.NotEqual(t, "Unavailable", grpcCode(err), "plaintext-клиент должен достучаться до сервера: %v", err)
	}

	require.NoError(t, shutdown(t, r))

	_, err = net.DialTimeout("tcp", cfg.RunAddr, 200*time.Millisecond)
	assert.Error(t, err, "после остановки порт должен быть закрыт")
}

// TestRun_TLS — при заданных cert и key сервер принимает только TLS-клиентов.
func TestRun_TLS(t *testing.T) {
	certPath, keyPath, pool := writeCert(t)
	cfg := memoryConfig(freeAddr(t))
	cfg.TLSCertPath, cfg.TLSKeyPath = certPath, keyPath

	r := startRun(t, cfg)
	waitListening(t, cfg.RunAddr, r)

	// TLS-клиент с доверенным сертификатом достучится до сервера.
	tlsConn, err := grpc.NewClient(cfg.RunAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13})))
	require.NoError(t, err)
	defer tlsConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	defer cancel()
	_, err = healthCheck(ctx, tlsConn)
	if err != nil {
		assert.NotEqual(t, "Unavailable", grpcCode(err), "TLS-клиент должен достучаться до сервера: %v", err)
	}

	// Plaintext-клиент не должен получить ответ.
	plainConn, err := grpc.NewClient(cfg.RunAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer plainConn.Close()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	_, err = healthCheck(ctx2, plainConn)
	require.Error(t, err, "plaintext-клиент не должен работать с TLS-сервером")
	assert.Equal(t, "Unavailable", grpcCode(err))

	require.NoError(t, shutdown(t, r))
}

// TestRun_Secrets — в memory-режиме секреты JWT и фейковой соли генерируются при старте.
// Обязательность секретов для Postgres проверяет TestRun_DatabaseSecretsRequired.
func TestRun_Secrets(t *testing.T) {
	t.Run("memory without secrets starts", func(t *testing.T) {
		cfg := Config{RunAddr: freeAddr(t), JWTTTL: 60}
		r := startRun(t, cfg)
		waitListening(t, cfg.RunAddr, r)
		require.NoError(t, shutdown(t, r))
	})
}

// grpcCode возвращает имя gRPC-кода ошибки.
func grpcCode(err error) string {
	return status.Code(err).String()
}
