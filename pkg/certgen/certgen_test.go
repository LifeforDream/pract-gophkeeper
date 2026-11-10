package certgen

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	handshakeTimeout = 5 * time.Second
)

// testPKI хранит всё, что нужно тестам: PEM-данные и разобранные сертификаты CA и сервера.
type testPKI struct {
	caPEM      []byte
	caCert     *x509.Certificate
	caKey      *ecdsa.PrivateKey
	serverPEM  []byte
	serverKey  []byte
	serverCert *x509.Certificate
}

// decodeCert разбирает PEM с единственным сертификатом.
func decodeCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()

	cert, err := ParseBytesToCert(certPEM)
	require.NoError(t, err)

	return cert
}

// decodeECKey разбирает PEM с приватным ключом PKCS#8 и проверяет, что это ECDSA.
func decodeECKey(t *testing.T, keyPEM []byte) *ecdsa.PrivateKey {
	t.Helper()

	signer, err := ParseBytesToKey(keyPEM)
	require.NoError(t, err)

	key, ok := signer.(*ecdsa.PrivateKey)
	require.True(t, ok, "ожидался ECDSA-ключ, получен %T", signer)

	return key
}

// newTestPKI генерирует CA и серверную пару.
func newTestPKI(t *testing.T) testPKI {
	t.Helper()

	caPEM, caKeyPEM, err := GenerateCAKeyPair()
	require.NoError(t, err)

	caCert := decodeCert(t, caPEM)
	caKey := decodeECKey(t, caKeyPEM)

	serverPEM, serverKey, err := GenerateServerKeyPair(caCert, caKey)
	require.NoError(t, err)

	return testPKI{
		caPEM:      caPEM,
		caCert:     caCert,
		caKey:      caKey,
		serverPEM:  serverPEM,
		serverKey:  serverKey,
		serverCert: decodeCert(t, serverPEM),
	}
}

// poolFromPEM собирает пул так же, как это делает клиент по --ca-cert.
func poolFromPEM(t *testing.T, caPEM []byte) *x509.CertPool {
	t.Helper()

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caPEM))

	return pool
}

func TestGenerateCAKeyPair(t *testing.T) {
	certPEM, keyPEM, err := GenerateCAKeyPair()
	require.NoError(t, err)

	cert := decodeCert(t, certPEM)
	key := decodeECKey(t, keyPEM)

	t.Run("ключ ECDSA P-256", func(t *testing.T) {
		assert.Equal(t, elliptic.P256(), key.Curve)
	})

	t.Run("ключ и сертификат образуют пару", func(t *testing.T) {
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		require.True(t, ok)
		assert.True(t, key.PublicKey.Equal(pub))
	})

	t.Run("самоподписанный", func(t *testing.T) {
		assert.NoError(t, cert.CheckSignatureFrom(cert))
		assert.Equal(t, cert.Subject.String(), cert.Issuer.String())
	})

	t.Run("флаги CA", func(t *testing.T) {
		assert.True(t, cert.IsCA)
		assert.True(t, cert.BasicConstraintsValid)
		assert.NotZero(t, cert.KeyUsage&x509.KeyUsageCertSign)
	})

	t.Run("действителен сейчас", func(t *testing.T) {
		now := time.Now()
		assert.True(t, cert.NotBefore.Before(now), "NotBefore должен быть в прошлом: %s", cert.NotBefore)
		assert.True(t, cert.NotAfter.After(now))
	})
}

func TestGenerateServerKeyPair(t *testing.T) {
	pki := newTestPKI(t)
	key := decodeECKey(t, pki.serverKey)

	t.Run("ключ ECDSA P-256", func(t *testing.T) {
		assert.Equal(t, elliptic.P256(), key.Curve)
	})

	t.Run("ключ и сертификат образуют пару", func(t *testing.T) {
		pub, ok := pki.serverCert.PublicKey.(*ecdsa.PublicKey)
		require.True(t, ok)
		assert.True(t, key.PublicKey.Equal(pub))

		_, err := tls.X509KeyPair(pki.serverPEM, pki.serverKey)
		assert.NoError(t, err)
	})

	t.Run("подписан CA", func(t *testing.T) {
		assert.NoError(t, pki.serverCert.CheckSignatureFrom(pki.caCert))
		assert.Equal(t, pki.caCert.Subject.String(), pki.serverCert.Issuer.String())
	})

	t.Run("не является CA", func(t *testing.T) {
		assert.False(t, pki.serverCert.IsCA)
	})

	t.Run("только ServerAuth", func(t *testing.T) {
		assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, pki.serverCert.ExtKeyUsage)
	})

	t.Run("действителен сейчас", func(t *testing.T) {
		now := time.Now()
		assert.True(t, pki.serverCert.NotBefore.Before(now), "NotBefore должен быть в прошлом: %s", pki.serverCert.NotBefore)
		assert.True(t, pki.serverCert.NotAfter.After(now))
	})

	t.Run("чужой ключ не подходит к сертификату", func(t *testing.T) {
		other := newTestPKI(t)
		_, err := tls.X509KeyPair(pki.serverPEM, other.serverKey)
		assert.Error(t, err)
	})
}

func TestGenerateServerKeyPairWrongKey(t *testing.T) {
	pkiA := newTestPKI(t)
	pkiB := newTestPKI(t)

	_, _, err := GenerateServerKeyPair(pkiA.caCert, pkiB.caKey)
	require.Error(t, err, "key different from the ca cert should error")
}

func TestServerCertVerify(t *testing.T) {
	const day = 24 * time.Hour

	pki := newTestPKI(t)
	foreign := newTestPKI(t)

	tests := []struct {
		name    string
		roots   *x509.CertPool
		dnsName string
		usages  []x509.ExtKeyUsage
		offset  time.Duration // сдвиг текущего времени относительно time.Now()
		wantErr bool
	}{
		{name: "localhost", roots: poolFromPEM(t, pki.caPEM), dnsName: "localhost"},
		{name: "IPv4 loopback", roots: poolFromPEM(t, pki.caPEM), dnsName: "127.0.0.1"},
		{name: "IPv6 loopback", roots: poolFromPEM(t, pki.caPEM), dnsName: "::1"},
		{name: "имя вне SAN", roots: poolFromPEM(t, pki.caPEM), dnsName: "evil.test", wantErr: true},
		{name: "IP вне SAN", roots: poolFromPEM(t, pki.caPEM), dnsName: "10.0.0.6", wantErr: true},
		{name: "другой CA", roots: poolFromPEM(t, foreign.caPEM), dnsName: "localhost", wantErr: true},
		{name: "пустой пул", roots: x509.NewCertPool(), dnsName: "localhost", wantErr: true},
		{name: "срок истёк", roots: poolFromPEM(t, pki.caPEM), dnsName: "localhost", offset: 2 * 365 * day, wantErr: true},
		{name: "ещё не действует", roots: poolFromPEM(t, pki.caPEM), dnsName: "localhost", offset: -day, wantErr: true},
		{
			name:    "клиентское использование ключа",
			roots:   poolFromPEM(t, pki.caPEM),
			dnsName: "localhost",
			usages:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			usages := tt.usages
			if usages == nil {
				usages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			}

			_, err := pki.serverCert.Verify(x509.VerifyOptions{
				Roots:       tt.roots,
				DNSName:     tt.dnsName,
				CurrentTime: time.Now().Add(tt.offset),
				KeyUsages:   usages,
			})

			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestTLSHandshake(t *testing.T) {
	pki := newTestPKI(t)
	foreign := newTestPKI(t)

	serverCert, err := tls.X509KeyPair(pki.serverPEM, pki.serverKey)
	require.NoError(t, err)

	tests := []struct {
		name       string
		caPEM      []byte
		serverName string
		wantErr    bool
	}{
		{name: "localhost", caPEM: pki.caPEM, serverName: "localhost"},
		{name: "127.0.0.1", caPEM: pki.caPEM, serverName: "127.0.0.1"},
		{name: "имя вне SAN", caPEM: pki.caPEM, serverName: "evil.test", wantErr: true},
		{name: "другой CA", caPEM: foreign.caPEM, serverName: "localhost", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
			defer cancel()

			serverCfg := &tls.Config{
				Certificates: []tls.Certificate{serverCert},
				MinVersion:   tls.VersionTLS13,
			}
			clientCfg := &tls.Config{
				RootCAs:    poolFromPEM(t, tt.caPEM),
				ServerName: tt.serverName,
				MinVersion: tls.VersionTLS13,
			}

			listener, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
			require.NoError(t, err)
			defer listener.Close()

			// горутину запускает и дожидается этот же тест
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)

				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
				defer conn.Close()

				_ = conn.(*tls.Conn).HandshakeContext(ctx)
			}()

			dialer := tls.Dialer{Config: clientCfg}
			conn, err := dialer.DialContext(ctx, "tcp", listener.Addr().String())
			if conn != nil {
				_ = conn.Close()
			}

			// закрытие слушателя разблокирует Accept, если клиент не дошёл до подключения
			_ = listener.Close()
			<-serverDone

			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestGenerateProducesFreshKeysEachCall(t *testing.T) {
	caCertA, caKeyA, err := GenerateCAKeyPair()
	require.NoError(t, err)
	caCertB, caKeyB, err := GenerateCAKeyPair()
	require.NoError(t, err)

	assert.NotEqual(t, caCertA, caCertB)
	assert.NotEqual(t, caKeyA, caKeyB)

	a := newTestPKI(t)
	b := newTestPKI(t)

	assert.NotEqual(t, a.serverKey, b.serverKey)
}
