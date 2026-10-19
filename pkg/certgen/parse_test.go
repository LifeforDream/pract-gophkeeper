package certgen

import (
	"crypto/ecdsa"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// garbagePEM возвращает PEM-блок заданного типа с невалидным содержимым.
func garbagePEM(blockType string) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: []byte("not a der structure")})
}

func TestParseBytesToCert(t *testing.T) {
	certPEM, keyPEM, err := GenerateCAKeyPair()
	require.NoError(t, err)

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{name: "валидный сертификат", data: certPEM},
		{name: "пустые данные", data: nil, wantErr: true},
		{name: "не PEM", data: []byte("hello"), wantErr: true},
		{name: "ключ вместо сертификата", data: keyPEM, wantErr: true},
		{name: "битый DER", data: garbagePEM("CERTIFICATE"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := ParseBytesToCert(tt.data)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, cert)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, cert)
			assert.True(t, cert.IsCA)
		})
	}
}

func TestParseBytesToKey(t *testing.T) {
	certPEM, keyPEM, err := GenerateCAKeyPair()
	require.NoError(t, err)

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{name: "валидный ключ", data: keyPEM},
		{name: "пустые данные", data: nil, wantErr: true},
		{name: "не PEM", data: []byte("hello"), wantErr: true},
		{name: "сертификат вместо ключа", data: certPEM, wantErr: true},
		{name: "битый DER", data: garbagePEM("PRIVATE KEY"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ParseBytesToKey(tt.data)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, key)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, key)
		})
	}
}

// TestParsedKeyMatchesParsedCert проверяет, что разобранные ключ и сертификат образуют пару.
func TestParsedKeyMatchesParsedCert(t *testing.T) {
	certPEM, keyPEM, err := GenerateCAKeyPair()
	require.NoError(t, err)

	cert, err := ParseBytesToCert(certPEM)
	require.NoError(t, err)

	key, err := ParseBytesToKey(keyPEM)
	require.NoError(t, err)

	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok)

	assert.True(t, pub.Equal(key.Public()))
}
