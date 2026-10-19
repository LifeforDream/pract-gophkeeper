// Package certgen содержит логику генерации сертификатов, не касаясь I/O
package certgen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// GenerateCAKeyPair генерирует и возвращает пару ключей (сертификат и приватный ключ)
func GenerateCAKeyPair() ([]byte, []byte, error) {
	certID, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return nil, nil, fmt.Errorf("error generating certId: %w", err)
	}

	cert := &x509.Certificate{
		SerialNumber: certID,
		Subject: pkix.Name{
			Organization: []string{"GophKeeper Dev CA"},
			Country:      []string{"RU"},
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating key: %w", err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	marshalledKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error marshalling key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: marshalledKey})

	return certPEM, keyPEM, nil
}

// GenerateServerKeyPair создаёт пару ключей сервера из ключа и сертификата CA.
//
// Функция принимает пару ключ+серт CA.
func GenerateServerKeyPair(caCert *x509.Certificate, key crypto.Signer) ([]byte, []byte, error) {
	certID, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return nil, nil, fmt.Errorf("error generating certId: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: certID,
		Subject: pkix.Name{
			Organization: []string{"GophKeeper Dev Server"},
			Country:      []string{"RU"},
		},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{"localhost"},
		NotBefore:   time.Now().Add(-5 * time.Minute),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating key: %w", err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &privateKey.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	marshalledKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error marshalling key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: marshalledKey})

	return certPEM, keyPEM, nil
}

// ParseBytesToCert превращает байты контейнера в сертификат.
func ParseBytesToCert(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no CERTIFICATE PEM block found in cert")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}
	return cert, nil
}

// ParseBytesToKey превращает байты контейнера в приватный ключ.
func ParseBytesToKey(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("no PRIVATE KEY PEM block found in key")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}

	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key: unexpected type %T", parsed)
	}
	return signer, nil
}
