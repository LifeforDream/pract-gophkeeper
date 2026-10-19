// Package main является точкой запуска утилиты генерации простенького сертификата
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/LifeforDream/pract-gophkeeper/pkg/certgen"
)

const (
	certFileMode       = 0o644
	keyFileMode        = 0o600
	caCertFilename     = "ca.pem"
	caKeyFilename      = "ca.key"
	serverCertFilename = "server.pem"
	serverKeyFilename  = "server.key"
)

func main() {
	certgenOptions, err := parseOptions()
	if err != nil {
		log.Fatal(err)
	}

	err = os.MkdirAll(certgenOptions.OutDir, 0o700)
	if err != nil {
		log.Fatal(err)
	}

	// сначала сгенерируем пару для CA.
	certBytesCA, keyBytesCA, err := certgen.GenerateCAKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	certpathCA := filepath.Join(certgenOptions.OutDir, caCertFilename)
	if err = writeFile(certpathCA, certBytesCA, certFileMode); err != nil {
		log.Fatal(err)
	}

	keypathCA := filepath.Join(certgenOptions.OutDir, caKeyFilename)
	if err = writeFile(keypathCA, keyBytesCA, keyFileMode); err != nil {
		log.Fatal(err)
	}

	// потом на её основе пару для сервера.
	certCA, err := certgen.ParseBytesToCert(certBytesCA)
	if err != nil {
		log.Fatal(err)
	}

	keyCA, err := certgen.ParseBytesToKey(keyBytesCA)
	if err != nil {
		log.Fatal(err)
	}

	certBytes, keyBytes, err := certgen.GenerateServerKeyPair(certCA, keyCA)
	if err != nil {
		log.Fatal(err)
	}

	certpath := filepath.Join(certgenOptions.OutDir, serverCertFilename)

	if err = writeFile(certpath, certBytes, certFileMode); err != nil {
		log.Fatal(err)
	}

	keypath := filepath.Join(certgenOptions.OutDir, serverKeyFilename)

	if err = writeFile(keypath, keyBytes, keyFileMode); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Wrote CA files:\n CA Certificate: %s \n CA Private key: %s \n", certpathCA, keypathCA)
	fmt.Printf("Wrote files:\n Certificate: %s \n Private key: %s \n", certpath, keypath)

}

func writeFile(path string, data []byte, perm os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("error opening file %s: %w", path, err)
	}

	if _, err = file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("error writing file %s: %w", path, err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("error closing file %s: %w", path, err)
	}
	return nil
}
