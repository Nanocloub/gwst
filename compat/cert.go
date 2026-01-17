package compat

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

type selfSignedCertConfig struct {
	keyType string // "rsa", "ecdsa", "ed25519"
}

type SelfSignedCertOption func(*selfSignedCertConfig)

func WithECC() SelfSignedCertOption {
	return func(cfg *selfSignedCertConfig) {
		cfg.keyType = "ecdsa"
	}
}

func WithRSA() SelfSignedCertOption {
	return func(cfg *selfSignedCertConfig) {
		cfg.keyType = "rsa"
	}
}

func WithEd25519() SelfSignedCertOption {
	return func(cfg *selfSignedCertConfig) {
		cfg.keyType = "ed25519"
	}
}

func GenerateSelfSignedCert(host string, opts ...SelfSignedCertOption) (*tls.Certificate, error) {
	cfg := &selfSignedCertConfig{keyType: "rsa"} // default to RSA
	for _, opt := range opts {
		opt(cfg)
	}

	var (
		privKey any
		pubKey  any
		err     error
	)

	switch cfg.keyType {
	case "ecdsa":
		privKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECDSA private key: %w", err)
		}

		pubKey = &privKey.(*ecdsa.PrivateKey).PublicKey
	case "ed25519":
		pubKey, privKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Ed25519 private key: %w", err)
		}
	default: // rsa
		privKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA private key: %w", err)
		}

		pubKey = &privKey.(*rsa.PrivateKey).PublicKey
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             notBefore,
		NotAfter:              notBefore.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := new(bytes.Buffer)
	if err := pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, fmt.Errorf("failed to encode certificate: %w", err)
	}

	privPEM := new(bytes.Buffer)
	switch cfg.keyType {
	case "ecdsa":
		privBytes, err := x509.MarshalECPrivateKey(privKey.(*ecdsa.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ECDSA private key: %w", err)
		}

		if err := pem.Encode(privPEM, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
			return nil, fmt.Errorf("failed to encode EC private key: %w", err)
		}
	case "ed25519":
		privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Ed25519 private key: %w", err)
		}

		if err := pem.Encode(privPEM, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
			return nil, fmt.Errorf("failed to encode Ed25519 private key: %w", err)
		}
	default: // rsa
		if err := pem.Encode(privPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey.(*rsa.PrivateKey))}); err != nil {
			return nil, fmt.Errorf("failed to encode RSA private key: %w", err)
		}
	}

	cert, err := tls.X509KeyPair(certPEM.Bytes(), privPEM.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to create X509 key pair: %w", err)
	}

	return &cert, nil
}
