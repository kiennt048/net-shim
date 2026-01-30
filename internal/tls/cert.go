package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	// Use /usr/local/share/netshim for persistent storage on pfSense
	// /var/db/ is often a memory filesystem that gets cleared on reboot
	CertDir  = "/usr/local/share/netshim"
	CertPath = "/usr/local/share/netshim/server.crt"
	KeyPath  = "/usr/local/share/netshim/server.key"
)

// EnsureCert generates a self-signed TLS certificate if it doesn't exist.
// Returns the paths to the certificate and key files.
func EnsureCert() (certPath, keyPath string, err error) {
	// Check if certificate already exists
	if _, err := os.Stat(CertPath); err == nil {
		if _, err := os.Stat(KeyPath); err == nil {
			return CertPath, KeyPath, nil
		}
	}

	// Create directory if needed
	if err := os.MkdirAll(CertDir, 0700); err != nil {
		return "", "", fmt.Errorf("failed to create cert directory: %w", err)
	}

	// Generate ECDSA P-256 private key (smaller and faster than RSA)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"BEYONDNET Firewall"},
			CommonName:   "BEYONDNET Control Panel",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years validity
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost", "pfsense", "pfsense.local", "firewall", "firewall.local"},
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write certificate to file
	certFile, err := os.OpenFile(CertPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return "", "", fmt.Errorf("failed to create cert file: %w", err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return "", "", fmt.Errorf("failed to write cert: %w", err)
	}

	// Write private key to file
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyFile, err := os.OpenFile(KeyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", "", fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyFile.Close()

	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return "", "", fmt.Errorf("failed to write key: %w", err)
	}

	return CertPath, KeyPath, nil
}
