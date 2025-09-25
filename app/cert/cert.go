package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// CertManager handles the generation and management of certificates for the MITM proxy.
type CertManager struct {
	CA      *x509.Certificate
	CAKey   *rsa.PrivateKey
	CertDir string
}

// NewCertManager creates a new certificate manager, including generating a new CA.
func NewCertManager(certDir string) (*CertManager, error) {
	ca, caKey, err := generateCA()
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA: %v", err)
	}

	return &CertManager{
		CA:      ca,
		CAKey:   caKey,
		CertDir: certDir,
	}, nil
}

// GenerateCert creates a new server certificate signed by the CA for the given host.
func (cm *CertManager) GenerateCert(host string) (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	hostname := extractHostname(host)

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization: []string{"MITM Proxy"},
			CommonName:   hostname,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
	}

	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, cm.CA, &key.PublicKey, cm.CAKey)
	if err != nil {
		return nil, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	return &cert, nil
}

// SaveCA saves the CA certificate to a file in the specified directory.
func (cm *CertManager) SaveCA() error {
	if err := os.MkdirAll(cm.CertDir, 0755); err != nil {
		return fmt.Errorf("failed to create cert directory: %v", err)
	}

	certFile, err := os.Create(fmt.Sprintf("%s/ca.crt", cm.CertDir))
	if err != nil {
		return err
	}
	defer certFile.Close()

	return pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cm.CA.Raw,
	})
}

// generateCA creates a new CA certificate and private key.
func generateCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"MITM Proxy"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

// extractHostname extracts the hostname from a host:port string.
func extractHostname(host string) string {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return hostname
}