package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"nproxy/app/config"
)

// MITMProxy is a structure that holds the configuration for MITM proxy server
type MITMProxy struct {
	CA      *x509.Certificate
	CAKey   *rsa.PrivateKey
	CertDir string
	Addr    string
	Handler func(*http.Request, *http.Response) // Handler for request/response modification
}

// NewMITMProxy creates a new MITM proxy
func NewMITMProxy(cfg *config.Config) (*MITMProxy, error) {
	certDir := cfg.Mitm.CertDir
	var ca *x509.Certificate
	var caKey *rsa.PrivateKey
	var err error

	if cfg.Mitm.PersistCA {
		ca, caKey, err = loadCA(certDir)
		if err != nil {
			log.Printf("Could not load CA, generating a new one: %v", err)
			ca, caKey, err = generateCA()
			if err != nil {
				return nil, fmt.Errorf("failed to generate CA: %v", err)
			}
			if err := saveCA(certDir, ca, caKey); err != nil {
				return nil, fmt.Errorf("failed to save CA: %v", err)
			}
		} else {
			log.Println("Loaded existing CA certificate and key.")
		}
	} else {
		ca, caKey, err = generateCA()
		if err != nil {
			return nil, fmt.Errorf("failed to generate CA: %v", err)
		}
	}

	return &MITMProxy{
		CA:      ca,
		CAKey:   caKey,
		CertDir: certDir,
		Addr:    cfg.Addr,
	}, nil
}

// Start starts the MITM proxy server
func (m *MITMProxy) Start() error {
	proxy := m.createReverseProxy()

	server := &http.Server{
		Addr:    m.Addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				m.handleConnect(w, r)
			} else {
				proxy.ServeHTTP(w, r)
			}
		}),
	}

	log.Printf("MITM Proxy server starting on %s", m.Addr)
	log.Printf("CA certificate is in %s/ca.crt", m.CertDir)
	log.Println("Install the CA certificate in your browser to avoid SSL warnings")

	return server.ListenAndServe()
}

func (m *MITMProxy) createReverseProxy() *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			target, err := url.Parse("http://" + r.Host)
			if err != nil {
				log.Printf("Failed to parse target URL: %v", err)
				return
			}
			r.URL.Scheme = target.Scheme
			r.URL.Host = target.Host
			r.URL.Path = r.URL.Path

			if m.Handler != nil {
				m.Handler(r, nil)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			if m.Handler != nil {
				m.Handler(nil, resp)
			}
			return nil
		},
	}
}

// handleConnect は HTTPS CONNECT メソッドを処理する
func (m *MITMProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	log.Printf("CONNECT request to %s", r.Host)

	cert, err := m.generateCert(r.Host)
	if err != nil {
		log.Printf("Failed to generate certificate for %s: %v", r.Host, err)
		http.Error(w, "failed to generate certificate", http.StatusInternalServerError)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// Acknowledge the CONNECT request
	_, err = clientConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	if err != nil {
		log.Printf("Failed to send 200 OK to client: %v", err)
		return
	}

	clientTLSConn := tls.Server(clientConn, tlsConfig)
	if err := clientTLSConn.Handshake(); err != nil {
		log.Printf("Client TLS handshake failed: %v", err)
		return
	}
	defer clientTLSConn.Close()

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "https"
			req.URL.Host = r.Host
			req.Host = r.Host
			if m.Handler != nil {
				m.Handler(req, nil)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			if m.Handler != nil {
				m.Handler(nil, resp)
			}
			return nil
		},
		// Use a transport that skips verification for the self-signed certs
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Create a new server to handle the requests over the hijacked connection
	server := &http.Server{
		Handler: proxy,
	}
	server.Serve(clientTLSConn)
}

// generateCA は CA証明書と秘密鍵を生成する
func generateCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	// RSA秘密鍵を生成
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// CA証明書テンプレートを作成
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"MITM Proxy"},
			Country:      []string{"JP"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1年間有効
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// 自己署名証明書を作成
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	// 証明書をパース
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

// generateCert は指定されたホスト名用のサーバー証明書を生成する
func (m *MITMProxy) generateCert(host string) (*tls.Certificate, error) {
	// RSA秘密鍵を生成
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	hostname := extractHostname(host)

	// サーバー証明書テンプレートを作成
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
	}

	// IP アドレスの場合は IPAddresses に追加
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	}

	// CA で署名された証明書を作成
	certDER, err := x509.CreateCertificate(rand.Reader, &template, m.CA, &key.PublicKey, m.CAKey)
	if err != nil {
		return nil, err
	}

	// TLS証明書を作成
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	return &cert, nil
}

// saveCA は CA証明書と秘密鍵をファイルに保存する
func saveCA(certDir string, ca *x509.Certificate, caKey *rsa.PrivateKey) error {
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create cert directory: %v", err)
	}

	// CA証明書をPEM形式で保存
	certFile, err := os.Create(fmt.Sprintf("%s/ca.crt", certDir))
	if err != nil {
		return err
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}); err != nil {
		return err
	}

	// CA秘密鍵をPEM形式で保存
	keyFile, err := os.Create(fmt.Sprintf("%s/ca.key", certDir))
	if err != nil {
		return err
	}
	defer keyFile.Close()
	return pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)})
}

// loadCA はファイルからCA証明書と秘密鍵を読み込む
func loadCA(certDir string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certBytes, err := os.ReadFile(fmt.Sprintf("%s/ca.crt", certDir))
	if err != nil {
		return nil, nil, err
	}
	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA certificate")
	}
	ca, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyBytes, err := os.ReadFile(fmt.Sprintf("%s/ca.key", certDir))
	if err != nil {
		return nil, nil, err
	}
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA private key")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return ca, caKey, nil
}

// extractHostname はホスト:ポート形式からホスト名を抽出する
func extractHostname(host string) string {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return hostname
}

// SetHandler はリクエスト・レスポンス改ざん用のハンドラーを設定する
func (m *MITMProxy) SetHandler(handler func(*http.Request, *http.Response)) {
	m.Handler = handler
}
