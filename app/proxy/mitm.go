package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"nproxy/app/config"
	"nproxy/app/handlers"
)

// singleConnListener accepts exactly one connection and then closes.
type singleConnListener struct {
	conn net.Conn
	ch   chan net.Conn
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	ch := make(chan net.Conn, 1)
	ch <- conn
	return &singleConnListener{conn: conn, ch: ch}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	c, ok := <-l.ch
	if !ok {
		return nil, net.ErrClosed
	}
	close(l.ch)
	return c, nil
}

func (l *singleConnListener) Close() error { return nil }

func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// MITMProxy holds the configuration for the MITM proxy server.
type MITMProxy struct {
	CA      *x509.Certificate
	CAKey   *rsa.PrivateKey
	CertDir string
	Addr    string
	Handler handlers.Handler
}

// NewMITMProxy creates a new MITMProxy from the given configuration.
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

// SetHandler sets the request/response modification handler.
func (m *MITMProxy) SetHandler(h handlers.Handler) {
	m.Handler = h
}

// Start starts the MITM proxy server.
func (m *MITMProxy) Start() error {
	rp := m.createReverseProxy()

	server := &http.Server{
		Addr: m.Addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				m.handleConnect(w, r)
			} else {
				rp.ServeHTTP(w, r)
			}
		}),
	}

	log.Printf("MITM proxy starting on %s", m.Addr)
	log.Printf("CA certificate: %s/ca.crt", m.CertDir)
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
			if m.Handler != nil {
				m.Handler.Handle(r, nil)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			if m.Handler != nil {
				m.Handler.Handle(nil, resp)
			}
			return nil
		},
	}
}

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

	if _, err = clientConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		log.Printf("Failed to send 200 OK to client: %v", err)
		return
	}

	clientTLSConn := tls.Server(clientConn, tlsConfig)
	if err := clientTLSConn.Handshake(); err != nil {
		log.Printf("Client TLS handshake failed: %v", err)
		return
	}
	defer clientTLSConn.Close()

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "https"
			req.URL.Host = r.Host
			req.Host = r.Host
			if m.Handler != nil {
				m.Handler.Handle(req, nil)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			if m.Handler != nil {
				m.Handler.Handle(nil, resp)
			}
			return nil
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	server := &http.Server{Handler: rp}
	server.Serve(newSingleConnListener(clientTLSConn))
}

func (m *MITMProxy) generateCert(host string) (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	hostname := extractHostname(host)

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

	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, m.CA, &key.PublicKey, m.CAKey)
	if err != nil {
		return nil, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
	return &cert, nil
}
