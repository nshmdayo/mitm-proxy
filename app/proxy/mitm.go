package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"nproxy/app/cert"
	"strings"
)

// MITMProxy holds the configuration for the MITM proxy server.
type MITMProxy struct {
	Addr        string
	CertManager *cert.CertManager
	Handler     func(*http.Request, *http.Response)
}

// NewMITMProxy creates a new MITM proxy instance.
func NewMITMProxy(addr string) (*MITMProxy, error) {
	certManager, err := cert.NewCertManager("./certs")
	if err != nil {
		return nil, fmt.Errorf("failed to create cert manager: %v", err)
	}

	return &MITMProxy{
		Addr:        addr,
		CertManager: certManager,
	}, nil
}

// Start begins the MITM proxy server.
func (m *MITMProxy) Start() error {
	if err := m.CertManager.SaveCA(); err != nil {
		return fmt.Errorf("failed to save CA certificate: %v", err)
	}

	server := &http.Server{
		Addr:    m.Addr,
		Handler: http.HandlerFunc(m.handleRequest),
	}

	log.Printf("MITM Proxy server starting on %s", m.Addr)
	log.Printf("CA certificate saved to %s/ca.crt", m.CertManager.CertDir)
	log.Println("Install the CA certificate in your browser to avoid SSL warnings")

	return server.ListenAndServe()
}

// SetHandler sets the handler for request/response modification.
func (m *MITMProxy) SetHandler(handler func(*http.Request, *http.Response)) {
	m.Handler = handler
}

// handleRequest processes incoming HTTP/HTTPS requests.
func (m *MITMProxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method == "CONNECT" {
		m.handleConnect(w, r)
	} else {
		m.handleHTTP(w, r)
	}
}

// handleConnect handles the HTTPS CONNECT method.
func (m *MITMProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	log.Printf("CONNECT request to %s", r.Host)
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Println("Hijacking not supported")
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("Failed to hijack connection: %v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	targetConn, err := net.Dial("tcp", r.Host)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", r.Host, err)
		return
	}
	defer targetConn.Close()

	cert, err := m.CertManager.GenerateCert(r.Host)
	if err != nil {
		log.Printf("Failed to generate certificate for %s: %v", r.Host, err)
		return
	}

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{*cert}}
	clientTLSConn := tls.Server(clientConn, tlsConfig)
	defer clientTLSConn.Close()

	serverTLSConn := tls.Client(targetConn, &tls.Config{
		ServerName:         extractHostname(r.Host),
		InsecureSkipVerify: true,
	})
	defer serverTLSConn.Close()

	if err := clientTLSConn.Handshake(); err != nil {
		log.Printf("Client TLS handshake failed: %v", err)
		return
	}
	if err := serverTLSConn.Handshake(); err != nil {
		log.Printf("Server TLS handshake failed: %v", err)
		return
	}

	m.interceptHTTPS(clientTLSConn, serverTLSConn)
}

// handleHTTP handles plain HTTP requests.
func (m *MITMProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("HTTP request to %s", r.URL.String())

	if m.Handler != nil {
		m.Handler(r, nil)
	}

	resp, err := m.forwardAndGetResponse(r)
	if err != nil {
		http.Error(w, "Failed to forward request", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if m.Handler != nil {
		m.Handler(r, resp)
	}

	writeResponse(w, resp)
}

// forwardAndGetResponse forwards an HTTP request and returns the response.
func (m *MITMProxy) forwardAndGetResponse(r *http.Request) (*http.Response, error) {
	targetURL := r.URL.String()
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "http://" + r.Host + r.RequestURI
	}

	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		return nil, err
	}

	copyHeaders(req.Header, r.Header)

	client := &http.Client{}
	return client.Do(req)
}

// interceptHTTPS intercepts and forwards HTTPS traffic.
func (m *MITMProxy) interceptHTTPS(clientConn, serverConn *tls.Conn) {
	go func() {
		defer clientConn.Close()
		defer serverConn.Close()
		reader := bufio.NewReader(clientConn)
		for {
			req, err := http.ReadRequest(reader)
			if err != nil {
				break
			}
			if m.Handler != nil {
				m.Handler(req, nil)
			}
			req.Write(serverConn)
		}
	}()

	reader := bufio.NewReader(serverConn)
	for {
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			break
		}
		if m.Handler != nil {
			m.Handler(nil, resp)
		}
		resp.Write(clientConn)
	}
}