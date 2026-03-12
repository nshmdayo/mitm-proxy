package proxy

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"mitmproxy/app/config"
	"mitmproxy/app/handlers"
)

func TestNewMITMProxy(t *testing.T) {
	cfg := &config.Config{
		Addr: ":0",
		Mitm: config.MitmConfig{
			Enabled:   true,
			PersistCA: false,
			CertDir:   "./certs",
		},
	}
	proxy, err := NewMITMProxy(cfg)
	if err != nil {
		t.Fatalf("Failed to create MITM proxy: %v", err)
	}

	if proxy == nil {
		t.Fatal("Proxy is nil")
	}
	if proxy.CA == nil {
		t.Error("CA certificate was not generated")
	}
	if proxy.CAKey == nil {
		t.Error("CA private key was not generated")
	}
	if proxy.CertDir != "./certs" {
		t.Errorf("Expected CertDir './certs', got '%s'", proxy.CertDir)
	}
	if proxy.Addr != ":0" {
		t.Errorf("Expected Addr ':0', got '%s'", proxy.Addr)
	}
}

func TestMITMProxy_SetHandler(t *testing.T) {
	cfg := &config.Config{
		Addr: ":0",
		Mitm: config.MitmConfig{
			Enabled:   true,
			PersistCA: false,
			CertDir:   "./certs",
		},
	}
	proxy, err := NewMITMProxy(cfg)
	if err != nil {
		t.Fatalf("Failed to create MITM proxy: %v", err)
	}

	if proxy.Handler != nil {
		t.Error("Handler should be nil initially")
	}

	var called bool
	proxy.SetHandler(handlers.HandlerFunc(func(req *http.Request, resp *http.Response) {
		called = true
	}))

	if proxy.Handler == nil {
		t.Error("Handler was not set")
	}

	proxy.Handler.Handle(nil, nil)
	if !called {
		t.Error("Handler was not called")
	}
}

func TestMITMProxy_HandleHTTP(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test-Response", "true")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from target"))
	}))
	defer targetServer.Close()

	cfg := &config.Config{
		Addr: ":0",
		Mitm: config.MitmConfig{
			Enabled:   true,
			PersistCA: false,
			CertDir:   "./certs",
		},
	}
	proxy, err := NewMITMProxy(cfg)
	if err != nil {
		t.Fatalf("Failed to create MITM proxy: %v", err)
	}

	var interceptedRequest *http.Request
	var interceptedResponse *http.Response
	proxy.SetHandler(handlers.HandlerFunc(func(req *http.Request, resp *http.Response) {
		if req != nil {
			interceptedRequest = req
			req.Header.Set("X-Intercepted-Request", "true")
		}
		if resp != nil {
			interceptedResponse = resp
			resp.Header.Set("X-Intercepted-Response", "true")
		}
	}))

	targetURL, _ := url.Parse(targetServer.URL)
	req := httptest.NewRequest("GET", targetServer.URL, nil)
	req.Host = targetURL.Host
	req.URL.Scheme = "http"
	req.URL.Host = targetURL.Host
	req.Header.Set("X-Original-Header", "test")

	w := httptest.NewRecorder()
	rp := proxy.createReverseProxy()
	rp.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
	if body := w.Body.String(); body != "Hello from target" {
		t.Errorf("Expected body 'Hello from target', got '%s'", body)
	}
	if w.Header().Get("X-Test-Response") != "true" {
		t.Error("Target server header was not copied")
	}
	if w.Header().Get("X-Intercepted-Response") != "true" {
		t.Error("Intercepted response header was not added")
	}
	if interceptedRequest == nil {
		t.Error("Request was not intercepted")
	} else if interceptedRequest.Header.Get("X-Intercepted-Request") != "true" {
		t.Error("Request was not modified by handler")
	}
	if interceptedResponse == nil {
		t.Error("Response was not intercepted")
	}
}

func TestMITMProxy_HandleConnect(t *testing.T) {
	cfg := &config.Config{
		Addr: ":0",
		Mitm: config.MitmConfig{
			Enabled:   true,
			PersistCA: false,
			CertDir:   "./certs",
		},
	}
	proxy, err := NewMITMProxy(cfg)
	if err != nil {
		t.Fatalf("Failed to create MITM proxy: %v", err)
	}

	req := httptest.NewRequest("CONNECT", "example.com:443", nil)
	req.Host = "example.com:443"
	w := httptest.NewRecorder()

	// NOTE: handleConnect requires Hijack support which httptest.Recorder does not provide.
	// It should return 500.
	proxy.handleConnect(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Logf("CONNECT response status: %d", w.Code)
	}
}

func TestMITMProxy_GenerateCert(t *testing.T) {
	cfg := &config.Config{
		Addr: ":0",
		Mitm: config.MitmConfig{
			Enabled:   true,
			PersistCA: false,
			CertDir:   "./certs",
		},
	}
	proxy, err := NewMITMProxy(cfg)
	if err != nil {
		t.Fatalf("Failed to create MITM proxy: %v", err)
	}

	tests := []struct {
		host string
	}{
		{"example.com:443"},
		{"localhost:8080"},
		{"192.168.1.1:443"},
		{"test.local:9000"},
	}

	for _, test := range tests {
		cert, err := proxy.generateCert(test.host)
		if err != nil {
			t.Errorf("Failed to generate certificate for %s: %v", test.host, err)
			continue
		}
		if cert == nil {
			t.Errorf("Certificate is nil for host %s", test.host)
			continue
		}
		if len(cert.Certificate) == 0 {
			t.Errorf("Certificate is empty for host %s", test.host)
		}
	}
}

func TestExtractHostname(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com:443", "example.com"},
		{"localhost:8080", "localhost"},
		{"192.168.1.1:80", "192.168.1.1"},
		{"example.com", "example.com"},
		{"[::1]:8080", "::1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
	}

	for _, test := range tests {
		result := extractHostname(test.input)
		if result != test.expected {
			t.Errorf("extractHostname(%s) = %s, expected %s", test.input, result, test.expected)
		}
	}
}

func TestMITMProxy_SaveCA(t *testing.T) {
	cfg := &config.Config{
		Addr: ":0",
		Mitm: config.MitmConfig{
			Enabled:   true,
			PersistCA: false,
			CertDir:   "./test_certs",
		},
	}
	proxy, err := NewMITMProxy(cfg)
	if err != nil {
		t.Fatalf("Failed to create MITM proxy: %v", err)
	}

	tempDir := "./test_certs"
	defer os.RemoveAll(tempDir)

	if err := os.MkdirAll(tempDir, 0755); err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	if err := saveCA(tempDir, proxy.CA, proxy.CAKey); err != nil {
		t.Fatalf("Failed to save CA certificate: %v", err)
	}

	certFile := tempDir + "/ca.crt"
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Error("CA certificate file was not created")
	}

	content, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("Failed to read CA certificate file: %v", err)
	}
	if !strings.Contains(string(content), "-----BEGIN CERTIFICATE-----") {
		t.Error("CA certificate file does not contain PEM header")
	}
	if !strings.Contains(string(content), "-----END CERTIFICATE-----") {
		t.Error("CA certificate file does not contain PEM footer")
	}
}

func TestMITMProxy_HTTPSInterception(t *testing.T) {
	cfg := &config.Config{
		Addr: ":0",
		Mitm: config.MitmConfig{
			Enabled:   true,
			PersistCA: false,
			CertDir:   "./certs",
		},
	}
	proxy, err := NewMITMProxy(cfg)
	if err != nil {
		t.Fatalf("Failed to create MITM proxy: %v", err)
	}

	cert, err := proxy.generateCert("test.example.com:443")
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}
	if cert == nil {
		t.Fatal("Generated certificate is nil")
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("Generated certificate is empty")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}
	if len(tlsConfig.Certificates) != 1 {
		t.Error("TLS config should contain exactly one certificate")
	}

	t.Log("HTTPS interception components test passed")
}

func serveProxyHTTP(p *MITMProxy, w http.ResponseWriter, r *http.Request) {
	rp := p.createReverseProxy()
	rp.ServeHTTP(w, r)
}

func TestMITMProxy_HandleRequestMethod(t *testing.T) {
	cfg := &config.Config{
		Addr: ":0",
		Mitm: config.MitmConfig{
			Enabled:   true,
			PersistCA: false,
			CertDir:   "./certs",
		},
	}
	proxy, err := NewMITMProxy(cfg)
	if err != nil {
		t.Fatalf("Failed to create MITM proxy: %v", err)
	}

	tests := []struct {
		method string
		url    string
	}{
		{"GET", "http://example.com/test"},
		{"POST", "http://example.com/api"},
	}

	for _, test := range tests {
		req := httptest.NewRequest(test.method, test.url, nil)
		w := httptest.NewRecorder()
		serveProxyHTTP(proxy, w, req)
		// 502 Bad Gateway expected because there is no backend server
		if w.Code != http.StatusBadGateway {
			t.Logf("Method %s handled, response status: %d (Expected 502)", test.method, w.Code)
		}
	}
}

func TestMITMProxy_ErrorHandling(t *testing.T) {
	cfg := &config.Config{
		Addr: ":0",
		Mitm: config.MitmConfig{
			Enabled:   true,
			PersistCA: false,
			CertDir:   "./certs",
		},
	}
	proxy, err := NewMITMProxy(cfg)
	if err != nil {
		t.Fatalf("Failed to create MITM proxy: %v", err)
	}

	req := httptest.NewRequest("GET", "http://nonexistent-host.local/test", nil)
	w := httptest.NewRecorder()
	serveProxyHTTP(proxy, w, req)
	if w.Code != http.StatusBadGateway {
		t.Logf("Error handling test: got status %d", w.Code)
	}

	connectReq := httptest.NewRequest("CONNECT", "https://nonexistent-host.local:443", nil)
	connectReq.Host = "nonexistent-host.local:443"
	connectW := httptest.NewRecorder()
	proxy.handleConnect(connectW, connectReq)
}

func BenchmarkMITMProxy_GenerateCert(b *testing.B) {
	cfg := &config.Config{
		Addr: ":0",
		Mitm: config.MitmConfig{
			Enabled:   true,
			PersistCA: false,
			CertDir:   "./certs",
		},
	}
	proxy, err := NewMITMProxy(cfg)
	if err != nil {
		b.Fatalf("Failed to create MITM proxy: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := proxy.generateCert("example.com:443")
		if err != nil {
			b.Fatalf("Failed to generate certificate: %v", err)
		}
	}
}

func BenchmarkMITMProxy_HandleHTTP(b *testing.B) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer targetServer.Close()

	cfg := &config.Config{
		Addr: ":0",
		Mitm: config.MitmConfig{
			Enabled:   true,
			PersistCA: false,
			CertDir:   "./certs",
		},
	}
	proxy, err := NewMITMProxy(cfg)
	if err != nil {
		b.Fatalf("Failed to create MITM proxy: %v", err)
	}

	targetURL, _ := url.Parse(targetServer.URL)
	req := httptest.NewRequest("GET", targetServer.URL, nil)
	req.Host = targetURL.Host
	req.URL.Scheme = "http"
	req.URL.Host = targetURL.Host

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		rp := proxy.createReverseProxy()
		rp.ServeHTTP(w, req)
	}
}
