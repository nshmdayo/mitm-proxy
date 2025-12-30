package proxy

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestProxy(t *testing.T) {
	// 1. Start a mock target server
	targetServer := http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}
	// Listen on a random port
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to listen for target server: %v", err)
	}
	targetPort := ln.Addr().(*net.TCPAddr).Port
	go targetServer.Serve(ln)
	defer targetServer.Close()

	// 2. Start the proxy server
	// We need to run Start in a goroutine because it blocks.
	// But Start takes an address. We should pick a random port.
	proxyLn, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to listen for proxy port allocation: %v", err)
	}
	proxyAddr := proxyLn.Addr().String()
	proxyLn.Close() // Close it so Start can listen on it

	go func() {
		// Note: There is a small race condition here where the port could be taken
		// between Close and Start, but it's rare in tests.
		// A better way would be if Start accepted a listener, but it accepts a string.
		if err := Start(proxyAddr); err != nil && err != http.ErrServerClosed {
			// t.Errorf here might be dangerous if test finished
			// log.Printf("Proxy server error: %v", err)
		}
	}()

	// Wait for proxy to start
	waitForServer(t, proxyAddr)

	// 3. Send a request to the proxy
	// Start in proxy.go creates a ReverseProxy that forwards to the URL specified in the request.
	// However, the implementation says:
	// target, err := url.Parse(r.URL.String())
	// r.URL = target
	// This usually means it behaves like a forward proxy if the request URL is absolute,
	// or it might be expecting r.URL to already contain the target if it was modified?
	// The code:
	/*
		Director: func(r *http.Request) {
			target, err := url.Parse(r.URL.String())
			// ...
			r.URL = target
			// ...
		}
	*/
	// If I send "GET http://target/ HTTP/1.1", r.URL.String() is "http://target/".
	// If I send "GET / HTTP/1.1", r.URL.String() is "/". Parse("/") returns path / and empty host.
	// So this proxy seems to expect absolute URLs (Forward Proxy behavior).

	proxyUrl := fmt.Sprintf("http://%s", proxyAddr)
	targetUrl := fmt.Sprintf("http://127.0.0.1:%d", targetPort)

	req, err := http.NewRequest("GET", targetUrl, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Configure client to use the proxy
	proxyURL, _ := url.Parse(proxyUrl)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request through proxy: %v", err)
	}
	defer resp.Body.Close()

	// 4. Verify response
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", resp.StatusCode)
	}
}

func waitForServer(t *testing.T, addr string) {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("Server failed to start on %s within timeout", addr)
}
