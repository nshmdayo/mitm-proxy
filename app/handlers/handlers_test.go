package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"nproxy/app/config"
)

func TestModificationHandler(t *testing.T) {
	cfg := &config.ModConfig{
		Enabled: true,
		Verbose: false,
	}

	handler := ModificationHandler(cfg)

	// 1. Test Request Modification
	req := httptest.NewRequest("GET", "http://example.com/api/test", nil)
	handler(req, nil)

	if req.Header.Get("X-MITM-Proxy") != "true" {
		t.Error("X-MITM-Proxy header was not set on request")
	}
	if req.Header.Get("User-Agent") != "MITM-Proxy/1.0" {
		t.Error("User-Agent header was not set correctly")
	}
	if req.Header.Get("X-API-Modified") != "true" {
		t.Error("X-API-Modified header was not set for /api/ path")
	}

	// 2. Test Response Modification
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")

	handler(nil, resp)

	if resp.Header.Get("X-MITM-Intercepted") != "true" {
		t.Error("X-MITM-Intercepted header was not set on response")
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("Security header X-Content-Type-Options was not set")
	}
	if resp.Header.Get("X-HTML-Modified") != "true" {
		t.Error("X-HTML-Modified header was not set for text/html content")
	}

	// 3. Test Verbose Logging (ensure no panic)
	cfg.Verbose = true
	handler(req, resp)
}

func TestLoggingHandler(t *testing.T) {
	handler := LoggingHandler()

	req := httptest.NewRequest("GET", "http://example.com", nil)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}

	// Just ensure it doesn't panic
	handler(req, resp)
	handler(req, nil)
	handler(nil, resp)
}
