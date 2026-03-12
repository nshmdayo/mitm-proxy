package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"mitm-proxy/app/config"
)

func TestModificationHandler(t *testing.T) {
	cfg := &config.ModConfig{
		Enabled: true,
		Verbose: false,
		Request: config.HeaderRules{
			Set: map[string]string{
				"X-MITM-Proxy": "true",
				"User-Agent":   "nproxy/1.0",
			},
			Remove: []string{"X-Remove-Me"},
		},
		Response: config.HeaderRules{
			Set: map[string]string{
				"X-MITM-Intercepted":    "true",
				"X-Content-Type-Options": "nosniff",
			},
			Remove: []string{"X-Remove-Me"},
		},
	}

	handler := ModificationHandler(cfg)

	// 1. Test Request Modification
	req := httptest.NewRequest("GET", "http://example.com/api/test", nil)
	req.Header.Set("X-Remove-Me", "should-be-removed")
	handler.Handle(req, nil)

	if req.Header.Get("X-MITM-Proxy") != "true" {
		t.Error("X-MITM-Proxy header was not set on request")
	}
	if req.Header.Get("User-Agent") != "nproxy/1.0" {
		t.Error("User-Agent header was not set correctly")
	}
	if req.Header.Get("X-Remove-Me") != "" {
		t.Error("X-Remove-Me header was not removed from request")
	}

	// 2. Test Response Modification
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     make(http.Header),
	}
	resp.Header.Set("X-Remove-Me", "should-be-removed")

	handler.Handle(nil, resp)

	if resp.Header.Get("X-MITM-Intercepted") != "true" {
		t.Error("X-MITM-Intercepted header was not set on response")
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("Security header X-Content-Type-Options was not set")
	}
	if resp.Header.Get("X-Remove-Me") != "" {
		t.Error("X-Remove-Me header was not removed from response")
	}

	// 3. Test Verbose Logging (ensure no panic)
	cfg.Verbose = true
	handler.Handle(req, resp)
}

func TestLoggingHandler(t *testing.T) {
	handler := LoggingHandler()

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     make(http.Header),
	}

	// Ensure it does not panic in all call combinations
	handler.Handle(req, resp)
	handler.Handle(req, nil)
	handler.Handle(nil, resp)
}

func TestIsSensitiveHeader(t *testing.T) {
	cases := []struct {
		key       string
		sensitive bool
	}{
		{"Authorization", true},
		{"authorization", true},
		{"Cookie", true},
		{"Set-Cookie", true},
		{"X-Api-Key", true},
		{"x-api-key", true},
		{"x-auth-token", true},
		{"Content-Type", false},
		{"X-Custom-Header", false},
	}

	for _, c := range cases {
		got := isSensitiveHeader(c.key)
		if got != c.sensitive {
			t.Errorf("isSensitiveHeader(%q) = %v, want %v", c.key, got, c.sensitive)
		}
	}
}

func TestHandlerFunc(t *testing.T) {
	var called bool
	var h Handler = HandlerFunc(func(req *http.Request, resp *http.Response) {
		called = true
	})

	h.Handle(nil, nil)
	if !called {
		t.Error("HandlerFunc.Handle did not call the underlying function")
	}
}
