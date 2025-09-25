package proxy

import (
	"log"
	"net/http"
	"regexp"
	"strings"
)

// CreateModificationHandler creates a handler for request/response modification
func CreateModificationHandler(verbose bool) func(*http.Request, *http.Response) {
	return func(req *http.Request, resp *http.Response) {
		if req != nil {
			if verbose {
				log.Printf("Request: %s %s", req.Method, req.URL.String())
				log.Printf("Request Headers: %v", req.Header)
			}

			// Example of request header modification
			req.Header.Set("X-MITM-Proxy", "true")
			req.Header.Set("User-Agent", "MITM-Proxy/1.0")

			// Modify requests for specific patterns
			if strings.Contains(req.URL.Path, "/api/") {
				req.Header.Set("X-API-Modified", "true")
			}
		}

		if resp != nil {
			if verbose {
				log.Printf("Response: %d %s", resp.StatusCode, resp.Status)
				log.Printf("Response Headers: %v", resp.Header)
			}

			// Example of response header modification
			resp.Header.Set("X-MITM-Intercepted", "true")
			resp.Header.Set("X-Proxy-Time", "2024-01-01")

			// Add security headers
			resp.Header.Set("X-Content-Type-Options", "nosniff")
			resp.Header.Set("X-Frame-Options", "DENY")
			resp.Header.Set("X-XSS-Protection", "1; mode=block")

			// Process text/html content type
			if contentType := resp.Header.Get("Content-Type"); strings.Contains(contentType, "text/html") {
				resp.Header.Set("X-HTML-Modified", "true")
			}
		}
	}
}

// CreateLoggingHandler creates a handler for logging only
func CreateLoggingHandler() func(*http.Request, *http.Response) {
	return func(req *http.Request, resp *http.Response) {
		if req != nil {
			log.Printf("📤 Request: %s %s", req.Method, req.URL.String())

			// Log headers while masking sensitive information
			LogHeaders(req.Header, "Request")
		}

		if resp != nil {
			log.Printf("📥 Response: %d %s", resp.StatusCode, resp.Status)

			// Log response headers
			LogHeaders(resp.Header, "Response")
		}
	}
}

// LogHeaders safely logs header information
func LogHeaders(headers http.Header, prefix string) {
	sensitiveHeaders := []string{
		"Authorization", "Cookie", "Set-Cookie", "X-API-Key", "X-Auth-Token",
	}

	for key, values := range headers {
		// Check if header contains sensitive information
		isSensitive := false
		for _, sensitive := range sensitiveHeaders {
			if matched, _ := regexp.MatchString("(?i)"+sensitive, key); matched {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			log.Printf("  %s Header %s: [MASKED]", prefix, key)
		} else {
			log.Printf("  %s Header %s: %v", prefix, key, values)
		}
	}
}