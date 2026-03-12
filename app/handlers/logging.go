package handlers

import (
	"log"
	"net/http"
	"strings"
)

var sensitiveHeaders = []string{
	"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
}

// LoggingHandler creates a Handler that logs requests and responses
// while masking sensitive headers.
func LoggingHandler() Handler {
	return HandlerFunc(func(req *http.Request, resp *http.Response) {
		if req != nil {
			log.Printf("Request: %s %s", req.Method, req.URL.String())
			logHeaders(req.Header, "Request")
		}
		if resp != nil {
			log.Printf("Response: %d %s", resp.StatusCode, resp.Status)
			logHeaders(resp.Header, "Response")
		}
	})
}

func logHeaders(headers http.Header, prefix string) {
	for key, values := range headers {
		if isSensitiveHeader(key) {
			log.Printf("  %s Header %s: [MASKED]", prefix, key)
		} else {
			log.Printf("  %s Header %s: %v", prefix, key, values)
		}
	}
}

func isSensitiveHeader(key string) bool {
	lower := strings.ToLower(key)
	for _, sensitive := range sensitiveHeaders {
		if lower == sensitive {
			return true
		}
	}
	return false
}
