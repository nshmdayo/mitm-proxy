package proxy

import (
	"io"
	"net"
	"net/http"
)

// copyHeaders is a utility function to duplicate headers from a source to a destination.
func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// extractHostname extracts the hostname from a host:port string.
func extractHostname(host string) string {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return hostname
}

// writeResponse copies the target's response (headers, status code, and body)
// back to the original response writer.
func writeResponse(w http.ResponseWriter, resp *http.Response) {
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}