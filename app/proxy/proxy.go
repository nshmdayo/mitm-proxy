package proxy

import (
	"log"
	"net/http"
)

// Start initializes and starts the basic proxy server.
func Start(addr string) error {
	// The log message from main.go is moved here to better encapsulate proxy startup.
	log.Printf("Starting simple proxy server on %s", addr)
	http.HandleFunc("/", handleProxyRequest)
	return http.ListenAndServe(addr, nil)
}

// handleProxyRequest is the core handler for all incoming proxy requests.
// It determines the target, forwards the request, and sends the response back.
func handleProxyRequest(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request: %s %s", r.Method, r.URL.String())

	targetURL := getTargetURL(r)
	log.Printf("Forwarding request to: %s", targetURL)

	// Forward the request to the target server.
	resp, err := forwardRequest(r, targetURL)
	if err != nil {
		log.Printf("Failed to forward request: %v", err)
		http.Error(w, "Failed to forward request", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	log.Printf("Received response: %d %s", resp.StatusCode, resp.Status)

	// Write the target's response back to the client.
	writeResponse(w, resp)
}

// getTargetURL determines the destination URL from the incoming request.
// It handles both direct and proxy-style requests.
func getTargetURL(r *http.Request) string {
	if r.URL.IsAbs() {
		// The request is already in proxy format with an absolute URL.
		return r.URL.String()
	}
	// The request is a direct-style request, so we construct the full URL.
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.RequestURI()
}

// forwardRequest creates and sends a new request to the target URL.
// It copies the method, body, and headers from the original request.
func forwardRequest(r *http.Request, targetURL string) (*http.Response, error) {
	// Create a new request to the target URL.
	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		return nil, err
	}

	// Copy headers from the original request.
	copyHeaders(req.Header, r.Header)

	// Send the request using a default HTTP client.
	client := &http.Client{}
	return client.Do(req)
}
