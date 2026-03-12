package proxy

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// SimpleProxy is a basic HTTP forward proxy.
type SimpleProxy struct {
	addr string
}

// NewSimpleProxy creates a new SimpleProxy.
func NewSimpleProxy(addr string) *SimpleProxy {
	return &SimpleProxy{addr: addr}
}

// Start starts the simple proxy server.
func (s *SimpleProxy) Start() error {
	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			target, err := url.Parse(r.URL.String())
			if err != nil {
				log.Printf("Failed to parse target URL: %v", err)
				return
			}
			r.URL = target
			if _, ok := r.Header["User-Agent"]; !ok {
				// explicitly disable User-Agent so it's not set to default value
				r.Header.Set("User-Agent", "")
			}
			log.Printf("Forwarding request to: %s", r.URL)
		},
	}

	log.Printf("Starting simple proxy server on %s", s.addr)
	return http.ListenAndServe(s.addr, rp)
}

// Start is a package-level convenience function used by existing tests.
func Start(addr string) error {
	return NewSimpleProxy(addr).Start()
}
