package proxy

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func Start(addr string) error {
	proxy := &httputil.ReverseProxy{
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

	log.Printf("Starting simple proxy server on %s", addr)
	return http.ListenAndServe(addr, proxy)
}
