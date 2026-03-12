package handlers

import (
	"log"
	"net/http"

	"mitmproxy/app/config"
)

// ModificationHandler creates a Handler that modifies request and response headers
// based on the rules defined in cfg.
func ModificationHandler(cfg *config.ModConfig) Handler {
	return HandlerFunc(func(req *http.Request, resp *http.Response) {
		if req != nil {
			if cfg.Verbose {
				log.Printf("Request: %s %s", req.Method, req.URL.String())
				log.Printf("Request Headers: %v", req.Header)
			}
			for key, value := range cfg.Request.Set {
				req.Header.Set(key, value)
			}
			for _, key := range cfg.Request.Remove {
				req.Header.Del(key)
			}
		}

		if resp != nil {
			if cfg.Verbose {
				log.Printf("Response: %d %s", resp.StatusCode, resp.Status)
				log.Printf("Response Headers: %v", resp.Header)
			}
			for key, value := range cfg.Response.Set {
				resp.Header.Set(key, value)
			}
			for _, key := range cfg.Response.Remove {
				resp.Header.Del(key)
			}
		}
	})
}
