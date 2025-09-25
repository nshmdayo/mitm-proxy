package main

import (
	"log"

	"nproxy/app/config"
	"nproxy/app/handlers"
	"nproxy/app/mock"
	"nproxy/app/proxy"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	if cfg.MockServer {
		// Start mock server
		log.Printf("Starting mock server on %s", cfg.Addr)
		if err := mock.Start(cfg.Addr); err != nil {
			log.Fatalf("Failed to start mock server: %v", err)
		}
	} else if cfg.Mitm.Enabled {
		// Start MITM proxy
		mitmProxy, err := proxy.NewMITMProxy(cfg)
		if err != nil {
			log.Fatalf("Failed to create MITM proxy: %v", err)
		}

		if cfg.Modification.Enabled {
			// Set request/response modification handler
			mitmProxy.SetHandler(handlers.ModificationHandler(&cfg.Modification))
		} else if cfg.Modification.Verbose {
			// Set logging-only handler
			mitmProxy.SetHandler(handlers.LoggingHandler())
		}

		log.Printf("Starting MITM proxy server on %s", cfg.Addr)
		if err := mitmProxy.Start(); err != nil {
			log.Fatalf("Failed to start MITM proxy: %v", err)
		}
	} else {
		// Start normal proxy
		log.Printf("Starting simple proxy server on %s", cfg.Addr)
		if err := proxy.Start(cfg.Addr); err != nil {
			log.Fatalf("Failed to start proxy: %v", err)
		}
	}
}
