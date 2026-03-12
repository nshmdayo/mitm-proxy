package main

import (
	"log"

	"nproxy/app/config"
	"nproxy/app/handlers"
	"nproxy/app/mock"
	"nproxy/app/proxy"
)

type server = proxy.Server

func main() {
	cfg, err := config.LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	srv, err := buildServer(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}

	if err := srv.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func buildServer(cfg *config.Config) (server, error) {
	if cfg.MockServer {
		return mock.NewMockServer(cfg.Addr), nil
	}

	if cfg.Mitm.Enabled {
		mitmProxy, err := proxy.NewMITMProxy(cfg)
		if err != nil {
			return nil, err
		}
		if h := buildHandler(cfg); h != nil {
			mitmProxy.SetHandler(h)
		}
		return mitmProxy, nil
	}

	return proxy.NewSimpleProxy(cfg.Addr), nil
}

func buildHandler(cfg *config.Config) handlers.Handler {
	if cfg.Modification.Enabled {
		return handlers.ModificationHandler(&cfg.Modification)
	}
	if cfg.Modification.Verbose {
		return handlers.LoggingHandler()
	}
	return nil
}
