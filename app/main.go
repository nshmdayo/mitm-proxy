package main

import (
	"flag"
	"log"

	"nproxy/app/mock"
	"nproxy/app/proxy"
)

func main() {
	var (
		addr    = flag.String("addr", ":8080", "proxy server address")
		mitm    = flag.Bool("mitm", false, "start as MITM proxy")
		modify  = flag.Bool("modify", false, "enable request/response modification")
		verbose = flag.Bool("v", false, "output detailed logs")
		mockSrv = flag.Bool("mock", false, "start as mock server")
	)
	flag.Parse()

	if *mockSrv {
		// Start mock server
		log.Printf("Starting mock server on %s", *addr)
		if err := mock.Start(*addr); err != nil {
			log.Fatalf("Failed to start mock server: %v", err)
		}
	} else if *mitm {
		// Start MITM proxy
		mitmProxy, err := proxy.NewMITMProxy(*addr)
		if err != nil {
			log.Fatalf("Failed to create MITM proxy: %v", err)
		}

		if *modify {
			// Set request/response modification handler
			mitmProxy.SetHandler(proxy.CreateModificationHandler(*verbose))
		} else if *verbose {
			// Set logging-only handler
			mitmProxy.SetHandler(proxy.CreateLoggingHandler())
		}

		log.Printf("Starting MITM proxy server on %s", *addr)
		if err := mitmProxy.Start(); err != nil {
			log.Fatalf("Failed to start MITM proxy: %v", err)
		}
	} else {
		// Start normal proxy
		if err := proxy.Start(*addr); err != nil {
			log.Fatalf("Failed to start proxy: %v", err)
		}
	}
}
