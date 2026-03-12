package proxy

// Server is the interface implemented by all proxy server modes.
type Server interface {
	Start() error
}
