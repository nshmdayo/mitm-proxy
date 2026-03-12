package proxy

import "net"

// extractHostname extracts the hostname from a "host:port" string.
func extractHostname(host string) string {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return hostname
}
