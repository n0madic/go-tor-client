// Package relay copies data bidirectionally between two connections for proxy
// tunnels (SOCKS CONNECT, HTTP CONNECT).
package relay

import (
	"io"
	"net"
	"sync"
)

// Bidirectional copies data both ways between a and b until one direction ends,
// then closes both connections so the other io.Copy unwinds, and waits for both
// to finish.
//
// It performs a full close (not a half-close): the underlying Tor stream has no
// CloseWrite, so closing one direction tears the whole connection down. A peer
// that closes only its write half mid-stream therefore ends the connection —
// fine for request/response (HTTP) traffic, which is the proxy's intended use.
func Bidirectional(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		_ = a.Close()
		_ = b.Close()
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}
