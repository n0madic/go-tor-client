// Package proxyauth defines the credential-isolated dialer abstraction shared by
// the SOCKS and HTTP proxy servers. Both servers select an upstream Dialer per
// client credential pair, so the caller can isolate traffic on a dedicated path
// per identity — mirroring tor's IsolateSOCKSAuth, where the proxy username and
// password are an isolation token rather than a validated credential.
//
// The package knows nothing about Tor or any particular transport.
package proxyauth

import (
	"context"
	"net"
)

// Dialer opens the upstream connection that a proxy relays or forwards to.
// *tor.Client satisfies it via its DialContext method.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DialerFactory returns the Dialer to use for a connection's auth identity. user
// and pass are empty for unauthenticated connections. Returning a distinct
// Dialer per identity lets the caller isolate traffic (e.g. a dedicated Tor
// guard channel and circuit pool per credential pair, mirroring tor's
// IsolateSOCKSAuth).
type DialerFactory func(ctx context.Context, user, pass string) (Dialer, error)

// IsoKey is the isolation key for an auth identity: "" for no-auth, otherwise
// user and pass joined by a NUL byte. NUL cannot appear in a SOCKS username or
// password (RFC 1929 length-prefixes them) nor in HTTP Basic credentials, so
// the mapping from (user, pass) to key is unambiguous.
func IsoKey(user, pass string) string {
	if user == "" && pass == "" {
		return ""
	}
	return user + "\x00" + pass
}
