// Package socks implements a minimal SOCKS5 proxy server (RFC 1928) with
// optional username/password authentication (RFC 1929). It is dialer-agnostic:
// the caller supplies a DialerFactory that returns a Dialer for a given auth
// identity, so the same server can tunnel through any net.Conn-producing
// transport. The package knows nothing about Tor.
//
// Only the CONNECT command is supported; BIND and UDP ASSOCIATE are rejected
// with "command not supported". Hostnames in DOMAINNAME requests are passed to
// the dialer verbatim (never resolved locally), so DNS resolution happens at
// the far end of the tunnel — essential for anonymity, and required for .onion
// addresses which only the dialer can route.
package socks

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"

	"github.com/n0madic/go-tor-client/internal/relay"
	"github.com/n0madic/go-tor-client/pkg/proxyauth"
)

// SOCKS protocol constants (RFC 1928, RFC 1929).
const (
	version5    = 0x05 // SOCKS protocol version
	authVersion = 0x01 // RFC 1929 username/password sub-negotiation version

	// Authentication methods (RFC 1928 §3).
	methodNoAuth       = 0x00
	methodUserPass     = 0x02
	methodNoAcceptable = 0xFF

	// Commands (RFC 1928 §4). Only CONNECT is supported; BIND (0x02) and UDP
	// ASSOCIATE (0x03) are rejected with replyCommandNotSupported.
	cmdConnect = 0x01

	// Address types (RFC 1928 §4).
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	// Reply codes (RFC 1928 §6).
	replySuccess              = 0x00
	replyGeneralFailure       = 0x01
	replyCommandNotSupported  = 0x07
	replyAddrTypeNotSupported = 0x08
	replyTTLExpired           = 0x06

	// authStatusSuccess is the RFC 1929 status byte for accepted credentials.
	authStatusSuccess = 0x00
)

// errUnsupportedAddrType is returned when a request carries an address type the
// server cannot parse; the handler replies with replyAddrTypeNotSupported.
var errUnsupportedAddrType = errors.New("socks: unsupported address type")

// Server is a SOCKS5 proxy. Factory is required and selects the upstream dialer
// per connection's auth identity (see proxyauth.DialerFactory); Logger is
// optional and defaults to a discard logger.
type Server struct {
	Factory proxyauth.DialerFactory
	Logger  *slog.Logger
}

func (s *Server) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Serve accepts connections on ln and handles each in its own goroutine until
// ctx is cancelled or ln fails permanently. It closes ln when ctx is cancelled
// so a blocked Accept unwinds, and returns nil after such a clean shutdown (or
// the underlying error on an unexpected Accept failure).
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	logger := s.logger()

	// Close the listener on cancellation to unblock Accept; the done channel
	// stops this watcher if Serve returns for another reason first.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
		case <-done:
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("socks: accept: %w", err)
			}
		}
		go func() {
			defer conn.Close()
			if err := s.handle(ctx, conn); err != nil {
				logger.Debug("socks: connection failed", "remote", conn.RemoteAddr(), "err", err)
			}
		}()
	}
}

// handle runs the full SOCKS5 exchange for one connection: method negotiation,
// optional user/pass auth, the CONNECT request, the upstream dial, and the
// bidirectional relay.
func (s *Server) handle(ctx context.Context, conn net.Conn) error {
	user, pass, err := negotiate(conn)
	if err != nil {
		return err
	}

	cmd, host, port, err := readRequest(conn)
	if err != nil {
		if errors.Is(err, errUnsupportedAddrType) {
			_ = sendReply(conn, replyAddrTypeNotSupported)
		}
		return err
	}
	if cmd != cmdConnect {
		_ = sendReply(conn, replyCommandNotSupported)
		return fmt.Errorf("socks: unsupported command 0x%02x", cmd)
	}

	dialer, err := s.Factory(ctx, user, pass)
	if err != nil {
		_ = sendReply(conn, replyGeneralFailure)
		return fmt.Errorf("socks: dialer factory: %w", err)
	}

	target := net.JoinHostPort(host, port)
	up, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		_ = sendReply(conn, dialErrorReply(err))
		return fmt.Errorf("socks: dial %s: %w", target, err)
	}
	defer up.Close()

	// Reply with a hidden bind address (0.0.0.0:0): the real upstream socket is
	// never disclosed to the client.
	if err := sendReply(conn, replySuccess); err != nil {
		return err
	}
	relay.Bidirectional(conn, up)
	return nil
}

// negotiate performs SOCKS5 method negotiation and, when username/password is
// selected, the RFC 1929 sub-negotiation. It returns the supplied credentials
// (empty for no-auth). On no acceptable method it replies 0xFF and errors.
func negotiate(conn net.Conn) (user, pass string, err error) {
	header := make([]byte, 2) // VER, NMETHODS
	if _, err = io.ReadFull(conn, header); err != nil {
		return "", "", err
	}
	if header[0] != version5 {
		return "", "", fmt.Errorf("socks: unsupported version 0x%02x", header[0])
	}
	methods := make([]byte, int(header[1]))
	if _, err = io.ReadFull(conn, methods); err != nil {
		return "", "", err
	}

	switch {
	case bytes.IndexByte(methods, methodUserPass) >= 0:
		// Prefer user/pass when offered: it carries the isolation token.
		if _, err = conn.Write([]byte{version5, methodUserPass}); err != nil {
			return "", "", err
		}
		return readUserPass(conn)
	case bytes.IndexByte(methods, methodNoAuth) >= 0:
		if _, err = conn.Write([]byte{version5, methodNoAuth}); err != nil {
			return "", "", err
		}
		return "", "", nil
	default:
		_, _ = conn.Write([]byte{version5, methodNoAcceptable})
		return "", "", errors.New("socks: no acceptable authentication method")
	}
}

// readUserPass reads RFC 1929 credentials and accepts them unconditionally. The
// pair is not validated: it is purely an isolation token (mirroring tor's
// IsolateSOCKSAuth), so the caller's DialerFactory can map it to a dedicated
// circuit identity.
func readUserPass(conn net.Conn) (user, pass string, err error) {
	header := make([]byte, 2) // VER, ULEN
	if _, err = io.ReadFull(conn, header); err != nil {
		return "", "", err
	}
	if header[0] != authVersion {
		return "", "", fmt.Errorf("socks: unsupported auth version 0x%02x", header[0])
	}
	uname := make([]byte, int(header[1]))
	if _, err = io.ReadFull(conn, uname); err != nil {
		return "", "", err
	}
	plen := make([]byte, 1)
	if _, err = io.ReadFull(conn, plen); err != nil {
		return "", "", err
	}
	passwd := make([]byte, int(plen[0]))
	if _, err = io.ReadFull(conn, passwd); err != nil {
		return "", "", err
	}
	if _, err = conn.Write([]byte{authVersion, authStatusSuccess}); err != nil {
		return "", "", err
	}
	return string(uname), string(passwd), nil
}

// readRequest reads a SOCKS5 request and returns its command plus the target
// host and port. The host is returned verbatim for DOMAINNAME (no local DNS).
func readRequest(r io.Reader) (cmd byte, host, port string, err error) {
	header := make([]byte, 4) // VER, CMD, RSV, ATYP
	if _, err = io.ReadFull(r, header); err != nil {
		return 0, "", "", err
	}
	if header[0] != version5 {
		return 0, "", "", fmt.Errorf("socks: unsupported version 0x%02x", header[0])
	}
	cmd = header[1]

	host, err = readAddr(r, header[3])
	if err != nil {
		return cmd, "", "", err
	}

	portBuf := make([]byte, 2)
	if _, err = io.ReadFull(r, portBuf); err != nil {
		return cmd, "", "", err
	}
	return cmd, host, strconv.Itoa(int(binary.BigEndian.Uint16(portBuf))), nil
}

// readAddr reads the DST.ADDR field for the given address type and formats it as
// a host string. DOMAINNAME bytes are returned verbatim — never resolved here,
// which would leak DNS and deanonymize the client.
func readAddr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		buf := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case atypIPv6:
		buf := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return "", err
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(r, domain); err != nil {
			return "", err
		}
		return string(domain), nil
	default:
		return "", errUnsupportedAddrType
	}
}

// sendReply writes a SOCKS5 reply with the given code and a hidden bind address
// (IPv4 0.0.0.0:0): the proxy's real upstream socket is never revealed.
func sendReply(w io.Writer, code byte) error {
	// VER, REP, RSV, ATYP=IPv4, BND.ADDR(4)=0.0.0.0, BND.PORT(2)=0
	_, err := w.Write([]byte{version5, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// dialErrorReply maps a dial error to the closest SOCKS reply code.
func dialErrorReply(err error) byte {
	if errors.Is(err, context.DeadlineExceeded) {
		return replyTTLExpired
	}
	return replyGeneralFailure
}
