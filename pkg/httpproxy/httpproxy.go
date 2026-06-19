// Package httpproxy implements a minimal HTTP forward proxy (RFC 7230) that is
// dialer-agnostic: the caller supplies a Dialer, so every proxied connection —
// both CONNECT tunnels and plain forwarded HTTP requests — is dialed through
// that transport. The package knows nothing about Tor.
//
// CONNECT requests (used by clients for HTTPS, and for .onion over TLS with a
// proxy-aware client) are tunneled as raw byte streams. Plain HTTP requests in
// absolute-form ("GET http://host/path") are forwarded to the origin and the
// response is streamed back. Target hostnames (including .onion) are passed to
// the dialer verbatim — never resolved locally — so DNS happens at the far end
// of the tunnel. No X-Forwarded-For or Via header is added, so the proxy does
// not disclose the client.
//
// Like the SOCKS server, the proxy credentials are an isolation token, not a
// validated secret: the Proxy-Authorization username and password are passed to
// Factory so traffic can be isolated on a dedicated Dialer per identity
// (mirroring tor's IsolateSOCKSAuth). Connections without (or with malformed)
// credentials map to the empty identity; requests are never rejected for
// missing or wrong credentials.
package httpproxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/n0madic/go-tor-client/internal/relay"
	"github.com/n0madic/go-tor-client/pkg/proxyauth"
)

const (
	// readHeaderTimeout bounds how long a client may take to send its request
	// headers; the slow-loris defense for the HTTP proxy.
	readHeaderTimeout = 30 * time.Second
	// idleTimeout bounds how long an idle keep-alive connection is kept open.
	idleTimeout = 60 * time.Second
	// maxHeaderBytes caps request header size (matches net/http's default).
	maxHeaderBytes = 1 << 20
	// maxConcurrentConns caps simultaneous accepted connections to prevent
	// goroutine/fd exhaustion from a connection flood.
	maxConcurrentConns = 1024
)

// limitListener bounds the number of simultaneously accepted connections. Accept
// blocks once the limit is reached and resumes as connections close, providing
// backpressure without a third-party dependency.
type limitListener struct {
	net.Listener
	sem chan struct{}
}

func (l *limitListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: conn, release: func() { <-l.sem }}, nil
}

// limitConn releases its listener slot exactly once when closed.
type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// Server is an HTTP forward proxy. Factory is required and returns the upstream
// dialer for each connection's Proxy-Authorization identity (see
// proxyauth.DialerFactory); Logger is optional and defaults to a discard logger.
type Server struct {
	Factory proxyauth.DialerFactory
	Logger  *slog.Logger

	// transports caches one forwarding transport per isolation identity, each
	// dialing through that identity's Dialer. CONNECT tunnels resolve their
	// dialer per request and so do not use this cache.
	mu         sync.Mutex
	transports map[string]*http.Transport
}

func (s *Server) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// transportFor returns the forwarding transport for the given identity, building
// it (over a freshly resolved per-identity Dialer) on first use. The Factory call
// runs WITHOUT the lock held, so first use of a new identity — which may bootstrap
// a fresh upstream client — does not serialize transport lookups for other
// identities. Factory deduplicates concurrent bootstraps of the same identity, so
// at worst two cheap transports are built and the loser is discarded.
func (s *Server) transportFor(ctx context.Context, user, pass string) (*http.Transport, error) {
	key := proxyauth.IsoKey(user, pass)
	s.mu.Lock()
	if t, ok := s.transports[key]; ok {
		s.mu.Unlock()
		return t, nil
	}
	s.mu.Unlock()

	dialer, err := s.Factory(ctx, user, pass)
	if err != nil {
		return nil, err
	}
	t := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		DisableKeepAlives:     true,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.transports[key]; ok {
		return existing, nil // lost the race; reuse the winner
	}
	if s.transports == nil {
		s.transports = make(map[string]*http.Transport)
	}
	s.transports[key] = t
	return t, nil
}

// Serve handles HTTP proxy connections on ln until ctx is cancelled (then it
// gracefully shuts down and returns nil) or Serve fails (then it returns the
// error).
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:     s,
		BaseContext: func(net.Listener) context.Context { return ctx },
		// ReadHeaderTimeout is the slow-loris defense: it bounds how long a client
		// may take to send request headers. ReadTimeout/WriteTimeout are
		// deliberately NOT set — they would impose an absolute deadline that breaks
		// long-lived CONNECT tunnels and large forwarded responses.
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	// Bound concurrent connections to prevent goroutine/fd exhaustion from a flood.
	ln = &limitListener{Listener: ln, sem: make(chan struct{}, maxConcurrentConns)}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// ServeHTTP extracts the Proxy-Authorization isolation identity, then dispatches
// CONNECT to the tunnel handler and everything else to the forward handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Credentials are an isolation token, not validated: a missing or malformed
	// Proxy-Authorization header maps to the empty (no-auth) identity.
	user, pass, _ := parseBasicAuth(r.Header.Get("Proxy-Authorization"))
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r, user, pass)
		return
	}
	s.handleForward(w, r, user, pass)
}

// handleConnect tunnels a CONNECT request: dial the target through the identity's
// Dialer, hijack the client connection, acknowledge with 200, and relay raw
// bytes.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request, user, pass string) {
	target := r.Host
	if target == "" {
		target = r.URL.Host
	}

	dialer, err := s.Factory(r.Context(), user, pass)
	if err != nil {
		s.logger().Debug("httpproxy: dialer factory failed", "err", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Dial before hijacking so a failure can still use the ResponseWriter.
	up, err := dialer.DialContext(r.Context(), "tcp", target)
	if err != nil {
		s.logger().Debug("httpproxy: CONNECT dial failed", "target", target, "err", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer up.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		s.logger().Debug("httpproxy: hijack failed", "err", err)
		return
	}
	defer clientConn.Close()
	// Clear any read deadline inherited from the header-read phase so the
	// long-lived tunnel is not torn down by a stale deadline.
	_ = clientConn.SetDeadline(time.Time{})

	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	relay.Bidirectional(clientConn, up)
}

// handleForward forwards a plain absolute-URI HTTP request to its origin through
// the identity's transport and streams the response back.
func (s *Server) handleForward(w http.ResponseWriter, r *http.Request, user, pass string) {
	if !r.URL.IsAbs() || r.URL.Host == "" {
		http.Error(w, "this is a forward proxy; requests must use an absolute URL", http.StatusBadRequest)
		return
	}

	tr, err := s.transportFor(r.Context(), user, pass)
	if err != nil {
		s.logger().Debug("httpproxy: dialer factory failed", "err", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	outReq := r.Clone(r.Context())
	outReq.RequestURI = "" // RequestURI must be unset on outbound client requests.
	// removeHopByHop also strips Proxy-Authorization, so the isolation token is
	// never forwarded to the origin.
	removeHopByHop(outReq.Header)

	resp, err := tr.RoundTrip(outReq)
	if err != nil {
		s.logger().Debug("httpproxy: forward failed", "url", r.URL.Redacted(), "err", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeHopByHop(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// hopByHopHeaders are connection-specific headers stripped from forwarded
// requests and responses (RFC 7230 §6.1).
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// removeHopByHop deletes hop-by-hop headers, including any named in a Connection
// header, so they are not forwarded end to end.
func removeHopByHop(h http.Header) {
	for _, field := range h.Values("Connection") {
		for name := range strings.SplitSeq(field, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// parseBasicAuth extracts the username and password from an HTTP Basic
// "Proxy-Authorization" header value of the form "Basic base64(user:pass)". ok
// is false if the value is empty or not well-formed Basic credentials, in which
// case the caller treats the connection as the empty (no-auth) identity rather
// than rejecting it — the credentials are an isolation token, not validated.
func parseBasicAuth(header string) (user, pass string, ok bool) {
	const prefix = "Basic "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(header[len(prefix):])
	if err != nil {
		return "", "", false
	}
	user, pass, ok = strings.Cut(string(decoded), ":")
	if !ok {
		return "", "", false
	}
	return user, pass, true
}
