package socks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/n0madic/go-tor-client/pkg/proxyauth"
)

// TestServeSlowLorisClosesIdleConn locks in the slow-loris defense: a client
// that connects and then sends nothing must be disconnected by the server once
// the handshake deadline fires, rather than pinning a goroutine forever.
func TestServeSlowLorisClosesIdleConn(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &Server{Factory: factoryFor(echoDialer()), testHandshakeTimeout: 100 * time.Millisecond}
	go func() { _ = srv.Serve(t.Context(), ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Send nothing. The server must close the connection after its handshake
	// deadline; the client then observes EOF. A generous client-side deadline is
	// only a safety net: if the server fails to close, Read returns a timeout
	// (not EOF) and the test fails.
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("idle connection not closed by server: read err = %v, want EOF", err)
	}
}

// TestIsTemporaryAcceptErr verifies that transient Accept errors (fd exhaustion,
// aborted connections) are classified as retryable while genuine failures are not.
func TestIsTemporaryAcceptErr(t *testing.T) {
	t.Parallel()
	for _, e := range []error{syscall.EMFILE, syscall.ENFILE, syscall.ECONNABORTED, syscall.ECONNRESET, syscall.ENOBUFS, syscall.ENOMEM} {
		if !isTemporaryAcceptErr(e) {
			t.Errorf("isTemporaryAcceptErr(%v) = false, want true", e)
		}
		if !isTemporaryAcceptErr(fmt.Errorf("socks: accept: %w", e)) {
			t.Errorf("isTemporaryAcceptErr(wrapped %v) = false, want true", e)
		}
	}
	for _, e := range []error{io.EOF, net.ErrClosed, errors.New("boom")} {
		if isTemporaryAcceptErr(e) {
			t.Errorf("isTemporaryAcceptErr(%v) = true, want false", e)
		}
	}
}

// fakeDialer records the dialed address and the auth identity it was created
// for, and returns a preconfigured upstream conn (or error) to the proxy.
type fakeDialer struct {
	mu         sync.Mutex
	dialed     string
	user, pass string
	conn       net.Conn
	err        error
}

func (d *fakeDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = address
	d.mu.Unlock()
	if d.err != nil {
		return nil, d.err
	}
	return d.conn, nil
}

func (d *fakeDialer) addr() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dialed
}

func (d *fakeDialer) auth() (string, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.user, d.pass
}

// factoryFor returns a DialerFactory that records the auth identity on d and
// hands back d as the dialer.
func factoryFor(d *fakeDialer) proxyauth.DialerFactory {
	return func(_ context.Context, user, pass string) (proxyauth.Dialer, error) {
		d.mu.Lock()
		d.user, d.pass = user, pass
		d.mu.Unlock()
		return d, nil
	}
}

// echoDialer returns a dialer whose upstream conn echoes everything written to
// it, so the relay can be exercised end to end.
func echoDialer() *fakeDialer {
	a, b := net.Pipe()
	go echoLoop(b)
	return &fakeDialer{conn: a}
}

func echoLoop(c net.Conn) {
	buf := make([]byte, 1024)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			if _, werr := c.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func writeAll(t *testing.T, c net.Conn, b []byte) {
	t.Helper()
	if _, err := c.Write(b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func readN(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return b
}

// SOCKS request builders.

func buildRequest(cmd, atyp byte, addr []byte, port uint16) []byte {
	b := []byte{version5, cmd, 0x00, atyp}
	b = append(b, addr...)
	return append(b, byte(port>>8), byte(port))
}

func connectDomain(host string, port uint16) []byte {
	addr := append([]byte{byte(len(host))}, host...)
	return buildRequest(cmdConnect, atypDomain, addr, port)
}

func connectIPv4(ip net.IP, port uint16) []byte {
	return buildRequest(cmdConnect, atypIPv4, ip.To4(), port)
}

func connectIPv6(ip net.IP, port uint16) []byte {
	return buildRequest(cmdConnect, atypIPv6, ip.To16(), port)
}

func userPassAuth(user, pass string) []byte {
	b := []byte{authVersion, byte(len(user))}
	b = append(b, user...)
	b = append(b, byte(len(pass)))
	return append(b, pass...)
}

// runHandle drives one SOCKS connection: it runs handle on one end of a pipe and
// invokes clientFn as the SOCKS client on the other, returning once handle ends.
func runHandle(t *testing.T, srv *Server, clientFn func(t *testing.T, c net.Conn)) {
	t.Helper()
	client, proxy := net.Pipe()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	done := make(chan struct{})
	go func() {
		_ = srv.handle(context.Background(), proxy)
		_ = proxy.Close()
		close(done)
	}()

	clientFn(t, client)
	_ = client.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handle did not finish in time")
	}
}

func TestHandleNoAuthConnectDomain(t *testing.T) {
	dialer := echoDialer()
	srv := &Server{Factory: factoryFor(dialer)}

	runHandle(t, srv, func(t *testing.T, c net.Conn) {
		writeAll(t, c, []byte{version5, 0x01, methodNoAuth})
		if m := readN(t, c, 2); m[0] != version5 || m[1] != methodNoAuth {
			t.Fatalf("method selection = %v, want [5 0]", m)
		}
		writeAll(t, c, connectDomain("example.com", 80))
		if reply := readN(t, c, 10); reply[0] != version5 || reply[1] != replySuccess {
			t.Fatalf("reply = %v, want success", reply)
		}
		// Bidirectional relay: the upstream echoes our bytes back.
		writeAll(t, c, []byte("ping"))
		if got := readN(t, c, 4); string(got) != "ping" {
			t.Fatalf("echo = %q, want ping", got)
		}
	})

	// Hostname is preserved verbatim — no local DNS resolution.
	if got := dialer.addr(); got != "example.com:80" {
		t.Fatalf("dialed %q, want example.com:80", got)
	}
	if u, p := dialer.auth(); u != "" || p != "" {
		t.Fatalf("auth = (%q, %q), want empty for no-auth", u, p)
	}
}

func TestHandleUserPassConnectIPv4(t *testing.T) {
	dialer := echoDialer()
	srv := &Server{Factory: factoryFor(dialer)}

	runHandle(t, srv, func(t *testing.T, c net.Conn) {
		writeAll(t, c, []byte{version5, 0x01, methodUserPass})
		if m := readN(t, c, 2); m[0] != version5 || m[1] != methodUserPass {
			t.Fatalf("method selection = %v, want [5 2]", m)
		}
		writeAll(t, c, userPassAuth("alice", "secret"))
		if st := readN(t, c, 2); st[0] != authVersion || st[1] != authStatusSuccess {
			t.Fatalf("auth status = %v, want [1 0]", st)
		}
		writeAll(t, c, connectIPv4(net.IPv4(1, 2, 3, 4), 443))
		if reply := readN(t, c, 10); reply[1] != replySuccess {
			t.Fatalf("reply code = 0x%02x, want 0x00", reply[1])
		}
	})

	if got := dialer.addr(); got != "1.2.3.4:443" {
		t.Fatalf("dialed %q, want 1.2.3.4:443", got)
	}
	if u, p := dialer.auth(); u != "alice" || p != "secret" {
		t.Fatalf("auth = (%q, %q), want (alice, secret)", u, p)
	}
}

func TestHandleConnectIPv6(t *testing.T) {
	dialer := echoDialer()
	srv := &Server{Factory: factoryFor(dialer)}

	runHandle(t, srv, func(t *testing.T, c net.Conn) {
		writeAll(t, c, []byte{version5, 0x01, methodNoAuth})
		readN(t, c, 2)
		writeAll(t, c, connectIPv6(net.ParseIP("2001:db8::1"), 8080))
		if reply := readN(t, c, 10); reply[1] != replySuccess {
			t.Fatalf("reply code = 0x%02x, want 0x00", reply[1])
		}
	})

	if got := dialer.addr(); got != "[2001:db8::1]:8080" {
		t.Fatalf("dialed %q, want [2001:db8::1]:8080", got)
	}
}

func TestHandleUnsupportedCommand(t *testing.T) {
	cases := []struct {
		name string
		cmd  byte
	}{
		{"bind", 0x02},
		{"udp_associate", 0x03},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dialer := &fakeDialer{}
			srv := &Server{Factory: factoryFor(dialer)}
			runHandle(t, srv, func(t *testing.T, c net.Conn) {
				writeAll(t, c, []byte{version5, 0x01, methodNoAuth})
				readN(t, c, 2)
				writeAll(t, c, buildRequest(tc.cmd, atypIPv4, net.IPv4(1, 2, 3, 4).To4(), 80))
				if reply := readN(t, c, 10); reply[1] != replyCommandNotSupported {
					t.Fatalf("reply code = 0x%02x, want 0x07", reply[1])
				}
			})
		})
	}
}

func TestHandleNoAcceptableMethods(t *testing.T) {
	dialer := &fakeDialer{}
	srv := &Server{Factory: factoryFor(dialer)}
	runHandle(t, srv, func(t *testing.T, c net.Conn) {
		// Offer only an unsupported method (0x80, e.g. private/GSSAPI-range).
		writeAll(t, c, []byte{version5, 0x01, 0x80})
		if m := readN(t, c, 2); m[0] != version5 || m[1] != methodNoAcceptable {
			t.Fatalf("method selection = %v, want [5 255]", m)
		}
	})
}

func TestHandleDialFailure(t *testing.T) {
	dialer := &fakeDialer{err: errors.New("upstream unreachable")}
	srv := &Server{Factory: factoryFor(dialer)}
	runHandle(t, srv, func(t *testing.T, c net.Conn) {
		writeAll(t, c, []byte{version5, 0x01, methodNoAuth})
		readN(t, c, 2)
		writeAll(t, c, connectDomain("example.com", 80))
		if reply := readN(t, c, 10); reply[1] != replyGeneralFailure {
			t.Fatalf("reply code = 0x%02x, want 0x01", reply[1])
		}
	})
}

// TestServeConnectEcho exercises Serve over a real loopback listener end to end.
func TestServeConnectEcho(t *testing.T) {
	dialer := echoDialer()
	srv := &Server{Factory: factoryFor(dialer)}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ctx, ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	writeAll(t, conn, []byte{version5, 0x01, methodNoAuth})
	readN(t, conn, 2)
	writeAll(t, conn, connectDomain("example.com", 80))
	if reply := readN(t, conn, 10); reply[1] != replySuccess {
		t.Fatalf("reply code = 0x%02x, want 0x00", reply[1])
	}
	writeAll(t, conn, []byte("hello"))
	if got := readN(t, conn, 5); string(got) != "hello" {
		t.Fatalf("echo = %q, want hello", got)
	}
	_ = conn.Close()

	cancel()
	if err := <-serveDone; err != nil {
		t.Fatalf("Serve returned %v, want nil after cancel", err)
	}
}
