package httpproxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/n0madic/go-tor-client/pkg/proxyauth"
)

// staticFactory returns a DialerFactory that always yields d, ignoring the auth
// identity — for tests that don't exercise per-identity isolation.
func staticFactory(d proxyauth.Dialer) proxyauth.DialerFactory {
	return func(context.Context, string, string) (proxyauth.Dialer, error) { return d, nil }
}

// fakeDialer records every address it is asked to dial and redirects the
// connection to a fixed target, so tests can assert that hostnames reach the
// dialer verbatim (no local DNS) while still connecting to a loopback origin.
type fakeDialer struct {
	target string

	mu     sync.Mutex
	dialed []string
}

func (d *fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, address)
	d.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, d.target)
}

func (d *fakeDialer) addrs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dialed...)
}

// startProxy runs s on a loopback listener and returns its address plus a
// cleanup function.
func startProxy(t *testing.T, s *Server) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = s.Serve(ctx, ln)
		close(done)
	}()
	return ln.Addr().String(), func() {
		cancel()
		_ = ln.Close()
		<-done
	}
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

func TestForwardGET(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "host=%s path=%s", r.Host, r.URL.Path)
	}))
	defer origin.Close()

	dialer := &fakeDialer{target: origin.Listener.Addr().String()}
	proxyAddr, stop := startProxy(t, &Server{Factory: staticFactory(dialer)})
	defer stop()

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get("http://example.com/hello")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "path=/hello") {
		t.Fatalf("body = %q, want it to contain path=/hello", body)
	}
	// Hostname must reach the dialer verbatim — never resolved locally.
	if got := dialer.addrs(); !slices.Contains(got, "example.com:80") {
		t.Fatalf("dialer was asked for %v, want example.com:80 (verbatim, no local resolve)", got)
	}
}

func TestForwardPOST(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Write(b)
	}))
	defer origin.Close()

	dialer := &fakeDialer{target: origin.Listener.Addr().String()}
	proxyAddr, stop := startProxy(t, &Server{Factory: staticFactory(dialer)})
	defer stop()

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Post("http://example.com/", "text/plain", strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("POST via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "payload" {
		t.Fatalf("echoed body = %q, want payload", body)
	}
}

func TestConnectTunnel(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go echoLoop(c)
		}
	}()

	dialer := &fakeDialer{target: echoLn.Addr().String()}
	proxyAddr, stop := startProxy(t, &Server{Factory: staticFactory(dialer)})
	defer stop()

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := fmt.Fprint(conn, "CONNECT secret.onion:443 HTTP/1.1\r\nHost: secret.onion:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	// The tunnel is now raw: echo through it. Read from br (it may hold buffered
	// tunnel bytes past the response headers).
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write tunnel: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read tunnel echo: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("tunnel echo = %q, want ping", got)
	}
	if addrs := dialer.addrs(); !slices.Contains(addrs, "secret.onion:443") {
		t.Fatalf("dialer was asked for %v, want secret.onion:443 (verbatim)", addrs)
	}
}

func TestForwardRejectsRelativeURL(t *testing.T) {
	dialer := &fakeDialer{target: "127.0.0.1:1"}
	proxyAddr, stop := startProxy(t, &Server{Factory: staticFactory(dialer)})
	defer stop()

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Origin-form (relative) request — invalid for a forward proxy.
	if _, err := fmt.Fprint(conn, "GET /relative HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for relative URL", resp.StatusCode)
	}
}

func TestRemoveHopByHop(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "X-Custom, Keep-Alive")
	h.Set("X-Custom", "secret")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("Proxy-Authorization", "Basic abc")
	h.Set("X-Keep", "yes")

	removeHopByHop(h)

	for _, gone := range []string{"Connection", "X-Custom", "Keep-Alive", "Proxy-Authorization"} {
		if h.Get(gone) != "" {
			t.Errorf("%s should have been removed, got %q", gone, h.Get(gone))
		}
	}
	if h.Get("X-Keep") != "yes" {
		t.Errorf("X-Keep was wrongly removed")
	}
}

// recordingFactory records the isolation identity of every Factory call and
// hands back a fresh fakeDialer pointed at target.
type recordingFactory struct {
	target string

	mu   sync.Mutex
	keys []string
}

func (f *recordingFactory) factory(_ context.Context, user, pass string) (proxyauth.Dialer, error) {
	f.mu.Lock()
	f.keys = append(f.keys, proxyauth.IsoKey(user, pass))
	f.mu.Unlock()
	return &fakeDialer{target: f.target}, nil
}

func (f *recordingFactory) identities() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.keys...)
}

// basicHeader formats a "Basic" Proxy-Authorization value for userinfo, or "" to
// send no header at all.
func basicHeader(userinfo string) string {
	if userinfo == "" {
		return ""
	}
	return "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(userinfo)) + "\r\n"
}

// TestForwardIsolatesByProxyAuth checks that the forward path routes each
// Proxy-Authorization identity to its own dialer, reuses a cached transport for
// a repeated identity, and never leaks the credentials to the origin.
func TestForwardIsolatesByProxyAuth(t *testing.T) {
	var mu sync.Mutex
	var leaked []string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.Header.Get("Proxy-Authorization"); v != "" {
			mu.Lock()
			leaked = append(leaked, v)
			mu.Unlock()
		}
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()

	rf := &recordingFactory{target: origin.Listener.Addr().String()}
	proxyAddr, stop := startProxy(t, &Server{Factory: rf.factory})
	defer stop()

	forwardAs := func(t *testing.T, userinfo string) {
		t.Helper()
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		req := "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n" + basicHeader(userinfo) + "Connection: close\r\n\r\n"
		if _, err := io.WriteString(conn, req); err != nil {
			t.Fatalf("write request: %v", err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
	}

	forwardAs(t, "alice:secret")
	forwardAs(t, "alice:secret") // same identity → cached transport, no new Factory call
	forwardAs(t, "bob:hunter2")  // distinct identity
	forwardAs(t, "")             // no-auth identity

	want := []string{
		proxyauth.IsoKey("alice", "secret"),
		proxyauth.IsoKey("bob", "hunter2"),
		proxyauth.IsoKey("", ""),
	}
	if got := rf.identities(); !slices.Equal(got, want) {
		t.Fatalf("forward Factory identities = %v, want %v (same creds must reuse a cached transport)", got, want)
	}
	if len(leaked) != 0 {
		t.Fatalf("origin received Proxy-Authorization %v; the isolation token must not leak", leaked)
	}
}

// TestConnectIsolatesByProxyAuth checks that the CONNECT path routes each
// Proxy-Authorization identity to its own dialer.
func TestConnectIsolatesByProxyAuth(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go echoLoop(c)
		}
	}()

	rf := &recordingFactory{target: echoLn.Addr().String()}
	proxyAddr, stop := startProxy(t, &Server{Factory: rf.factory})
	defer stop()

	connectAs := func(t *testing.T, userinfo string) {
		t.Helper()
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		req := "CONNECT secret.onion:443 HTTP/1.1\r\nHost: secret.onion:443\r\n" + basicHeader(userinfo) + "\r\n"
		if _, err := io.WriteString(conn, req); err != nil {
			t.Fatalf("write CONNECT: %v", err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
		if err != nil {
			t.Fatalf("read CONNECT response: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
		}
	}

	connectAs(t, "alice:secret")
	connectAs(t, "bob:hunter2")
	connectAs(t, "")

	want := []string{
		proxyauth.IsoKey("alice", "secret"),
		proxyauth.IsoKey("bob", "hunter2"),
		proxyauth.IsoKey("", ""),
	}
	if got := rf.identities(); !slices.Equal(got, want) {
		t.Fatalf("CONNECT Factory identities = %v, want %v", got, want)
	}
}

func TestParseBasicAuth(t *testing.T) {
	enc := func(s string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(s)) }
	cases := []struct {
		name       string
		header     string
		user, pass string
		ok         bool
	}{
		{"empty", "", "", "", false},
		{"valid", enc("alice:secret"), "alice", "secret", true},
		{"empty pass", enc("alice:"), "alice", "", true},
		{"empty user", enc(":secret"), "", "secret", true},
		{"colon in pass", enc("alice:a:b:c"), "alice", "a:b:c", true},
		{"no colon", enc("aliceonly"), "", "", false},
		{"case-insensitive scheme", "basic " + base64.StdEncoding.EncodeToString([]byte("u:p")), "u", "p", true},
		{"wrong scheme", "Bearer xyz", "", "", false},
		{"bad base64", "Basic !!!not-base64!!!", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user, pass, ok := parseBasicAuth(tc.header)
			if user != tc.user || pass != tc.pass || ok != tc.ok {
				t.Fatalf("parseBasicAuth(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tc.header, user, pass, ok, tc.user, tc.pass, tc.ok)
			}
		})
	}
}
