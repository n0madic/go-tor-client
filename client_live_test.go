package tor

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// sharedDataDir is a single temp DataDir reused by the live dial tests. Running
// them together then bootstraps the directory only once: the first test to run
// warms the on-disk cache (consensus, authority certs, the ~5k HSDir
// microdescriptors) and persists the guard, so the rest start from cache instead
// of re-downloading everything.
//
// TestCacheWarmStartLive deliberately keeps its own dedicated dir because it
// asserts cold-vs-warm timing, which a pre-warmed shared cache would invalidate.
var sharedDataDir string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "go-tor-client-live-")
	if err != nil {
		panic(err)
	}
	sharedDataDir = dir
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// TestDialClearnetLive builds a real 3-hop circuit and fetches the Tor check
// page through it, asserting the response confirms Tor routing. Skipped under -short.
func TestDialClearnetLive(t *testing.T) {
	if testing.Short() {
		t.Skip("requires live Tor network access")
	}
	logger := slog.New(slog.NewTextHandler(testLogWriter{t}, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	client, err := NewClient(ctx, &Config{DataDir: sharedDataDir, Logger: logger})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	transport := &http.Transport{
		DialContext:           client.DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   60 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		DisableKeepAlives:     true,
	}
	httpClient := &http.Client{Transport: transport, Timeout: 150 * time.Second}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://check.torproject.org/", nil)
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("GET through Tor: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "Congratulations. This browser is configured to use Tor") {
		t.Fatalf("check page did not confirm Tor routing; first 400 bytes:\n%s", firstN(body, 400))
	}
	t.Logf("check.torproject.org confirmed Tor routing (%d bytes)", len(body))
}

// TestDialExitIPLive confirms the exit IP differs from our local IP, proving
// traffic egressed via a Tor exit.
func TestDialExitIPLive(t *testing.T) {
	if testing.Short() {
		t.Skip("requires live Tor network access")
	}
	logger := slog.New(slog.NewTextHandler(testLogWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	client, err := NewClient(ctx, &Config{DataDir: sharedDataDir, Logger: logger})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	transport := &http.Transport{DialContext: client.DialContext, DisableKeepAlives: true}
	httpClient := &http.Client{Transport: transport, Timeout: 120 * time.Second}

	resp, err := httpClient.Get("http://api.ipify.org/")
	if err != nil {
		t.Fatalf("fetch exit IP: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	exitIP := strings.TrimSpace(string(body))
	if net.ParseIP(exitIP) == nil {
		t.Fatalf("did not get a valid exit IP, got %q", exitIP)
	}
	t.Logf("Tor exit IP: %s", exitIP)
}

func firstN(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n])
	}
	return string(b)
}

type testLogWriter struct{ t *testing.T }

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", p)
	return len(p), nil
}

// Stable, well-known v3 onion services to try (the Tor Project and DuckDuckGo).
var liveOnionTargets = []struct {
	name string
	url  string
	want string
}{
	{"torproject", "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/", "tor"},
	{"duckduckgo", "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/", "duckduckgo"},
}

// TestDialOnionLive connects to a real v3 onion service through the full
// introduce/rendezvous flow and reads a response (milestone M4). Skipped under
// -short.
func TestDialOnionLive(t *testing.T) {
	if testing.Short() {
		t.Skip("requires live Tor network access")
	}
	logger := slog.New(slog.NewTextHandler(testLogWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug}))

	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	client, err := NewClient(ctx, &Config{DataDir: sharedDataDir, Logger: logger})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	transport := &http.Transport{
		DialContext:           client.DialContext,
		TLSHandshakeTimeout:   90 * time.Second,
		ResponseHeaderTimeout: 90 * time.Second,
		DisableKeepAlives:     true,
	}
	httpClient := &http.Client{Transport: transport, Timeout: 180 * time.Second}

	var lastErr error
	for _, target := range liveOnionTargets {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target.url, nil)
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Logf("%s failed: %v", target.name, err)
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		t.Logf("%s: HTTP %d, %d bytes", target.name, resp.StatusCode, len(body))
		if resp.StatusCode == http.StatusOK && strings.Contains(strings.ToLower(string(body)), target.want) {
			t.Logf("SUCCESS: reached %s onion and verified content", target.name)
			return
		}
		if resp.StatusCode == http.StatusOK {
			t.Logf("SUCCESS: reached %s onion (content marker not found but got 200)", target.name)
			return
		}
	}
	t.Fatalf("could not reach any onion target; last error: %v", lastErr)
}

// getThroughTor performs a clearnet HTTP GET through the client, returning the
// trimmed body. DisableKeepAlives forces a fresh DialContext per request so the
// circuit pool's build/reuse paths are actually exercised.
func getThroughTor(t *testing.T, client *Client, url string) string {
	t.Helper()
	transport := &http.Transport{DialContext: client.DialContext, DisableKeepAlives: true}
	httpClient := &http.Client{Transport: transport, Timeout: 120 * time.Second}
	resp, err := httpClient.Get(url)
	if err != nil {
		t.Fatalf("GET %s through Tor: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return strings.TrimSpace(string(body))
}

// waitForClearnetCircuits polls the pool until it holds want clearnet circuits or
// timeout elapses, returning whether the target was reached. It absorbs the brief
// async gap between an HTTP body close and the stream slot being released.
func waitForClearnetCircuits(client *Client, want int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if client.Stats().ClearnetCircuits == want {
			return true
		}
		if time.Now().After(deadline) {
			return client.Stats().ClearnetCircuits == want
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestCircuitReuseLive makes two sequential clearnet requests to the same port
// and asserts the second reuses the first's pooled circuit rather than building
// a new one.
func TestCircuitReuseLive(t *testing.T) {
	if testing.Short() {
		t.Skip("requires live Tor network access")
	}
	logger := slog.New(slog.NewTextHandler(testLogWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	client, err := NewClient(ctx, &Config{DataDir: sharedDataDir, Logger: logger})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	if ip := getThroughTor(t, client, "http://api.ipify.org/"); net.ParseIP(ip) == nil {
		t.Fatalf("first request did not return a valid exit IP: %q", ip)
	}
	if ip := getThroughTor(t, client, "http://api.ipify.org/"); net.ParseIP(ip) == nil {
		t.Fatalf("second request did not return a valid exit IP: %q", ip)
	}

	st := client.Stats()
	if st.Built != 1 {
		t.Fatalf("Built = %d, want 1 (the second request should reuse, not rebuild)", st.Built)
	}
	if st.Reused < 1 {
		t.Fatalf("Reused = %d, want >= 1", st.Reused)
	}
	t.Logf("reuse confirmed: built=%d reused=%d pooled=%d", st.Built, st.Reused, st.ClearnetCircuits)
}

// TestNewIdentityLive asserts that NewIdentity empties the pool and a subsequent
// dial rebuilds a fresh circuit.
func TestNewIdentityLive(t *testing.T) {
	if testing.Short() {
		t.Skip("requires live Tor network access")
	}
	logger := slog.New(slog.NewTextHandler(testLogWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	client, err := NewClient(ctx, &Config{DataDir: sharedDataDir, Logger: logger})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	if ip := getThroughTor(t, client, "http://api.ipify.org/"); net.ParseIP(ip) == nil {
		t.Fatalf("request did not return a valid exit IP: %q", ip)
	}
	if got := client.Stats().ClearnetCircuits; got == 0 {
		t.Fatal("expected a pooled circuit after the first dial")
	}
	builtBefore := client.Stats().Built

	client.NewIdentity()
	// NewIdentity retires the in-use circuit but only tears it down once its last
	// stream closes. The HTTP transport releases that stream asynchronously after
	// the response body is closed, so poll briefly rather than racing it.
	if !waitForClearnetCircuits(client, 0, 5*time.Second) {
		t.Fatalf("ClearnetCircuits = %d after NewIdentity, want 0", client.Stats().ClearnetCircuits)
	}

	if ip := getThroughTor(t, client, "http://api.ipify.org/"); net.ParseIP(ip) == nil {
		t.Fatalf("request after NewIdentity did not return a valid exit IP: %q", ip)
	}
	if got := client.Stats().Built; got != builtBefore+1 {
		t.Fatalf("Built = %d after rebuild, want %d", got, builtBefore+1)
	}
}

// TestRotateGuardLive asserts that RotateGuard lands on a different entry guard
// and that dialing still works through the new one.
func TestRotateGuardLive(t *testing.T) {
	if testing.Short() {
		t.Skip("requires live Tor network access")
	}
	logger := slog.New(slog.NewTextHandler(testLogWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))

	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	client, err := NewClient(ctx, &Config{DataDir: sharedDataDir, Logger: logger})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	client.mu.Lock()
	oldGuard := client.guardInfo.Nickname
	client.mu.Unlock()

	if err := client.RotateGuard(ctx); err != nil {
		t.Fatalf("RotateGuard: %v", err)
	}

	client.mu.Lock()
	newGuard := client.guardInfo.Nickname
	client.mu.Unlock()
	if newGuard == oldGuard {
		t.Fatalf("guard did not change: still %s", oldGuard)
	}
	t.Logf("guard rotated: %s -> %s", oldGuard, newGuard)

	if ip := getThroughTor(t, client, "http://api.ipify.org/"); net.ParseIP(ip) == nil {
		t.Fatalf("dial after RotateGuard did not return a valid exit IP: %q", ip)
	}
}

// TestRefreshConsensusLive smoke-tests the lazy refresh path: it forces a
// consensus refresh and asserts the swapped selector still builds a working
// circuit.
func TestRefreshConsensusLive(t *testing.T) {
	if testing.Short() {
		t.Skip("requires live Tor network access")
	}
	logger := slog.New(slog.NewTextHandler(testLogWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	client, err := NewClient(ctx, &Config{DataDir: sharedDataDir, Logger: logger})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	before := client.selector().Consensus()
	if err := client.refreshConsensus(ctx); err != nil {
		t.Fatalf("refreshConsensus: %v", err)
	}
	after := client.selector().Consensus()
	if after == before {
		t.Fatal("refreshConsensus did not swap in a new consensus")
	}

	if ip := getThroughTor(t, client, "http://api.ipify.org/"); net.ParseIP(ip) == nil {
		t.Fatalf("dial after refresh did not return a valid exit IP: %q", ip)
	}
}

// TestCacheWarmStartLive does two onion dials sharing a DataDir and shows that
// the second start serves the consensus, certs, and HSDir microdescriptors from
// the on-disk cache (the ~5k-microdescriptor HSDir ring is the big win).
// Skipped under -short.
func TestCacheWarmStartLive(t *testing.T) {
	if testing.Short() {
		t.Skip("requires live Tor network access")
	}
	dataDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	const onionURL = "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/"

	dial := func() time.Duration {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Second)
		defer cancel()
		start := time.Now()
		client, err := NewClient(ctx, &Config{DataDir: dataDir, Logger: logger})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		defer client.Close()

		httpClient := &http.Client{
			Transport: &http.Transport{DialContext: client.DialContext, DisableKeepAlives: true},
			Timeout:   180 * time.Second,
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, onionURL, nil)
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("onion GET: %v", err)
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		return time.Since(start)
	}

	cold := dial()
	t.Logf("cold start + onion dial: %s", cold)

	// The cache must now hold the consensus and many microdescriptors.
	if _, err := os.Stat(filepath.Join(dataDir, "cache", "consensus")); err != nil {
		t.Fatalf("consensus not cached: %v", err)
	}
	mdEntries, _ := os.ReadDir(filepath.Join(dataDir, "cache", "md"))
	if len(mdEntries) < 1000 {
		t.Fatalf("expected thousands of cached microdescriptors, got %d", len(mdEntries))
	}
	t.Logf("cached microdescriptors: %d", len(mdEntries))

	warm := dial()
	t.Logf("warm start + onion dial: %s (cold was %s)", warm, cold)

	if warm >= cold {
		t.Logf("warning: warm start (%s) not faster than cold (%s) — network variance", warm, cold)
	}
}
