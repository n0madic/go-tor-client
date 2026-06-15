package directory

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

// TestBootstrapLive performs a real cold-start bootstrap against the live Tor
// directory authorities and validates consensus signatures end-to-end. It is
// skipped under -short.
func TestBootstrapLive(t *testing.T) {
	if testing.Short() {
		t.Skip("requires network access to Tor directory authorities")
	}
	c := NewClient(nil, slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug})))

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	cons, err := c.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if len(cons.Routers) < 1000 {
		t.Fatalf("only %d routers, expected thousands", len(cons.Routers))
	}
	now := time.Now()
	if now.Before(cons.ValidAfter) || now.After(cons.ValidUntil) {
		t.Fatalf("consensus not live: valid-after=%s valid-until=%s now=%s", cons.ValidAfter, cons.ValidUntil, now)
	}
	t.Logf("consensus: %d routers, valid %s..%s", len(cons.Routers), cons.ValidAfter, cons.ValidUntil)

	// Fetch microdescriptors for the first handful of routers and confirm the
	// returned digests match the requested consensus "m" hashes.
	var hashes []string
	for i := 0; i < len(cons.Routers) && len(hashes) < 20; i++ {
		if cons.Routers[i].MicrodescHash != "" {
			hashes = append(hashes, cons.Routers[i].MicrodescHash)
		}
	}
	mds, err := c.FetchMicrodescriptors(ctx, hashes)
	if err != nil {
		t.Fatalf("FetchMicrodescriptors: %v", err)
	}
	matched := 0
	for _, h := range hashes {
		md, ok := mds[h]
		if !ok {
			continue
		}
		matched++
		if len(md.NtorOnionKey) != 32 {
			t.Errorf("microdesc %s: ntor key len %d", h, len(md.NtorOnionKey))
		}
	}
	if matched < len(hashes)/2 {
		t.Fatalf("only matched %d/%d microdescriptors by digest", matched, len(hashes))
	}
	t.Logf("matched %d/%d microdescriptors by SHA-256 digest", matched, len(hashes))
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", p)
	return len(p), nil
}
