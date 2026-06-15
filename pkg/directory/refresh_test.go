package directory

import (
	"context"
	"testing"
)

// tunnelFunc adapts a function to the Tunnel interface.
type tunnelFunc func(ctx context.Context, path string) ([]byte, error)

func (f tunnelFunc) DirGet(ctx context.Context, path string) ([]byte, error) { return f(ctx, path) }

// TestRefreshBypassesCacheAndFetches verifies that Refresh always fetches a fresh
// consensus through the fetch path (preferring the tunnel) and never returns a
// cached one — unlike Bootstrap, which short-circuits on a valid cache.
func TestRefreshBypassesCacheAndFetches(t *testing.T) {
	t.Parallel()

	var gotPath string
	calls := 0
	c := NewClient(nil, nil)
	// A present cache entry must NOT be consulted by Refresh.
	cache := newMapCache()
	cache.Put("consensus", []byte("stale-but-present"))
	c.UseCache(cache)
	// Returning a non-nil body keeps fetchFromAny from falling back to direct
	// HTTP, so the test never touches the network.
	c.UseTunnel(tunnelFunc(func(_ context.Context, path string) ([]byte, error) {
		calls++
		gotPath = path
		return []byte("garbage-consensus"), nil
	}))

	_, err := c.Refresh(context.Background())
	if calls != 1 {
		t.Fatalf("Refresh should fetch via the tunnel exactly once, got %d calls", calls)
	}
	if gotPath != pathConsensusMicrodesc {
		t.Fatalf("Refresh fetched %q, want %q", gotPath, pathConsensusMicrodesc)
	}
	if err == nil {
		t.Fatal("expected a verification error parsing the garbage consensus")
	}
}
