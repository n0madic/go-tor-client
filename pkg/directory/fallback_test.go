package directory

import (
	"context"
	"errors"
	"testing"
)

// TestFetchFromAnyFailsClosed verifies that once a tunnel is configured, a tunnel
// failure is returned as an error by default instead of silently falling back to
// direct HTTP (which would leak the request from the local IP).
func TestFetchFromAnyFailsClosed(t *testing.T) {
	t.Parallel()
	c := NewClient(nil, nil)
	c.UseTunnel(tunnelFunc(func(context.Context, string) ([]byte, error) {
		return nil, errors.New("tunnel down")
	}))

	if _, err := c.fetchFromAny(context.Background(), pathConsensusMicrodesc); err == nil {
		t.Fatal("expected fail-closed error when tunnel fails and fallback disabled")
	}
}

// TestFetchFromAnyTunnelSuccess verifies the happy path returns the tunnel body
// without touching the network.
func TestFetchFromAnyTunnelSuccess(t *testing.T) {
	t.Parallel()
	c := NewClient(nil, nil)
	c.UseTunnel(tunnelFunc(func(context.Context, string) ([]byte, error) {
		return []byte("ok"), nil
	}))

	body, err := c.fetchFromAny(context.Background(), pathConsensusMicrodesc)
	if err != nil {
		t.Fatalf("tunnel success: unexpected err %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}
}
