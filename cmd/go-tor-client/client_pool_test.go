package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	tor "github.com/n0madic/go-tor-client"
)

// newTestPool builds a clientPool whose bootstrap is stubbed, so the cap and
// dedup logic can be exercised without touching the network. build is invoked in
// place of tor.NewClient.
func newTestPool(build func(context.Context, *tor.Config) (*tor.Client, error)) *clientPool {
	p := newClientPool(nil, &tor.Client{})
	p.newClient = build
	return p
}

// TestClientPoolCap verifies the pool refuses new identities past the cap while
// still serving already-cached ones.
func TestClientPoolCap(t *testing.T) {
	t.Parallel()
	p := newTestPool(func(context.Context, *tor.Config) (*tor.Client, error) {
		return &tor.Client{}, nil
	})

	ctx := context.Background()
	// The base "" identity already occupies one slot, so maxIsolatedClients-1
	// fresh identities fill the pool.
	for i := range maxIsolatedClients - 1 {
		if _, err := p.clientFor(ctx, fmt.Sprintf("k%d", i)); err != nil {
			t.Fatalf("clientFor k%d: %v", i, err)
		}
	}
	if _, err := p.clientFor(ctx, "overflow"); err == nil {
		t.Fatal("expected capacity rejection for a new identity past the cap")
	}
	// A cached identity must still resolve even when the pool is full.
	if _, err := p.clientFor(ctx, "k0"); err != nil {
		t.Fatalf("cached identity rejected while full: %v", err)
	}
}

// TestClientPoolDedup verifies concurrent requests for one new identity trigger a
// single bootstrap and all receive the same client.
func TestClientPoolDedup(t *testing.T) {
	t.Parallel()
	var builds int32
	want := &tor.Client{}
	start := make(chan struct{})
	p := newTestPool(func(context.Context, *tor.Config) (*tor.Client, error) {
		atomic.AddInt32(&builds, 1)
		return want, nil
	})

	const n = 16
	var wg sync.WaitGroup
	got := make([]*tor.Client, n)
	for i := range n {
		wg.Go(func() {
			<-start // converge before racing on the same key
			c, err := p.clientFor(context.Background(), "same")
			if err != nil {
				t.Errorf("clientFor: %v", err)
				return
			}
			got[i] = c
		})
	}
	close(start)
	wg.Wait()

	if builds != 1 {
		t.Fatalf("bootstraps = %d, want 1 (dedup)", builds)
	}
	for i, c := range got {
		if c != want {
			t.Fatalf("goroutine %d got %p, want shared %p", i, c, want)
		}
	}
}
