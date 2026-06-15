package main

import (
	"context"
	"fmt"
	"sync"

	tor "github.com/n0madic/go-tor-client"
	"github.com/n0madic/go-tor-client/pkg/proxyauth"
)

// clientPool lazily creates one *tor.Client per distinct proxy auth identity, so
// each credential pair gets its own guard channel and circuit pool —
// circuit-isolated identities, mirroring tor's IsolateSOCKSAuth. It backs both
// the SOCKS and HTTP proxy subcommands. The no-auth identity (empty user/pass)
// maps to the base client created at startup.
//
// Bootstrapping a per-identity client re-verifies the consensus (cheap with a
// warm -datadir cache) and connects its own guard; the cost is amortized over
// every stream that identity carries.
type clientPool struct {
	cfg *tor.Config

	mu      sync.Mutex
	clients map[string]*tor.Client
}

func newClientPool(cfg *tor.Config, base *tor.Client) *clientPool {
	return &clientPool{
		cfg:     cfg,
		clients: map[string]*tor.Client{"": base},
	}
}

// dialer satisfies proxyauth.DialerFactory: it returns the *tor.Client for the
// connection's auth identity, creating it on first use. It is wired directly as
// the Factory of both the SOCKS and HTTP proxy servers.
func (p *clientPool) dialer(ctx context.Context, user, pass string) (proxyauth.Dialer, error) {
	return p.clientFor(ctx, proxyauth.IsoKey(user, pass))
}

// clientFor returns the cached client for key, bootstrapping a fresh one (with
// its own guard and pool, sharing the config template) on first use. The lock is
// held across bootstrap, so creating a new identity briefly serializes other
// new-identity lookups; the common no-auth path is pre-populated and never
// bootstraps here.
func (p *clientPool) clientFor(ctx context.Context, key string) (*tor.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.clients[key]; ok {
		return c, nil
	}
	c, err := tor.NewClient(ctx, p.cfg)
	if err != nil {
		return nil, fmt.Errorf("bootstrap isolated tor client: %w", err)
	}
	p.clients[key] = c
	return c, nil
}

func (p *clientPool) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.clients {
		_ = c.Close()
	}
}
