package main

import (
	"context"
	"fmt"
	"sync"

	tor "github.com/n0madic/go-tor-client"
	"github.com/n0madic/go-tor-client/pkg/proxyauth"
)

// maxIsolatedClients bounds how many distinct proxy-auth identities the pool will
// bootstrap. Each identity is a full Tor client (its own guard channel and
// circuit pool), so without a cap an attacker who can reach the proxy could spin
// up unbounded clients by rotating credentials. The base no-auth identity counts
// toward the cap. 64 is generous for legitimate isolation use.
const maxIsolatedClients = 64

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
	// newClient bootstraps a fresh isolated client; defaults to tor.NewClient and
	// is overridden in tests to avoid real network bootstrap.
	newClient func(context.Context, *tor.Config) (*tor.Client, error)

	mu       sync.Mutex
	clients  map[string]*tor.Client
	building map[string]*clientBuild // in-flight bootstraps, keyed by identity
}

// clientBuild tracks a single in-flight bootstrap so concurrent requests for the
// same new identity wait on one bootstrap instead of each starting their own.
type clientBuild struct {
	done   chan struct{}
	client *tor.Client
	err    error
}

func newClientPool(cfg *tor.Config, base *tor.Client) *clientPool {
	return &clientPool{
		cfg:       cfg,
		newClient: tor.NewClient,
		clients:   map[string]*tor.Client{"": base},
		building:  map[string]*clientBuild{},
	}
}

// dialer satisfies proxyauth.DialerFactory: it returns the *tor.Client for the
// connection's auth identity, creating it on first use. It is wired directly as
// the Factory of both the SOCKS and HTTP proxy servers.
func (p *clientPool) dialer(ctx context.Context, user, pass string) (proxyauth.Dialer, error) {
	return p.clientFor(ctx, proxyauth.IsoKey(user, pass))
}

// clientFor returns the cached client for key, bootstrapping a fresh one (with
// its own guard and pool, sharing the config template) on first use. The pool
// lock is released across the bootstrap so one slow new identity does not
// serialize lookups for other identities; concurrent callers for the same key
// share a single in-flight bootstrap, and new identities are rejected once the
// pool is at capacity.
func (p *clientPool) clientFor(ctx context.Context, key string) (*tor.Client, error) {
	p.mu.Lock()
	if c, ok := p.clients[key]; ok {
		p.mu.Unlock()
		return c, nil
	}
	if b, ok := p.building[key]; ok {
		p.mu.Unlock()
		select {
		case <-b.done:
			return b.client, b.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if len(p.clients)+len(p.building) >= maxIsolatedClients {
		p.mu.Unlock()
		return nil, fmt.Errorf("isolated client pool at capacity (%d identities); refusing new identity", maxIsolatedClients)
	}
	b := &clientBuild{done: make(chan struct{})}
	p.building[key] = b
	p.mu.Unlock()

	// Bootstrap without holding the pool lock.
	c, err := p.newClient(ctx, p.cfg)
	if err != nil {
		err = fmt.Errorf("bootstrap isolated tor client: %w", err)
	}

	p.mu.Lock()
	delete(p.building, key)
	if err == nil {
		p.clients[key] = c
	}
	p.mu.Unlock()

	b.client, b.err = c, err
	close(b.done)
	return c, err
}

func (p *clientPool) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.clients {
		_ = c.Close()
	}
}
