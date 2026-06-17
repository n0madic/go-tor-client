// Package tor implements a minimal pure-Go Tor client. The public entry point
// is Client.DialContext, which is compatible with proxy.ContextDialer and
// *net.Dialer.DialContext, so it can be installed directly as an
// http.Transport.DialContext.
//
// Stage 1 supports clearnet streams over 3-hop circuits and v3 onion services.
// Only modern protocol features are implemented: ntor handshakes, link
// protocol v4/v5, and the microdescriptor consensus.
package tor

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/n0madic/go-tor-client/pkg/channel"
	"github.com/n0madic/go-tor-client/pkg/circuit"
	"github.com/n0madic/go-tor-client/pkg/directory"
	"github.com/n0madic/go-tor-client/pkg/onion"
	"github.com/n0madic/go-tor-client/pkg/pathsel"
	"github.com/n0madic/go-tor-client/pkg/stream"
)

// Config configures a Client. The zero value is usable; all fields optional.
type Config struct {
	// DataDir, if set, persists the selected guard between runs and, unless
	// Cache is provided, backs an on-disk directory cache (consensus, certs,
	// microdescriptors) for faster startup.
	DataDir string
	// Logger receives debug/info logs; defaults to slog.Default().
	Logger *slog.Logger
	// DirAuthorities overrides the hardcoded authority set (for tests).
	DirAuthorities []directory.Authority
	// Cache overrides the directory cache implementation. When nil and DataDir
	// is set, an on-disk cache under DataDir/cache is used; when nil and DataDir
	// is empty, caching is disabled.
	Cache directory.Cache
	// OnionClientAuth maps an onion address (the 56-char base32 label, with or
	// without the ".onion" suffix) to a 32-byte x25519 client-authorization
	// private key, for connecting to restricted-discovery onion services.
	OnionClientAuth map[string][]byte
	// MaxCircuitDirtiness bounds how long a pooled circuit accepts new streams
	// after first use, mirroring tor's option of the same name. Zero selects the
	// 10-minute default.
	MaxCircuitDirtiness time.Duration
	// AllowDirectDirFallback permits post-bootstrap directory fetches to fall back
	// to direct HTTP (from the local IP) when the Tor tunnel fails. Default false:
	// once the tunnel is up, tunnel failures are returned as errors rather than
	// silently deanonymizing the request. The cold-start consensus is always
	// fetched directly regardless of this setting.
	AllowDirectDirFallback bool
}

// Client is a bootstrapped Tor client.
type Client struct {
	log *slog.Logger
	dir *directory.Client
	// sel holds the current path selector. It is swapped atomically on consensus
	// refresh; the selector itself is immutable.
	sel atomic.Pointer[pathsel.Selector]

	mu        sync.Mutex
	guardChan *channel.Channel
	guardInfo circuit.RelayInfo
	mdCache   map[string]directory.Microdescriptor
	ringCache []onion.RingNode
	dirCirc   *circuit.Circuit // reusable circuit for tunneled directory fetches
	dirMgr    *stream.Manager  // persistent stream manager bound to dirCirc (one per circuit)
	onionAuth map[string][]byte
	closed    bool

	ringMu sync.Mutex // single-flights the (expensive) HSDir ring build

	// Circuit pool: reusable, age-rotated circuits keyed by reuse class.
	poolMu       sync.Mutex
	clearnetPool []*pooledCircuit
	onionPool    map[string][]*pooledCircuit
	built        int // circuits built (for Stats)
	reused       int // circuit reuses (for Stats)

	dataDir   string
	maxDirty  time.Duration
	done      chan struct{} // closed by Close to stop the janitor
	closeOnce sync.Once
	// refreshSem is a capacity-1 semaphore that single-flights lazy consensus
	// refreshes. It is a channel (not a Mutex) so a waiter can honor its own ctx
	// instead of blocking past its deadline behind another caller's slow refresh.
	refreshSem chan struct{}
}

// selector returns the current path selector.
func (c *Client) selector() *pathsel.Selector { return c.sel.Load() }

// normalizeOnionAuth lower-cases auth-key map keys and strips any ".onion".
func normalizeOnionAuth(in map[string][]byte) map[string][]byte {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]byte, len(in))
	for k, v := range in {
		out[strings.TrimSuffix(strings.ToLower(k), ".onion")] = v
	}
	return out
}

// onionAuthKey returns the client-authorization key for an onion host, or nil.
func (c *Client) onionAuthKey(host string) []byte {
	if len(c.onionAuth) == 0 {
		return nil
	}
	h := strings.TrimSuffix(strings.ToLower(host), ".onion")
	return c.onionAuth[h]
}

// NewClient bootstraps the client: it verifies a fresh consensus, selects and
// connects an entry guard, and returns a ready Client.
func NewClient(ctx context.Context, cfg *Config) (*Client, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}

	dir := directory.NewClient(cfg.DirAuthorities, log)
	dir.AllowDirectFallback(cfg.AllowDirectDirFallback)
	if cache := resolveCache(cfg, log); cache != nil {
		dir.UseCache(cache)
	}
	cons, err := dir.Bootstrap(ctx)
	if err != nil {
		return nil, err
	}
	log.Info("consensus bootstrapped", "routers", len(cons.Routers), "valid_until", cons.ValidUntil)

	maxDirty := cfg.MaxCircuitDirtiness
	if maxDirty <= 0 {
		maxDirty = defaultMaxCircuitDirtiness
	}

	c := &Client{
		log:        log,
		dir:        dir,
		mdCache:    make(map[string]directory.Microdescriptor),
		onionAuth:  normalizeOnionAuth(cfg.OnionClientAuth),
		onionPool:  make(map[string][]*pooledCircuit),
		dataDir:    cfg.DataDir,
		maxDirty:   maxDirty,
		done:       make(chan struct{}),
		refreshSem: make(chan struct{}, 1),
	}
	c.sel.Store(pathsel.New(cons))

	if err := c.connectGuard(ctx, cfg.DataDir, nil); err != nil {
		return nil, err
	}
	// Now that a guard is available, route further directory fetches
	// (microdescriptors, consensus refreshes) through Tor via BEGIN_DIR.
	dir.UseTunnel(c)
	go c.maintain()
	return c, nil
}

// connectGuard selects an entry guard, fetches its microdescriptor, and opens a
// verified link channel to it. When avoid is non-nil (guard rotation), the
// persisted-guard preference is skipped and a guard with that identity is never
// chosen, so rotation always lands on a different relay.
func (c *Client) connectGuard(ctx context.Context, dataDir string, avoid []byte) error {
	persisted := ""
	if avoid == nil {
		persisted = loadGuard(dataDir)
	}

	var exclude []*directory.RouterStatus
	if avoid != nil {
		if old := c.findRouterByIdentity(avoid); old != nil {
			exclude = append(exclude, old)
		}
	}

	const maxAttempts = 8
	var lastErr error
	for attempt := range maxAttempts {
		var rs *directory.RouterStatus
		if attempt == 0 && persisted != "" {
			rs = c.findRouterByIdentityHex(persisted)
		}
		if rs == nil {
			var err error
			rs, err = c.selector().SelectGuard(exclude...)
			if err != nil {
				return err
			}
		}
		if avoid != nil && string(rs.Identity) == string(avoid) {
			continue
		}

		info, err := c.relayInfo(ctx, rs)
		if err != nil {
			lastErr = err
			continue
		}
		ch, err := channel.Dial(ctx, info.ORAddr, channel.Config{
			ExpectedEd25519: info.EdIdentity,
			Logger:          c.log,
		})
		if err != nil {
			c.log.Debug("guard dial failed", "guard", rs.Nickname, "err", err)
			lastErr = err
			continue
		}

		c.mu.Lock()
		c.guardChan = ch
		c.guardInfo = info
		c.mu.Unlock()
		saveGuard(dataDir, rs.Identity)
		c.log.Info("connected to guard", "nick", rs.Nickname, "addr", info.ORAddr)
		return nil
	}
	return fmt.Errorf("tor: could not connect to any guard: %w", lastErr)
}

// DialContext opens a stream through Tor. addr is "host:port"; a ".onion" host
// is routed through the v3 onion-service flow, anything else through a 3-hop
// circuit and an exit relay.
func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("tor: unsupported network %q", network)
	}
	c.ensureFreshConsensus(ctx)
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("tor: bad address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("tor: bad port %q: %w", portStr, err)
	}

	if strings.HasSuffix(strings.ToLower(host), ".onion") {
		return c.dialOnion(ctx, host, port)
	}
	return c.dialClearnet(ctx, addr, port)
}

// dialClearnet opens a stream to addr, reusing a pooled circuit whose exit
// permits the target port when one is available and otherwise building a fresh
// guard->middle->exit circuit and pooling it.
func (c *Client) dialClearnet(ctx context.Context, addr string, port int) (net.Conn, error) {
	pc := c.acquireClearnet(port)
	if pc == nil {
		circ, exit, err := c.buildExitCircuit(ctx, port)
		if err != nil {
			return nil, err
		}
		pc = &pooledCircuit{
			circ:    circ,
			mgr:     stream.NewManager(circ, c.log),
			born:    time.Now(),
			exitMD:  exit.md,
			streams: 1,
		}
		c.poolMu.Lock()
		c.clearnetPool = append(c.clearnetPool, pc)
		c.built++
		c.poolMu.Unlock()
	}

	s, err := pc.mgr.Begin(ctx, addr)
	if err != nil {
		c.releaseStream(pc)
		return nil, fmt.Errorf("tor: BEGIN %s: %w", addr, err)
	}
	return c.newTrackedConn(pc, s), nil
}

// buildExitCircuit selects a path with a port-compatible exit, builds the circuit
// over the guard channel, and returns it together with the chosen exit (so the
// pool can store the exit's microdescriptor for reuse matching).
func (c *Client) buildExitCircuit(ctx context.Context, port int) (*circuit.Circuit, selectedRelay, error) {
	c.mu.Lock()
	guardChan := c.guardChan
	guardInfo := c.guardInfo
	guardRS := c.findRouterByIdentity(guardInfo.RSAIDDigest)
	c.mu.Unlock()
	if guardChan == nil {
		return nil, selectedRelay{}, fmt.Errorf("tor: client closed")
	}

	guardSel, err := c.selectedGuard(ctx, guardRS)
	if err != nil {
		return nil, selectedRelay{}, err
	}

	sel := c.selector()
	middle, err := c.pickRelay(ctx, sel.SelectMiddle, []selectedRelay{guardSel}, nil)
	if err != nil {
		return nil, selectedRelay{}, err
	}
	exit, err := c.pickRelay(ctx,
		func(exclude ...*directory.RouterStatus) (*directory.RouterStatus, error) {
			return sel.SelectExit(nil, exclude...)
		},
		[]selectedRelay{guardSel, middle},
		func(md directory.Microdescriptor) bool { return md.ExitPolicy.Allows(port) },
	)
	if err != nil {
		return nil, selectedRelay{}, fmt.Errorf("tor: no exit permits port %d: %w", port, err)
	}

	circ, err := circuit.New(guardChan, c.log)
	if err != nil {
		return nil, selectedRelay{}, err
	}
	path := []circuit.RelayInfo{guardInfo, toRelayInfo(middle.rs, middle.md), toRelayInfo(exit.rs, exit.md)}
	if err := circ.Build(ctx, path); err != nil {
		circ.Destroy()
		return nil, selectedRelay{}, fmt.Errorf("tor: build circuit: %w", err)
	}
	c.log.Debug("circuit built", "middle", middle.rs.Nickname, "exit", exit.rs.Nickname)
	return circ, exit, nil
}

// Close stops the janitor, tears down all pooled circuits, and closes the guard
// channel (which drops the directory circuit and every other circuit on it).
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	guardChan := c.guardChan
	c.mu.Unlock()

	c.closeOnce.Do(func() { close(c.done) })

	c.poolMu.Lock()
	for _, pc := range c.allPooledLocked() {
		c.destroyLocked(pc)
	}
	c.poolMu.Unlock()

	if guardChan != nil {
		return guardChan.Close()
	}
	return nil
}

// NewIdentity drops all pooled circuits so subsequent dials build fresh paths —
// the NEWNYM equivalent. It performs no network I/O: idle circuits are torn down
// immediately; in-use ones are retired and reaped once their last stream closes,
// so existing open streams keep working until the caller closes them.
func (c *Client) NewIdentity() {
	c.poolMu.Lock()
	for _, pc := range c.allPooledLocked() {
		pc.retired = true
		if pc.streams == 0 {
			c.destroyLocked(pc)
		}
	}
	c.poolMu.Unlock()

	c.mu.Lock()
	dirCirc := c.dirCirc
	c.dirCirc = nil
	c.dirMgr = nil
	c.mu.Unlock()
	if dirCirc != nil {
		dirCirc.Destroy()
	}
}

// RotateGuard closes the current guard channel (tearing down every circuit on
// it, including all pooled and directory circuits) and connects to a different
// entry guard. In-flight streams break; callers should expect to redial.
func (c *Client) RotateGuard(ctx context.Context) error {
	c.mu.Lock()
	oldChan := c.guardChan
	oldID := append([]byte(nil), c.guardInfo.RSAIDDigest...)
	c.mu.Unlock()

	// Connect a different guard FIRST. connectGuard installs the new guardChan on
	// success and leaves the current one untouched on failure, so a failed
	// rotation keeps the client working on its existing guard instead of wedging
	// it with a nil guardChan.
	if err := c.connectGuard(ctx, c.dataDir, oldID); err != nil {
		return fmt.Errorf("tor: rotate guard: %w", err)
	}

	// New guard is up; tear down everything bound to the old guard channel.
	c.mu.Lock()
	c.dirCirc = nil
	c.dirMgr = nil
	c.mu.Unlock()

	c.poolMu.Lock()
	for _, pc := range c.allPooledLocked() {
		c.destroyLocked(pc)
	}
	c.poolMu.Unlock()

	if oldChan != nil {
		_ = oldChan.Close()
	}
	return nil
}

// ensureFreshConsensus refreshes the consensus (and resets dependent caches) if
// the current one has expired. Best-effort: on refresh failure the dial proceeds
// on the stale consensus rather than failing hard.
func (c *Client) ensureFreshConsensus(ctx context.Context) {
	if c.selector().Consensus().ValidUntil.After(time.Now()) {
		return
	}
	// Acquire the single-flight slot, but honor our own ctx while waiting: if a
	// concurrent refresh is in progress and our deadline passes first, proceed on
	// the stale consensus (this is best-effort) rather than block past it.
	select {
	case c.refreshSem <- struct{}{}:
		defer func() { <-c.refreshSem }()
	case <-ctx.Done():
		return
	}
	// Double-check: another dial may have refreshed while we waited for the slot.
	if c.selector().Consensus().ValidUntil.After(time.Now()) {
		return
	}
	if err := c.refreshConsensus(ctx); err != nil {
		c.log.Debug("consensus refresh failed; using stale consensus", "err", err)
	}
}

// refreshConsensus fetches a fresh consensus, swaps in a new selector, and resets
// the consensus-derived caches. Unlike ensureFreshConsensus it does not check
// expiry first.
func (c *Client) refreshConsensus(ctx context.Context) error {
	cons, err := c.dir.Refresh(ctx)
	if err != nil {
		return err
	}
	c.sel.Store(pathsel.New(cons))
	c.mu.Lock()
	c.ringCache = nil
	clear(c.mdCache)
	c.mu.Unlock()
	c.log.Info("consensus refreshed", "routers", len(cons.Routers), "valid_until", cons.ValidUntil)
	return nil
}

// --- helpers ---

func (c *Client) relayInfo(ctx context.Context, rs *directory.RouterStatus) (circuit.RelayInfo, error) {
	md, err := c.microdesc(ctx, rs)
	if err != nil {
		return circuit.RelayInfo{}, err
	}
	return toRelayInfo(rs, md), nil
}

func (c *Client) microdesc(ctx context.Context, rs *directory.RouterStatus) (directory.Microdescriptor, error) {
	return c.microdescVia(ctx, rs, c.dir.FetchMicrodescriptors)
}

// microdescDirect fetches a microdescriptor over direct HTTP (no tunnel), used
// when building the tunnel's own directory circuit.
func (c *Client) microdescDirect(ctx context.Context, rs *directory.RouterStatus) (directory.Microdescriptor, error) {
	return c.microdescVia(ctx, rs, c.dir.FetchMicrodescriptorsDirect)
}

func (c *Client) microdescVia(ctx context.Context, rs *directory.RouterStatus, fetch func(context.Context, []string) (map[string]directory.Microdescriptor, error)) (directory.Microdescriptor, error) {
	c.mu.Lock()
	if md, ok := c.mdCache[rs.MicrodescHash]; ok {
		c.mu.Unlock()
		return md, nil
	}
	c.mu.Unlock()

	mds, err := fetch(ctx, []string{rs.MicrodescHash})
	if err != nil {
		return directory.Microdescriptor{}, err
	}
	md, ok := mds[rs.MicrodescHash]
	if !ok {
		return directory.Microdescriptor{}, fmt.Errorf("tor: microdescriptor for %s not returned", rs.Nickname)
	}
	if len(md.Ed25519ID) != 32 || len(md.NtorOnionKey) != 32 {
		return directory.Microdescriptor{}, fmt.Errorf("tor: incomplete microdescriptor for %s", rs.Nickname)
	}
	c.mu.Lock()
	c.mdCache[rs.MicrodescHash] = md
	c.mu.Unlock()
	return md, nil
}

// selectedRelay bundles a chosen relay with its microdescriptor, so path
// selection can apply family exclusion.
type selectedRelay struct {
	rs *directory.RouterStatus
	md directory.Microdescriptor
}

// selectedGuard returns the guard plus its microdescriptor for family checks.
func (c *Client) selectedGuard(ctx context.Context, guardRS *directory.RouterStatus) (selectedRelay, error) {
	if guardRS == nil {
		return selectedRelay{}, fmt.Errorf("tor: guard not in consensus")
	}
	md, err := c.microdesc(ctx, guardRS)
	if err != nil {
		return selectedRelay{}, err
	}
	return selectedRelay{rs: guardRS, md: md}, nil
}

// pickRelay samples relays via sel until one fetches a microdescriptor that
// passes mdOK (if non-nil) and shares no declared family with any already-chosen
// relay, re-rolling on a conflict.
func (c *Client) pickRelay(
	ctx context.Context,
	sel func(exclude ...*directory.RouterStatus) (*directory.RouterStatus, error),
	chosen []selectedRelay,
	mdOK func(directory.Microdescriptor) bool,
) (selectedRelay, error) {
	exclude := make([]*directory.RouterStatus, 0, len(chosen)+8)
	for _, ch := range chosen {
		exclude = append(exclude, ch.rs)
	}
	const attempts = 20
	var lastErr error
	for range attempts {
		rs, err := sel(exclude...)
		if err != nil {
			return selectedRelay{}, err
		}
		md, err := c.microdesc(ctx, rs)
		if err != nil {
			lastErr = err
			exclude = append(exclude, rs)
			continue
		}
		if (mdOK != nil && !mdOK(md)) || c.familyConflict(rs, md, chosen) {
			exclude = append(exclude, rs)
			continue
		}
		return selectedRelay{rs: rs, md: md}, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no eligible relay after %d attempts", attempts)
	}
	return selectedRelay{}, lastErr
}

func (c *Client) familyConflict(rs *directory.RouterStatus, md directory.Microdescriptor, chosen []selectedRelay) bool {
	for _, ch := range chosen {
		if directory.SameFamily(md, rs.Identity, ch.md, ch.rs.Identity) {
			return true
		}
	}
	return false
}

func (c *Client) findRouterByIdentity(id []byte) *directory.RouterStatus {
	cons := c.selector().Consensus()
	for i := range cons.Routers {
		r := &cons.Routers[i]
		if string(r.Identity) == string(id) {
			return r
		}
	}
	return nil
}

func (c *Client) findRouterByIdentityHex(hexID string) *directory.RouterStatus {
	cons := c.selector().Consensus()
	for i := range cons.Routers {
		r := &cons.Routers[i]
		if strings.EqualFold(hex.EncodeToString(r.Identity), hexID) {
			return r
		}
	}
	return nil
}

func toRelayInfo(rs *directory.RouterStatus, md directory.Microdescriptor) circuit.RelayInfo {
	return circuit.RelayInfo{
		Nickname:     rs.Nickname,
		ORAddr:       net.JoinHostPort(rs.IP, strconv.Itoa(rs.ORPort)),
		RSAIDDigest:  rs.Identity,
		EdIdentity:   md.Ed25519ID,
		NtorOnionKey: md.NtorOnionKey,
	}
}
