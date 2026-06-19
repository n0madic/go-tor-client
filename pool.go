package tor

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/n0madic/go-tor-client/pkg/circuit"
	"github.com/n0madic/go-tor-client/pkg/directory"
	"github.com/n0madic/go-tor-client/pkg/onion"
	"github.com/n0madic/go-tor-client/pkg/stream"
)

const (
	// defaultMaxCircuitDirtiness mirrors tor's MaxCircuitDirtiness: a circuit
	// stops accepting new streams once this long has elapsed since it was first
	// used. Streams already open on it keep working until they close.
	defaultMaxCircuitDirtiness = 10 * time.Minute
	// reapInterval is how often the background janitor scans the pool for
	// circuits to tear down.
	reapInterval = 30 * time.Second

	// maxClearnetCircuits caps the number of reusable clearnet circuits retained
	// in the pool. A burst of concurrent dials may transiently build more (each
	// serves its dial), but any circuit beyond the cap is retired on construction
	// so it is torn down once its stream closes instead of being kept for reuse.
	maxClearnetCircuits = 32
	// maxOnionCircuitsPerHost caps reusable circuits retained per onion host.
	maxOnionCircuitsPerHost = 8
	// maxOnionHosts caps the number of distinct onion hosts retained in the pool,
	// bounding memory when a client dials many different services.
	maxOnionHosts = 64
)

// pooledCircuit is a reusable circuit plus its stream manager. A single manager
// multiplexes many concurrent streams over one circuit. The born/streams/retired
// fields are guarded by Client.poolMu; circ, mgr, onion and exitMD are immutable
// after construction.
type pooledCircuit struct {
	circ    *circuit.Circuit
	mgr     *stream.Manager           // one manager per circuit → multi-stream multiplex
	born    time.Time                 // dirty-since clock: set when the circuit is built
	onion   string                    // "" = clearnet; otherwise the onion host (reuse key)
	exitMD  directory.Microdescriptor // clearnet only: for ExitPolicy.Allows(port)
	streams int                       // active stream count (guarded by poolMu)
	retired bool                      // NEWNYM/rotation marked it unusable for new streams
}

// circuitReusable reports whether a pooled circuit may carry a new stream: it
// must be open, not retired, still within the dirtiness window, and match the
// caller's requirement (exit allows the port, or onion host equal).
func circuitReusable(born, now time.Time, maxDirty time.Duration, retired, closed, matches bool) bool {
	return !closed && !retired && now.Sub(born) < maxDirty && matches
}

// reusableClearnetLocked counts clearnet circuits still eligible for reuse
// (not retired). Must hold poolMu.
func (c *Client) reusableClearnetLocked() int {
	n := 0
	for _, pc := range c.clearnetPool {
		if !pc.retired {
			n++
		}
	}
	return n
}

// reusableOnionLocked counts reusable circuits retained for host. Must hold poolMu.
func (c *Client) reusableOnionLocked(host string) int {
	n := 0
	for _, pc := range c.onionPool[host] {
		if !pc.retired {
			n++
		}
	}
	return n
}

// retireNewClearnetLocked reports whether a freshly built clearnet circuit should
// be retired (served once, not retained for reuse) because the pool is already at
// capacity. Must hold poolMu.
func (c *Client) retireNewClearnetLocked() bool {
	return c.reusableClearnetLocked() >= maxClearnetCircuits
}

// retireNewOnionLocked reports whether a freshly built onion circuit for host
// should be retired because the host — or the distinct-host count — is at
// capacity. Must hold poolMu.
func (c *Client) retireNewOnionLocked(host string) bool {
	newHost := c.onionPool[host] == nil
	return c.reusableOnionLocked(host) >= maxOnionCircuitsPerHost ||
		(newHost && len(c.onionPool) >= maxOnionHosts)
}

// Stats reports circuit-pool counters for observability and tests.
type Stats struct {
	ClearnetCircuits int
	OnionCircuits    int
	Built            int
	Reused           int
}

// Stats returns a snapshot of the circuit-pool counters.
func (c *Client) Stats() Stats {
	c.poolMu.Lock()
	defer c.poolMu.Unlock()
	onionCircuits := 0
	for _, pcs := range c.onionPool {
		onionCircuits += len(pcs)
	}
	return Stats{
		ClearnetCircuits: len(c.clearnetPool),
		OnionCircuits:    onionCircuits,
		Built:            c.built,
		Reused:           c.reused,
	}
}

// acquireClearnet returns a reusable pooled clearnet circuit whose exit permits
// port, incrementing its stream count, or nil if none qualifies.
func (c *Client) acquireClearnet(port int) *pooledCircuit {
	now := time.Now()
	c.poolMu.Lock()
	defer c.poolMu.Unlock()
	for _, pc := range c.clearnetPool {
		matches := pc.exitMD.ExitPolicy.Allows(port)
		if circuitReusable(pc.born, now, c.maxDirty, pc.retired, pc.circ.Closed(), matches) {
			pc.streams++
			c.reused++
			return pc
		}
	}
	return nil
}

// acquireOnion returns a reusable pooled onion circuit for host, incrementing its
// stream count, or nil if none qualifies.
func (c *Client) acquireOnion(host string) *pooledCircuit {
	now := time.Now()
	c.poolMu.Lock()
	defer c.poolMu.Unlock()
	for _, pc := range c.onionPool[host] {
		if circuitReusable(pc.born, now, c.maxDirty, pc.retired, pc.circ.Closed(), true) {
			pc.streams++
			c.reused++
			return pc
		}
	}
	return nil
}

// dialOnionViaDescriptor builds a fresh onion circuit for host from a decoded
// descriptor, pools it, and opens the first stream to the service's port.
func (c *Client) dialOnionViaDescriptor(ctx context.Context, host string, desc *onion.Descriptor, subcred []byte, port int) (net.Conn, error) {
	circ, err := c.buildOnionCircuitWithRetry(ctx, desc, subcred)
	if err != nil {
		return nil, err
	}
	pc := &pooledCircuit{
		circ:    circ,
		mgr:     stream.NewManager(circ, c.log),
		born:    time.Now(),
		onion:   host,
		streams: 1,
	}
	c.poolMu.Lock()
	// Retire (don't retain for reuse) once this host — or the host count — is at
	// capacity; the circuit still serves this dial and is torn down on close.
	if c.retireNewOnionLocked(host) {
		pc.retired = true
	}
	c.onionPool[host] = append(c.onionPool[host], pc)
	c.built++
	c.poolMu.Unlock()

	s, err := pc.mgr.Begin(ctx, ":"+strconv.Itoa(port))
	if err != nil {
		c.releaseStream(pc)
		return nil, fmt.Errorf("tor: onion BEGIN: %w", err)
	}
	return c.newTrackedConn(pc, s), nil
}

// releaseStream returns one stream slot to a pooled circuit and tears the circuit
// down once it is idle and no longer eligible for reuse (retired or expired).
// Dead-but-idle circuits are left for the janitor, which also handles them.
func (c *Client) releaseStream(pc *pooledCircuit) {
	c.poolMu.Lock()
	defer c.poolMu.Unlock()
	if pc.streams > 0 {
		pc.streams--
	}
	if pc.streams == 0 && (pc.retired || c.expiredLocked(pc)) {
		c.destroyLocked(pc)
	}
}

// expiredLocked reports whether a circuit has exceeded the dirtiness window.
func (c *Client) expiredLocked(pc *pooledCircuit) bool {
	return time.Since(pc.born) >= c.maxDirty
}

// destroyLocked tears down a pooled circuit and removes it from its pool. Must
// hold poolMu.
func (c *Client) destroyLocked(pc *pooledCircuit) {
	pc.circ.Destroy()
	c.removeLocked(pc)
}

// removeLocked drops pc from whichever pool slice/map holds it. Must hold poolMu.
func (c *Client) removeLocked(pc *pooledCircuit) {
	if pc.onion == "" {
		c.clearnetPool = removePooled(c.clearnetPool, pc)
		return
	}
	rest := removePooled(c.onionPool[pc.onion], pc)
	if len(rest) == 0 {
		delete(c.onionPool, pc.onion)
	} else {
		c.onionPool[pc.onion] = rest
	}
}

func removePooled(s []*pooledCircuit, pc *pooledCircuit) []*pooledCircuit {
	out := make([]*pooledCircuit, 0, len(s))
	for _, p := range s {
		if p != pc {
			out = append(out, p)
		}
	}
	return out
}

// allPooledLocked returns a snapshot of every pooled circuit, safe to iterate
// while destroyLocked mutates the underlying pools. Must hold poolMu.
func (c *Client) allPooledLocked() []*pooledCircuit {
	all := make([]*pooledCircuit, 0, len(c.clearnetPool))
	all = append(all, c.clearnetPool...)
	for _, pcs := range c.onionPool {
		all = append(all, pcs...)
	}
	return all
}

// maintain runs the background janitor, reaping dead/dirty/idle circuits on a
// ticker until the client is closed.
func (c *Client) maintain() {
	ticker := time.NewTicker(reapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			c.reap()
		}
	}
}

// reap destroys and removes pooled circuits that have died, or are idle and no
// longer reusable (expired or retired).
func (c *Client) reap() {
	now := time.Now()
	c.poolMu.Lock()
	defer c.poolMu.Unlock()
	for _, pc := range c.allPooledLocked() {
		idle := pc.streams == 0
		dead := pc.circ.Closed()
		if dead || (idle && (pc.retired || now.Sub(pc.born) >= c.maxDirty)) {
			c.destroyLocked(pc)
		}
	}
}

// trackedConn wraps a pooled circuit's stream so that closing it releases the
// circuit's stream slot exactly once, in addition to closing the stream itself.
type trackedConn struct {
	net.Conn
	c         *Client
	pc        *pooledCircuit
	closeOnce sync.Once
}

func (c *Client) newTrackedConn(pc *pooledCircuit, s net.Conn) *trackedConn {
	return &trackedConn{Conn: s, c: c, pc: pc}
}

// Close closes the underlying stream and releases the pooled circuit's stream
// slot. It is idempotent: a second call is a no-op.
func (t *trackedConn) Close() error {
	var err error
	t.closeOnce.Do(func() {
		err = t.Conn.Close()
		t.c.releaseStream(t.pc)
	})
	return err
}
