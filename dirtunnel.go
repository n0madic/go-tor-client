package tor

import (
	"context"
	"fmt"

	"github.com/n0madic/go-tor-client/pkg/circuit"
	"github.com/n0madic/go-tor-client/pkg/stream"
)

// DirGet implements directory.Tunnel: it fetches a directory document through
// Tor over a reusable BEGIN_DIR circuit, anonymizing post-bootstrap directory
// requests (microdescriptors, consensus refreshes). The circuit's stream
// manager is shared and persistent, so concurrent DirGet calls multiplex
// distinct streams over it instead of each resetting the circuit's cell handler.
func (c *Client) DirGet(ctx context.Context, path string) ([]byte, error) {
	circ, mgr, err := c.dirCircuit(ctx)
	if err != nil {
		return nil, err
	}
	body, err := c.dirGet(ctx, mgr, path)
	if err != nil && circ.Closed() {
		// The shared circuit died; drop it so the next call rebuilds. A
		// transient per-request error (e.g. context cancellation or an HSDir
		// HTTP error) leaves the still-open circuit in place for concurrent and
		// subsequent directory fetches instead of tearing it out from under them.
		c.mu.Lock()
		if c.dirCirc == circ {
			c.dirCirc = nil
			c.dirMgr = nil
		}
		c.mu.Unlock()
		circ.Destroy()
	}
	return body, err
}

// dirCircuit returns the shared directory circuit and its persistent stream
// manager, building both if absent or dead.
func (c *Client) dirCircuit(ctx context.Context) (*circuit.Circuit, *stream.Manager, error) {
	c.mu.Lock()
	if c.dirCirc != nil && !c.dirCirc.Closed() {
		circ, mgr := c.dirCirc, c.dirMgr
		c.mu.Unlock()
		return circ, mgr, nil
	}
	c.mu.Unlock()

	circ, err := c.buildDirCircuit(ctx)
	if err != nil {
		return nil, nil, err
	}
	// One manager per circuit, registered once: it installs the circuit's stream
	// handler and multiplexes every tunneled directory stream over it.
	mgr := stream.NewManager(circ, c.log)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		circ.Destroy()
		return nil, nil, fmt.Errorf("tor: client closed")
	}
	if c.dirCirc != nil && !c.dirCirc.Closed() {
		// Another goroutine built a directory circuit while we were building;
		// keep theirs and tear ours down so it is not leaked.
		existing, existingMgr := c.dirCirc, c.dirMgr
		c.mu.Unlock()
		circ.Destroy()
		return existing, existingMgr, nil
	}
	c.dirCirc = circ
	c.dirMgr = mgr
	c.mu.Unlock()
	return circ, mgr, nil
}

// buildDirCircuit builds guard -> middle -> dir-cache(V2Dir). It resolves its
// relays' microdescriptors via DIRECT HTTP so it does not depend on the tunnel
// it is the basis for.
func (c *Client) buildDirCircuit(ctx context.Context) (*circuit.Circuit, error) {
	c.mu.Lock()
	guardChan := c.guardChan
	guardInfo := c.guardInfo
	guardRS := c.findRouterByIdentity(guardInfo.RSAIDDigest)
	c.mu.Unlock()
	if guardChan == nil {
		return nil, fmt.Errorf("tor: client closed")
	}

	// Select middle and dir-cache with the same family exclusion the exit circuit
	// uses, resolving microdescriptors over direct HTTP (the tunnel this circuit
	// underpins does not exist yet).
	guardSel, err := c.selectedRelayDirect(ctx, guardRS)
	if err != nil {
		return nil, err
	}
	sel := c.selector()
	middle, err := c.pickRelayVia(ctx, sel.SelectMiddle, []selectedRelay{guardSel}, nil, c.microdescDirect)
	if err != nil {
		return nil, err
	}
	dirRelay, err := c.pickRelayVia(ctx, sel.SelectDirCache, []selectedRelay{guardSel, middle}, nil, c.microdescDirect)
	if err != nil {
		return nil, err
	}
	middleInfo := toRelayInfo(middle.rs, middle.md)
	dirInfo := toRelayInfo(dirRelay.rs, dirRelay.md)

	circ, err := circuit.New(guardChan, c.log)
	if err != nil {
		return nil, err
	}
	if err := circ.Build(ctx, []circuit.RelayInfo{guardInfo, middleInfo, dirInfo}); err != nil {
		circ.Destroy()
		return nil, fmt.Errorf("tor: build directory circuit: %w", err)
	}
	c.log.Debug("directory circuit built", "middle", middleInfo.Nickname, "dircache", dirInfo.Nickname)
	return circ, nil
}
