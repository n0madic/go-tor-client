package tor

import (
	"context"
	"fmt"

	"github.com/n0madic/go-tor-client/pkg/circuit"
	"github.com/n0madic/go-tor-client/pkg/directory"
)

// DirGet implements directory.Tunnel: it fetches a directory document through
// Tor over a reusable BEGIN_DIR circuit, anonymizing post-bootstrap directory
// requests (microdescriptors, consensus refreshes).
func (c *Client) DirGet(ctx context.Context, path string) ([]byte, error) {
	circ, err := c.dirCircuit(ctx)
	if err != nil {
		return nil, err
	}
	body, err := c.dirGet(ctx, circ, path)
	if err != nil {
		// The circuit may be dead; drop it so the next call rebuilds.
		c.mu.Lock()
		if c.dirCirc == circ {
			c.dirCirc = nil
		}
		c.mu.Unlock()
		circ.Destroy()
	}
	return body, err
}

// dirCircuit returns the shared directory circuit, building it if absent or dead.
func (c *Client) dirCircuit(ctx context.Context) (*circuit.Circuit, error) {
	c.mu.Lock()
	if c.dirCirc != nil && !c.dirCirc.Closed() {
		circ := c.dirCirc
		c.mu.Unlock()
		return circ, nil
	}
	c.mu.Unlock()

	circ, err := c.buildDirCircuit(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		circ.Destroy()
		return nil, fmt.Errorf("tor: client closed")
	}
	if c.dirCirc != nil && !c.dirCirc.Closed() {
		// Another goroutine built a directory circuit while we were building;
		// keep theirs and tear ours down so it is not leaked.
		existing := c.dirCirc
		c.mu.Unlock()
		circ.Destroy()
		return existing, nil
	}
	c.dirCirc = circ
	c.mu.Unlock()
	return circ, nil
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

	sel := c.selector()
	middle, err := sel.SelectMiddle(guardRS)
	if err != nil {
		return nil, err
	}
	dirRelay, err := sel.SelectDirCache(guardRS, middle)
	if err != nil {
		return nil, err
	}
	middleInfo, err := c.relayInfoDirect(ctx, middle)
	if err != nil {
		return nil, err
	}
	dirInfo, err := c.relayInfoDirect(ctx, dirRelay)
	if err != nil {
		return nil, err
	}

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

func (c *Client) relayInfoDirect(ctx context.Context, rs *directory.RouterStatus) (circuit.RelayInfo, error) {
	md, err := c.microdescDirect(ctx, rs)
	if err != nil {
		return circuit.RelayInfo{}, err
	}
	return toRelayInfo(rs, md), nil
}
