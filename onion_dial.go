package tor

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/n0madic/go-tor-client/pkg/cell"
	"github.com/n0madic/go-tor-client/pkg/circuit"
	"github.com/n0madic/go-tor-client/pkg/directory"
	"github.com/n0madic/go-tor-client/pkg/onion"
	"github.com/n0madic/go-tor-client/pkg/stream"
	"github.com/n0madic/go-tor-client/pkg/torcrypto"
)

// dialOnion connects to a v3 onion service: derive the time period and blinded
// key, fetch and decrypt the descriptor from a responsible HSDir, then perform
// the introduction and rendezvous handshakes and open a stream.
func (c *Client) dialOnion(ctx context.Context, host string, port int) (net.Conn, error) {
	// Fast path: reuse an existing circuit to this onion service (building one is
	// expensive — descriptor fetch plus introduce/rendezvous — so reuse is a big
	// win).
	if pc := c.acquireOnion(host); pc != nil {
		s, err := pc.mgr.Begin(ctx, ":"+strconv.Itoa(port))
		if err != nil {
			c.releaseStream(pc)
			return nil, fmt.Errorf("tor: onion BEGIN: %w", err)
		}
		return c.newTrackedConn(pc, s), nil
	}

	addr, err := onion.ParseAddress(host)
	if err != nil {
		return nil, err
	}
	cons := c.selector().Consensus()
	tpCur, plen := onion.TimePeriod(cons.ValidAfter)
	tpPrev := tpCur - 1

	// Optional client-authorization key for restricted-discovery services.
	clientAuthKey := c.onionAuthKey(host)

	ring, err := c.hsDirRing(ctx)
	if err != nil {
		return nil, err
	}

	// Try the current and previous time periods, each with the SRV the client
	// rule selects plus the other as a fallback, to be robust to clock/segment
	// edge cases. The blinded key and subcredential differ per period.
	srvFor := onion.SRVForFetch(cons.ValidAfter, cons.SharedRandCurrent, cons.SharedRandPrevious)
	type attempt struct {
		tp  uint64
		srv []byte
	}
	consensusSRVs := dedupeSRVs(srvFor, cons.SharedRandCurrent, cons.SharedRandPrevious)
	var attempts []attempt
	for _, tp := range []uint64{tpCur, tpPrev} {
		srvs := consensusSRVs
		if len(srvs) == 0 {
			// The consensus carries no shared-random value (e.g. just after a
			// directory-authority outage); fall back to the per-period disaster
			// SRV the spec mandates (rend-spec-v3 [SHAREDRANDOM-DISASTER]).
			srvs = [][]byte{onion.DisasterSRV(tp, plen)}
		}
		for _, srv := range srvs {
			attempts = append(attempts, attempt{tp, srv})
		}
	}

	var lastErr error
	for _, a := range attempts {
		blinded, err := torcrypto.BlindPublicKey(addr.PublicKey, a.tp, plen)
		if err != nil {
			lastErr = err
			continue
		}
		subcred := onion.Subcredential(addr.PublicKey, blinded)
		responsible := onion.ResponsibleHSDirs(blinded, a.tp, plen, a.srv, ring)
		if len(responsible) == 0 {
			continue
		}
		desc, err := c.fetchDescriptor(ctx, responsible, blinded, subcred, clientAuthKey)
		if err != nil {
			lastErr = err
			continue
		}
		c.log.Debug("onion descriptor decoded", "intro_points", len(desc.IntroPoints), "period", a.tp)
		return c.dialOnionViaDescriptor(ctx, host, desc, subcred, port)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no descriptor found for %s", host)
	}
	return nil, fmt.Errorf("tor: %w", lastErr)
}

func dedupeSRVs(srvs ...[]byte) [][]byte {
	var out [][]byte
	seen := map[string]bool{}
	for _, s := range srvs {
		if len(s) != 32 || seen[string(s)] {
			continue
		}
		seen[string(s)] = true
		out = append(out, s)
	}
	return out
}

// hsDirRingNode carries the consensus + microdescriptor data for an HSDir.
type hsDirRingNode struct {
	rs *directory.RouterStatus
	md directory.Microdescriptor
}

// hsDirRing builds (and caches) the ring of HSDir-flagged relays with their
// Ed25519 identities, fetching all their microdescriptors.
func (c *Client) hsDirRing(ctx context.Context) ([]onion.RingNode, error) {
	c.mu.Lock()
	if c.ringCache != nil {
		ring := c.ringCache
		c.mu.Unlock()
		return ring, nil
	}
	c.mu.Unlock()

	// Single-flight the build: concurrent first-time callers would otherwise each
	// fetch every HSDir's microdescriptor (the most expensive directory fetch).
	c.ringMu.Lock()
	defer c.ringMu.Unlock()
	c.mu.Lock()
	if c.ringCache != nil {
		ring := c.ringCache
		c.mu.Unlock()
		return ring, nil
	}
	c.mu.Unlock()

	cons := c.selector().Consensus()
	var candidates []*directory.RouterStatus
	var hashes []string
	for i := range cons.Routers {
		r := &cons.Routers[i]
		if r.HasFlag("HSDir") && r.HasFlag("Running") && r.HasFlag("Valid") && r.MicrodescHash != "" {
			candidates = append(candidates, r)
			hashes = append(hashes, r.MicrodescHash)
		}
	}
	mds, err := c.dir.FetchMicrodescriptors(ctx, hashes)
	if err != nil {
		return nil, fmt.Errorf("tor: fetch HSDir microdescriptors: %w", err)
	}

	var ring []onion.RingNode
	for _, r := range candidates {
		md, ok := mds[r.MicrodescHash]
		if !ok || len(md.Ed25519ID) != 32 {
			continue
		}
		ring = append(ring, onion.RingNode{EdID: md.Ed25519ID, Payload: hsDirRingNode{rs: r, md: md}})
	}
	if len(ring) == 0 {
		return nil, fmt.Errorf("tor: no usable HSDirs in consensus")
	}

	c.mu.Lock()
	c.ringCache = ring
	c.mu.Unlock()
	c.log.Debug("HSDir ring built", "nodes", len(ring))
	return ring, nil
}

// fetchDescriptor tries each responsible HSDir until one serves a descriptor
// that decrypts.
func (c *Client) fetchDescriptor(ctx context.Context, dirs []onion.RingNode, blinded, subcred, clientAuthKey []byte) (*onion.Descriptor, error) {
	// The descriptor fetch URL uses the base64 (unpadded) blinded key, not
	// base32 (rend-spec-v3 [FETCHUPLOADDESC]).
	path := "/tor/hs/3/" + base64.RawStdEncoding.EncodeToString(blinded)
	var lastErr error
	for _, node := range dirs {
		n := node.Payload.(hsDirRingNode)
		info := toRelayInfo(n.rs, n.md)

		// Bound each HSDir attempt so one slow relay does not exhaust the budget.
		attemptCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		circ, err := c.buildCircuitVia(attemptCtx, info)
		if err != nil {
			cancel()
			c.log.Debug("onion: HSDir circuit failed", "hsdir", info.Nickname, "err", err)
			lastErr = err
			continue
		}
		raw, err := c.dirGet(attemptCtx, circ, path)
		circ.Destroy()
		cancel()
		if err != nil {
			c.log.Debug("onion: HSDir fetch failed", "hsdir", info.Nickname, "err", err)
			lastErr = err
			continue
		}
		desc, err := onion.DecodeDescriptor(raw, blinded, subcred, clientAuthKey)
		if err != nil {
			c.log.Debug("onion: descriptor decode failed", "hsdir", info.Nickname, "bytes", len(raw), "err", err)
			lastErr = err
			continue
		}
		c.log.Debug("onion: descriptor fetched", "hsdir", info.Nickname)
		return desc, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no HSDir served a descriptor")
	}
	return nil, fmt.Errorf("tor: fetch onion descriptor: %w", lastErr)
}

// dirGet opens a BEGIN_DIR stream on circ and performs an HTTP/1.0 GET.
func (c *Client) dirGet(ctx context.Context, circ *circuit.Circuit, path string) ([]byte, error) {
	mgr := stream.NewManager(circ, c.log)
	s, err := mgr.BeginDir(ctx)
	if err != nil {
		return nil, fmt.Errorf("BEGIN_DIR: %w", err)
	}
	defer s.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = s.SetDeadline(deadline)
	}

	req := "GET " + path + " HTTP/1.0\r\nHost: tor\r\nAccept-Encoding: gzip, deflate, identity\r\n\r\n"
	if _, err := s.Write([]byte(req)); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(s), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HSDir HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	return directory.Decompress(resp.Header.Get("Content-Encoding"), body)
}

// buildCircuitVia builds a guard->middle->third circuit over the guard channel.
func (c *Client) buildCircuitVia(ctx context.Context, third circuit.RelayInfo) (*circuit.Circuit, error) {
	c.mu.Lock()
	guardChan := c.guardChan
	guardInfo := c.guardInfo
	guardRS := c.findRouterByIdentity(guardInfo.RSAIDDigest)
	c.mu.Unlock()
	if guardChan == nil {
		return nil, fmt.Errorf("tor: client closed")
	}

	// Family/subnet exclusion against the guard and (when it is a known relay)
	// the fixed third hop.
	chosen := []selectedRelay{}
	if gs, err := c.selectedGuard(ctx, guardRS); err == nil {
		chosen = append(chosen, gs)
	}
	if thirdRS := c.findRouterByIdentity(third.RSAIDDigest); thirdRS != nil {
		if md, err := c.microdesc(ctx, thirdRS); err == nil {
			chosen = append(chosen, selectedRelay{rs: thirdRS, md: md})
		}
	}
	middle, err := c.pickRelay(ctx, c.selector().SelectMiddle, chosen, nil)
	if err != nil {
		return nil, err
	}

	circ, err := circuit.New(guardChan, c.log)
	if err != nil {
		return nil, err
	}
	if err := circ.Build(ctx, []circuit.RelayInfo{guardInfo, toRelayInfo(middle.rs, middle.md), third}); err != nil {
		circ.Destroy()
		return nil, fmt.Errorf("tor: build onion circuit: %w", err)
	}
	return circ, nil
}

// onionControl demuxes circuit-level control cells for the rendezvous and
// introduction flows.
type onionControl struct {
	established chan struct{}
	rendezvous2 chan []byte
	introAck    chan uint16
	once        sync.Once
}

func newOnionControl() *onionControl {
	return &onionControl{
		established: make(chan struct{}, 1),
		rendezvous2: make(chan []byte, 1),
		introAck:    make(chan uint16, 1),
	}
}

func (oc *onionControl) handle(rc cell.RelayCell) {
	switch rc.Command {
	case cell.RelayRendezvousEstablished:
		trySignal(oc.established, struct{}{})
	case cell.RelayRendezvous2:
		select {
		case oc.rendezvous2 <- rc.Data:
		default:
		}
	case cell.RelayIntroduceAck:
		var status uint16
		if len(rc.Data) >= 2 {
			status = binary.BigEndian.Uint16(rc.Data[:2])
		}
		select {
		case oc.introAck <- status:
		default:
		}
	}
}

func trySignal[T any](ch chan T, v T) {
	select {
	case ch <- v:
	default:
	}
}

// Onion rendezvous retry budget. The rendezvous and introduction circuits are
// built on freshly selected middle relays, and the RENDEZVOUS2 reply depends on
// the service connecting to our rendezvous point — any of which can stall on a
// slow or dead relay. A bounded per-attempt timeout plus a retry on a fresh path
// keeps one bad path from burning the whole deadline, mirroring what a full tor
// client does with adaptive circuit-build timeouts.
const (
	onionRendezvousAttempts   = 3
	onionRendezvousPerAttempt = 40 * time.Second
)

// buildOnionCircuitWithRetry runs buildOnionCircuit under a bounded per-attempt
// timeout, retrying on a fresh path until it succeeds, the attempt budget is
// exhausted, or the parent context ends. Each failed attempt tears its own
// circuits down internally, so no circuit leaks across retries.
func (c *Client) buildOnionCircuitWithRetry(ctx context.Context, desc *onion.Descriptor, subcred []byte) (*circuit.Circuit, error) {
	var lastErr error
	for attempt := 1; attempt <= onionRendezvousAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, err
		}
		attemptCtx, cancel := context.WithTimeout(ctx, onionRendezvousPerAttempt)
		circ, err := c.buildOnionCircuit(attemptCtx, desc, subcred)
		cancel()
		if err == nil {
			return circ, nil
		}
		lastErr = err
		c.log.Debug("onion: rendezvous attempt failed; retrying on a fresh path",
			"attempt", attempt, "max", onionRendezvousAttempts, "err", err)
	}
	return nil, lastErr
}

// buildOnionCircuit performs the full introduction + rendezvous handshake and
// returns a circuit joined end-to-end with the onion service, ready for streams.
// The caller (dialOnionViaDescriptor) pools it and opens the first stream.
func (c *Client) buildOnionCircuit(ctx context.Context, desc *onion.Descriptor, subcred []byte) (*circuit.Circuit, error) {
	// 1. Establish a rendezvous point.
	rpInfo, err := c.pickRendezvousPoint(ctx)
	if err != nil {
		return nil, err
	}
	rendCirc, err := c.buildCircuitVia(ctx, rpInfo)
	if err != nil {
		return nil, fmt.Errorf("tor: rendezvous circuit: %w", err)
	}
	rendCtl := newOnionControl()
	rendCirc.SetControlHandler(rendCtl.handle)

	cookie := make([]byte, 20)
	if _, err := rand.Read(cookie); err != nil {
		rendCirc.Destroy()
		return nil, err
	}
	const rpHop = 2
	if err := rendCirc.SendRelayToHop(rpHop, cell.RelayCell{Command: cell.RelayEstablishRendezvous, Data: cookie}); err != nil {
		rendCirc.Destroy()
		return nil, fmt.Errorf("tor: ESTABLISH_RENDEZVOUS: %w", err)
	}
	if err := waitSignal(ctx, rendCtl.established); err != nil {
		rendCirc.Destroy()
		return nil, fmt.Errorf("tor: RENDEZVOUS_ESTABLISHED: %w", err)
	}

	// 2. Introduce via an intro point.
	rpLinkSpecs, err := rpInfo.LinkSpecifiers()
	if err != nil {
		rendCirc.Destroy()
		return nil, err
	}
	state, err := c.introduce(ctx, desc, subcred, cookie, rpInfo.NtorOnionKey, rpLinkSpecs)
	if err != nil {
		rendCirc.Destroy()
		return nil, err
	}

	// 3. Await RENDEZVOUS2 and finish hs_ntor.
	var rend2 []byte
	select {
	case rend2 = <-rendCtl.rendezvous2:
	case <-ctx.Done():
		rendCirc.Destroy()
		return nil, ctx.Err()
	}
	serverPK, auth, ok := onion.ParseRendezvous2(rend2)
	if !ok {
		rendCirc.Destroy()
		return nil, fmt.Errorf("tor: malformed RENDEZVOUS2")
	}
	seed, err := state.Finish(serverPK, auth)
	if err != nil {
		rendCirc.Destroy()
		return nil, fmt.Errorf("tor: rendezvous handshake: %w", err)
	}

	df, db, kf, kb := torcrypto.HSNtorExpandKeys(seed)
	if err := rendCirc.AddRendezvousHop(df, db, kf, kb); err != nil {
		rendCirc.Destroy()
		return nil, err
	}
	c.log.Debug("rendezvous joined with onion service")
	return rendCirc, nil
}

// introduce builds an intro circuit and sends INTRODUCE1, returning the
// client-side hs_ntor state for finishing at rendezvous.
func (c *Client) introduce(ctx context.Context, desc *onion.Descriptor, subcred, cookie, rpNtorKey, rpLinkSpecs []byte) (*torcrypto.HSNtorClient, error) {
	var lastErr error
	for _, ip := range desc.IntroPoints {
		ls, err := onion.ParseLinkSpecifiers(ip.LinkSpecifiers)
		if err != nil {
			lastErr = err
			continue
		}
		introInfo := circuit.RelayInfo{
			Nickname:     "intro",
			ORAddr:       ls.ORAddr,
			RSAIDDigest:  ls.RSAID,
			EdIdentity:   ls.EdID,
			NtorOnionKey: ip.OnionKey,
		}
		if len(introInfo.EdIdentity) != 32 {
			lastErr = fmt.Errorf("intro point missing ed identity")
			continue
		}

		introCirc, err := c.buildCircuitVia(ctx, introInfo)
		if err != nil {
			lastErr = err
			continue
		}
		introCtl := newOnionControl()
		introCirc.SetControlHandler(introCtl.handle)

		encKey, macKey, clientX, state, err := torcrypto.HSNtorClientIntro(ip.EncKey, ip.AuthKey, subcred)
		if err != nil {
			introCirc.Destroy()
			lastErr = err
			continue
		}
		plaintext := onion.BuildIntroduce1Plaintext(cookie, rpNtorKey, rpLinkSpecs)
		intro1, err := onion.BuildIntroduce1(ip.AuthKey, encKey, macKey, clientX, plaintext)
		if err != nil {
			introCirc.Destroy()
			lastErr = err
			continue
		}
		const introHop = 2
		if err := introCirc.SendRelayToHop(introHop, cell.RelayCell{Command: cell.RelayIntroduce1, Data: intro1}); err != nil {
			introCirc.Destroy()
			lastErr = err
			continue
		}
		select {
		case status := <-introCtl.introAck:
			if status != 0 {
				introCirc.Destroy()
				lastErr = fmt.Errorf("INTRODUCE_ACK status %d", status)
				continue
			}
			// Intro circuit can be torn down; the service now connects to the RP.
			introCirc.Destroy()
			return state, nil
		case <-ctx.Done():
			introCirc.Destroy()
			return nil, ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no usable intro points")
	}
	return nil, fmt.Errorf("tor: introduction failed: %w", lastErr)
}

func (c *Client) pickRendezvousPoint(ctx context.Context) (circuit.RelayInfo, error) {
	c.mu.Lock()
	guardRS := c.findRouterByIdentity(c.guardInfo.RSAIDDigest)
	c.mu.Unlock()
	rp, err := c.selector().SelectMiddle(guardRS)
	if err != nil {
		return circuit.RelayInfo{}, err
	}
	return c.relayInfo(ctx, rp)
}

func waitSignal(ctx context.Context, ch chan struct{}) error {
	timer := time.NewTimer(60 * time.Second)
	defer timer.Stop()
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return fmt.Errorf("timeout")
	}
}
