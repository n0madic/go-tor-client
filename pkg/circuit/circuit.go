// Package circuit builds and operates Tor circuits over a link channel: the
// ntor v1 CREATE2/EXTEND2 telescoping handshake, the per-hop onion crypto
// (persistent AES-128-CTR keystreams plus a rolling SHA-1 digest), the
// RELAY_EARLY budget, and inbound cell recognition/decryption.
package circuit

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/n0madic/go-tor-client/internal/byteutil"
	"github.com/n0madic/go-tor-client/pkg/cell"
	"github.com/n0madic/go-tor-client/pkg/torcrypto"
)

// Link is the subset of a link channel a circuit needs: cell I/O and circuit-ID
// allocation. *channel.Channel satisfies it. AllocCircuit also returns a done
// channel the link closes when the circuit is freed or the channel dies, so the
// receive loop can stop without the link ever closing the inbox.
type Link interface {
	SendCell(cell.Cell) error
	AllocCircuit() (id uint32, inbox <-chan *cell.Cell, done <-chan struct{}, err error)
	FreeCircuit(uint32)
}

// Handshake type identifiers for CREATE2/EXTEND2 (tor-spec §5.1).
const (
	handshakeTypeNtor = 0x0002

	// maxRelayEarly bounds the RELAY_EARLY cells per circuit (tor-spec §5.6).
	maxRelayEarly = 8

	// Circuit-level flow control (tor-spec §7.3).
	circWindowStart     = 1000
	circWindowIncrement = 100

	// sendmeVersionAuth is the authenticated SENDME version (prop289).
	sendmeVersionAuth = 0x01
)

// Errors returned by circuit operations.
var (
	ErrCircuitClosed     = errors.New("circuit: closed")
	ErrRelayEarlyExpired = errors.New("circuit: RELAY_EARLY budget exhausted")
	ErrDestroyed         = errors.New("circuit: destroyed by relay")
)

// hop holds one relay's negotiated crypto state.
type hop struct {
	info      RelayInfo
	fwdCipher cipher.Stream
	bwdCipher cipher.Stream
	fwdDigest *torcrypto.RunningDigest
	bwdDigest *torcrypto.RunningDigest
}

// Circuit is a multi-hop Tor circuit over a single link channel.
type Circuit struct {
	ch       Link
	id       uint32
	inbox    <-chan *cell.Cell
	linkDone <-chan struct{} // closed by the link when this circuit is freed/dead
	log      *slog.Logger

	mu              sync.Mutex
	hops            []*hop
	relayEarlyCount int
	closed          bool
	closeErr        error

	// Ordered-write turnstile. Each relay cell claims a monotonic ticket
	// (sendNext) in the same c.mu section that advances its forward crypto, so
	// ticket order == encryption order. writeAtTurn then performs the blocking
	// network write outside c.mu, gated so writes happen in ticket order — a
	// stalled write can no longer block the inbound decrypt path (which needs
	// c.mu). sendNext is guarded by c.mu; sendTurn by sendMu. The claim never
	// touches sendMu, so no sendMu→c.mu ordering exists (no deadlock).
	sendMu   sync.Mutex
	sendCond *sync.Cond // sync.NewCond(&c.sendMu)
	sendNext uint64     // next ticket to hand out; guarded by c.mu
	sendTurn uint64     // ticket currently cleared to write; guarded by sendMu

	createdCh  chan []byte
	extendedCh chan []byte
	destroyed  chan struct{}

	// Circuit-level flow control. circPkgTokens is a cancellable semaphore of
	// outbound RELAY_DATA permits; circDeliverWindow counts inbound data cells
	// toward the next SENDME (guarded by mu).
	circPkgTokens     chan struct{}
	circDeliverWindow int

	// onStreamCell receives decrypted relay cells the circuit does not consume
	// itself (stream-level traffic and circuit SENDMEs). The stream layer sets
	// it via SetStreamHandler.
	onStreamCell func(rc cell.RelayCell)

	// onControlCell receives circuit-level (StreamID 0) relay cells the circuit
	// does not consume itself — used by the onion layer for rendezvous and
	// introduction control cells.
	onControlCell func(rc cell.RelayCell)
}

// New allocates a fresh circuit ID on the channel and starts its receive loop.
// The circuit has no hops yet; call Create then Extend.
func New(ch Link, log *slog.Logger) (*Circuit, error) {
	if log == nil {
		log = slog.Default()
	}
	id, inbox, done, err := ch.AllocCircuit()
	if err != nil {
		return nil, fmt.Errorf("circuit: alloc id: %w", err)
	}
	c := &Circuit{
		ch:                ch,
		id:                id,
		inbox:             inbox,
		linkDone:          done,
		log:               log,
		createdCh:         make(chan []byte, 1),
		extendedCh:        make(chan []byte, 1),
		destroyed:         make(chan struct{}),
		circPkgTokens:     byteutil.MakeTokens(circWindowStart),
		circDeliverWindow: circWindowStart,
	}
	c.sendCond = sync.NewCond(&c.sendMu)
	go c.recvLoop()
	return c, nil
}

// ID returns the circuit's ID on its channel.
func (c *Circuit) ID() uint32 { return c.id }

// Closed reports whether the circuit has been torn down.
func (c *Circuit) Closed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// NumHops returns the number of established hops.
func (c *Circuit) NumHops() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.hops)
}

// SetStreamHandler installs the callback for stream-level relay cells.
func (c *Circuit) SetStreamHandler(fn func(rc cell.RelayCell)) {
	c.mu.Lock()
	c.onStreamCell = fn
	c.mu.Unlock()
}

// SetControlHandler installs the callback for circuit-level (StreamID 0) relay
// cells not consumed by the circuit itself (RENDEZVOUS2, RENDEZVOUS_ESTABLISHED,
// INTRODUCE_ACK, ...).
func (c *Circuit) SetControlHandler(fn func(rc cell.RelayCell)) {
	c.mu.Lock()
	c.onControlCell = fn
	c.mu.Unlock()
}

// AddRendezvousHop appends a virtual hop for an onion service's end-to-end
// crypto on a joined rendezvous circuit: AES-256-CTR keystreams (Kf/Kb) and
// SHA3-256 running digests (Df/Db).
func (c *Circuit) AddRendezvousHop(df, db, kf, kb []byte) error {
	fwd, err := torcrypto.NewCTR(kf)
	if err != nil {
		return fmt.Errorf("circuit: rend fwd cipher: %w", err)
	}
	bwd, err := torcrypto.NewCTR(kb)
	if err != nil {
		return fmt.Errorf("circuit: rend bwd cipher: %w", err)
	}
	c.mu.Lock()
	c.hops = append(c.hops, &hop{
		fwdCipher: fwd,
		bwdCipher: bwd,
		fwdDigest: torcrypto.NewRunningDigestSHA3(df),
		bwdDigest: torcrypto.NewRunningDigestSHA3(db),
	})
	c.mu.Unlock()
	return nil
}

// SendRelayToHop sends a relay cell to a specific hop index (used to address
// the rendezvous point rather than the exit).
func (c *Circuit) SendRelayToHop(hopIdx int, rc cell.RelayCell) error {
	return c.sendRelay(hopIdx, rc, false)
}

// Build creates the first hop and extends through the remaining relays.
func (c *Circuit) Build(ctx context.Context, path []RelayInfo) error {
	if len(path) == 0 {
		return errors.New("circuit: empty path")
	}
	if err := c.Create(ctx, path[0]); err != nil {
		return err
	}
	for _, r := range path[1:] {
		if err := c.Extend(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

// Create performs the ntor handshake with the first hop via CREATE2/CREATED2.
func (c *Circuit) Create(ctx context.Context, first RelayInfo) error {
	clientData, state, err := torcrypto.NtorClientHandshake(first.RSAIDDigest, first.NtorOnionKey)
	if err != nil {
		return fmt.Errorf("circuit: ntor init: %w", err)
	}

	payload := byteutil.NewWriter(4 + len(clientData)).
		U16(handshakeTypeNtor).
		U16(uint16(len(clientData))).
		Write(clientData).
		Bytes()

	if err := c.ch.SendCell(cell.Cell{CircID: c.id, Command: cell.CmdCreate2, Payload: payload}); err != nil {
		return fmt.Errorf("circuit: send CREATE2: %w", err)
	}

	select {
	case hdata := <-c.createdCh:
		keys, err := state.Complete(hdata, torcrypto.NtorKeyMaterialLen)
		if err != nil {
			return fmt.Errorf("circuit: CREATED2: %w", err)
		}
		return c.addHop(first, keys)
	case <-ctx.Done():
		return ctx.Err()
	case <-c.destroyed:
		return ErrDestroyed
	}
}

// Extend telescopes the circuit one hop further via an EXTEND2 in a RELAY_EARLY
// cell, completing with EXTENDED2 from the current last hop.
func (c *Circuit) Extend(ctx context.Context, next RelayInfo) error {
	c.mu.Lock()
	lastHop := len(c.hops) - 1
	c.mu.Unlock()
	if lastHop < 0 {
		return errors.New("circuit: cannot extend before Create")
	}

	clientData, state, err := torcrypto.NtorClientHandshake(next.RSAIDDigest, next.NtorOnionKey)
	if err != nil {
		return fmt.Errorf("circuit: ntor init: %w", err)
	}
	specs, err := next.linkSpecifiers()
	if err != nil {
		return err
	}

	body := byteutil.NewWriter(len(specs) + 4 + len(clientData)).
		Write(specs).
		U16(handshakeTypeNtor).
		U16(uint16(len(clientData))).
		Write(clientData).
		Bytes()

	if err := c.sendRelay(lastHop, cell.RelayCell{Command: cell.RelayExtend2, Data: body}, true); err != nil {
		return fmt.Errorf("circuit: send EXTEND2: %w", err)
	}

	select {
	case hdata := <-c.extendedCh:
		keys, err := state.Complete(hdata, torcrypto.NtorKeyMaterialLen)
		if err != nil {
			return fmt.Errorf("circuit: EXTENDED2: %w", err)
		}
		return c.addHop(next, keys)
	case <-ctx.Done():
		return ctx.Err()
	case <-c.destroyed:
		return ErrDestroyed
	}
}

func (c *Circuit) addHop(info RelayInfo, keyMaterial []byte) error {
	rk, ok := torcrypto.SplitNtorKeys(keyMaterial)
	if !ok {
		return errors.New("circuit: short ntor key material")
	}
	fwd, err := torcrypto.NewCTR(rk.Kf)
	if err != nil {
		return fmt.Errorf("circuit: fwd cipher: %w", err)
	}
	bwd, err := torcrypto.NewCTR(rk.Kb)
	if err != nil {
		return fmt.Errorf("circuit: bwd cipher: %w", err)
	}
	c.mu.Lock()
	c.hops = append(c.hops, &hop{
		info:      info,
		fwdCipher: fwd,
		bwdCipher: bwd,
		fwdDigest: torcrypto.NewRunningDigestSHA1(rk.Df),
		bwdDigest: torcrypto.NewRunningDigestSHA1(rk.Db),
	})
	c.mu.Unlock()
	return nil
}

// SendRelay sends a relay cell to the last (exit) hop.
func (c *Circuit) SendRelay(rc cell.RelayCell) error {
	c.mu.Lock()
	dest := len(c.hops) - 1
	c.mu.Unlock()
	if dest < 0 {
		return ErrCircuitClosed
	}
	return c.sendRelay(dest, rc, false)
}

// sendRelay encrypts a relay cell for destHop, layers the forward ciphers, claims
// an ordered-write ticket, then writes it via the turnstile. The encrypt + ticket
// claim happen under c.mu so per-hop forward crypto advances and the ticket is
// assigned in a single atomic step — the relay verifies the running digest over
// cells in arrival order, so on-wire order must equal encryption order, which the
// turnstile guarantees by writing strictly in ticket order. The blocking network
// write happens outside c.mu (in writeAtTurn), so a stalled write can no longer
// block the inbound decrypt path. Every early return is before the claim, so no
// path strands a ticket. A failed write means this hop's forward digest and
// ciphers are now irrecoverably ahead of the relay, so the circuit is failed and
// evicted from any pool rather than reused with corrupt crypto state.
func (c *Circuit) sendRelay(destHop int, rc cell.RelayCell, early bool) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return c.closeErr
	}
	if destHop >= len(c.hops) {
		c.mu.Unlock()
		return ErrCircuitClosed
	}
	if early {
		if c.relayEarlyCount >= maxRelayEarly {
			c.mu.Unlock()
			return ErrRelayEarlyExpired
		}
	}

	payload := c.encryptForwardLocked(destHop, rc)

	cmd := cell.CmdRelay
	if early {
		cmd = cell.CmdRelayEarly
		c.relayEarlyCount++
	}
	ticket := c.sendNext
	c.sendNext++
	c.mu.Unlock()

	return c.writeAtTurn(ticket, cell.Cell{CircID: c.id, Command: cmd, Payload: payload})
}

// writeAtTurn blocks until ticket is the turnstile's current turn, performs the
// network write (bounded by the channel's cellWriteTimeout), then advances the
// turn exactly once and wakes the next writer. It is shared by the caller path
// (sendRelay) and the detached circuit-level SENDME. The turn advances even if
// SendCell panics, so a stuck or failed write can never strand later tickets.
// c.fail (which takes c.mu) runs only after sendMu is released, so writeAtTurn
// never holds sendMu while taking c.mu — no reverse lock ordering.
func (c *Circuit) writeAtTurn(ticket uint64, cl cell.Cell) error {
	c.sendMu.Lock()
	for c.sendTurn != ticket {
		c.sendCond.Wait()
	}
	c.sendMu.Unlock()

	var err error
	func() {
		defer func() { // ALWAYS advance the turn, even on panic in SendCell.
			c.sendMu.Lock()
			c.sendTurn++
			c.sendCond.Broadcast()
			c.sendMu.Unlock()
		}()
		err = c.ch.SendCell(cl) // bounded by cellWriteTimeout
	}()

	if err != nil {
		c.fail(err) // AFTER sendMu released ⇒ never holds sendMu while taking c.mu
	}
	return err
}

// encryptForwardLocked builds a relay cell addressed to destHop: it zeroes the
// recognized and digest fields, advances destHop's forward digest, writes the
// digest, and layers every forward cipher from destHop down to hop 0. Must be
// called with c.mu held.
func (c *Circuit) encryptForwardLocked(destHop int, rc cell.RelayCell) []byte {
	rc.Recognized = 0
	rc.Digest = [4]byte{}
	payload := rc.Encode() // 509 bytes, digest+recognized zeroed

	c.hops[destHop].fwdDigest.Update(payload)
	snap := c.hops[destHop].fwdDigest.Snapshot()
	copy(payload[cell.RelayDigestOffset:cell.RelayDigestOffset+cell.RelayDigestLen], snap[:cell.RelayDigestLen])

	for i := destHop; i >= 0; i-- {
		c.hops[i].fwdCipher.XORKeyStream(payload, payload)
	}
	return payload
}

func (c *Circuit) recvLoop() {
	for {
		select {
		case raw, ok := <-c.inbox:
			if !ok {
				c.fail(ErrCircuitClosed)
				return
			}
			switch raw.Command {
			case cell.CmdCreated2:
				c.deliverHandshake(c.createdCh, parseLenPrefixed(raw.Payload))
			case cell.CmdRelay, cell.CmdRelayEarly:
				c.handleRelay(raw)
			case cell.CmdDestroy:
				c.fail(ErrDestroyed)
				return
			default:
				c.log.Debug("circuit: unexpected cell", "cmd", raw.Command, "circ", c.id)
			}
		case <-c.destroyed:
			return
		case <-c.linkDone:
			// The link freed this circuit or the whole channel died.
			c.fail(ErrCircuitClosed)
			return
		}
	}
}

func (c *Circuit) handleRelay(raw *cell.Cell) {
	c.mu.Lock()
	payload := append([]byte(nil), raw.Payload...)
	hopIdx, rc, ok := c.decryptInboundLocked(payload)
	var sendmeTag []byte
	if ok && rc.Command == cell.RelayData {
		// Snapshot the hop's backward digest right after committing this cell;
		// it is the authentication tag for the circuit-level SENDME.
		sendmeTag = c.hops[hopIdx].bwdDigest.Snapshot()
	}
	handler := c.onStreamCell
	control := c.onControlCell
	c.mu.Unlock()
	if !ok {
		c.log.Debug("circuit: unrecognized relay cell", "circ", c.id)
		return
	}

	switch rc.Command {
	case cell.RelayExtended2:
		c.deliverHandshake(c.extendedCh, parseLenPrefixed(rc.Data))
	case cell.RelayTruncated:
		c.fail(ErrDestroyed)
	case cell.RelaySendme:
		if rc.StreamID == 0 {
			c.creditPackageWindow(circWindowIncrement)
		} else if handler != nil {
			handler(rc)
		}
	case cell.RelayData:
		c.accountInboundData(hopIdx, sendmeTag)
		if handler != nil {
			handler(rc)
		}
	default:
		switch {
		case rc.StreamID == 0 && control != nil:
			control(rc)
		case handler != nil:
			handler(rc)
		default:
			c.log.Debug("circuit: dropped relay cell (no handler)", "cmd", rc.Command, "hop", hopIdx)
		}
	}
}

// accountInboundData decrements the circuit deliver window and, every
// circWindowIncrement cells, emits an authenticated circuit-level SENDME to the
// data source hop with the snapshot digest as its tag. It runs on recvLoop, so
// the encrypt + ticket claim stay synchronous under c.mu (ordered with all other
// sends), but the blocking wait→write→advance is detached to a goroutine — the
// receive loop must never block on a stalled write.
func (c *Circuit) accountInboundData(hopIdx int, tag []byte) {
	c.mu.Lock()
	c.circDeliverWindow--
	send := c.circDeliverWindow <= circWindowStart-circWindowIncrement
	if send {
		c.circDeliverWindow += circWindowIncrement
	}
	if !send {
		c.mu.Unlock()
		return
	}
	if c.closed || hopIdx >= len(c.hops) {
		c.mu.Unlock()
		return
	}
	body := encodeSendmeV1(tag)
	payload := c.encryptForwardLocked(hopIdx, cell.RelayCell{Command: cell.RelaySendme, Data: body})
	ticket := c.sendNext
	c.sendNext++
	c.mu.Unlock()

	cl := cell.Cell{CircID: c.id, Command: cell.CmdRelay, Payload: payload}
	go func() {
		if err := c.writeAtTurn(ticket, cl); err != nil {
			c.log.Debug("circuit: failed to send circuit SENDME", "circ", c.id, "err", err)
		}
	}()
}

// creditPackageWindow returns up to n outbound RELAY_DATA permits, capped at the
// channel's capacity (the window never exceeds circWindowStart).
func (c *Circuit) creditPackageWindow(n int) {
	for range n {
		select {
		case c.circPkgTokens <- struct{}{}:
		default:
			return
		}
	}
}

// SendData sends one RELAY_DATA cell to the exit hop, blocking until a
// circuit-level package-window permit is available or ctx is cancelled.
func (c *Circuit) SendData(ctx context.Context, streamID uint16, data []byte) error {
	select {
	case <-c.circPkgTokens:
	case <-ctx.Done():
		return ctx.Err()
	case <-c.destroyed:
		return ErrCircuitClosed
	}
	c.mu.Lock()
	dest := len(c.hops) - 1
	c.mu.Unlock()
	if dest < 0 {
		c.creditPackageWindow(1) // return the unused permit
		return ErrCircuitClosed
	}
	if err := c.sendRelay(dest, cell.RelayCell{Command: cell.RelayData, StreamID: streamID, Data: data}, false); err != nil {
		c.creditPackageWindow(1) // cell never reached the relay; reclaim the permit
		return err
	}
	return nil
}

// sendmeTagLen is the authenticated SENDME v1 digest length (20 bytes), used
// even for SHA3-256 rendezvous circuits (the snapshot is truncated).
const sendmeTagLen = 20

func encodeSendmeV1(tag []byte) []byte {
	d := tag
	if len(d) > sendmeTagLen {
		d = d[:sendmeTagLen]
	}
	return byteutil.NewWriter(3 + len(d)).
		Byte(sendmeVersionAuth).
		U16(uint16(len(d))).
		Write(d).
		Bytes()
}

// decryptInboundLocked peels backward cipher layers from hop 0 outward, looking
// for the hop at which the cell is recognized (recognized==0 and the rolling
// backward digest matches). It must be called with c.mu held.
func (c *Circuit) decryptInboundLocked(payload []byte) (int, cell.RelayCell, bool) {
	for i := range c.hops {
		c.hops[i].bwdCipher.XORKeyStream(payload, payload)

		if binary.BigEndian.Uint16(payload[cell.RelayRecognizedOffset:]) != 0 {
			continue
		}
		// Candidate: verify the digest on a copy with the digest field zeroed.
		var want [cell.RelayDigestLen]byte
		copy(want[:], payload[cell.RelayDigestOffset:cell.RelayDigestOffset+cell.RelayDigestLen])

		hashable := append([]byte(nil), payload...)
		for j := range cell.RelayDigestLen {
			hashable[cell.RelayDigestOffset+j] = 0
		}
		if !c.hops[i].bwdDigest.VerifyAndCommit(hashable, want[:]) {
			continue // false positive; keep peeling
		}
		rc, ok := cell.DecodeRelay(payload)
		return i, rc, ok
	}
	return 0, cell.RelayCell{}, false
}

func (c *Circuit) deliverHandshake(ch chan []byte, data []byte) {
	if data == nil {
		return
	}
	select {
	case ch <- data:
	default:
		c.log.Debug("circuit: dropped duplicate handshake response", "circ", c.id)
	}
}

func (c *Circuit) fail(err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.closeErr = err
	close(c.destroyed)
	c.mu.Unlock()
}

// Destroy tears down the circuit, sending a DESTROY cell to the first hop.
func (c *Circuit) Destroy() error {
	c.mu.Lock()
	already := c.closed
	c.mu.Unlock()
	if !already {
		_ = c.ch.SendCell(cell.Cell{CircID: c.id, Command: cell.CmdDestroy, Payload: []byte{0}})
	}
	c.fail(ErrCircuitClosed)
	c.ch.FreeCircuit(c.id)
	return nil
}

// LastHop returns the RelayInfo of the exit hop, or false if no hops exist.
func (c *Circuit) LastHop() (RelayInfo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.hops) == 0 {
		return RelayInfo{}, false
	}
	return c.hops[len(c.hops)-1].info, true
}

// parseLenPrefixed reads a 2-byte length followed by that many bytes (the
// HLEN|HDATA framing of CREATED2/EXTENDED2). It returns nil on malformed input.
func parseLenPrefixed(b []byte) []byte {
	r := byteutil.NewReader(b)
	n := int(r.U16())
	data := r.Bytes(n)
	if r.Err() {
		return nil
	}
	return append([]byte(nil), data...)
}
