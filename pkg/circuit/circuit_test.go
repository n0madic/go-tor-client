package circuit

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log/slog"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/n0madic/go-tor-client/pkg/cell"
	"github.com/n0madic/go-tor-client/pkg/torcrypto"
)

// initSend wires up the ordered-write turnstile cond for circuits built directly
// in tests (bypassing New, which normally initializes it).
func (c *Circuit) initSend() { c.sendCond = sync.NewCond(&c.sendMu) }

// waitFor polls cond until it returns true or the timeout elapses.
func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return cond()
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// hopKeys is one hop's symmetric key set, shared by the client-side circuit and
// the relay-side model in these tests.
type hopKeys struct {
	kf, kb, df, db []byte
}

func newHopKeys() hopKeys {
	return hopKeys{kf: randBytes(16), kb: randBytes(16), df: randBytes(20), db: randBytes(20)}
}

// relayModel mirrors one relay's view of the onion crypto: a forward cipher to
// decrypt client->relay cells and a backward cipher to encrypt relay->client.
type relayModel struct {
	fwdCipher cipher.Stream
	bwdCipher cipher.Stream
	fwdDigest *torcrypto.RunningDigest
	bwdDigest *torcrypto.RunningDigest
}

// addHopsAndRelays appends one client hop and its mirror relay model per key,
// sharing the symmetric material so the relay side can decrypt/verify.
func addHopsAndRelays(c *Circuit, keys []hopKeys) []*relayModel {
	relays := make([]*relayModel, len(keys))
	for i, k := range keys {
		cFwd, _ := torcrypto.NewCTR(k.kf)
		cBwd, _ := torcrypto.NewCTR(k.kb)
		c.hops = append(c.hops, &hop{
			fwdCipher: cFwd,
			bwdCipher: cBwd,
			fwdDigest: torcrypto.NewRunningDigestSHA1(k.df),
			bwdDigest: torcrypto.NewRunningDigestSHA1(k.db),
		})
		rFwd, _ := torcrypto.NewCTR(k.kf)
		rBwd, _ := torcrypto.NewCTR(k.kb)
		relays[i] = &relayModel{
			fwdCipher: rFwd,
			bwdCipher: rBwd,
			fwdDigest: torcrypto.NewRunningDigestSHA1(k.df),
			bwdDigest: torcrypto.NewRunningDigestSHA1(k.db),
		}
	}
	return relays
}

func buildClientAndRelays(t *testing.T, keys []hopKeys) (*Circuit, []*relayModel) {
	t.Helper()
	c := &Circuit{log: slog.Default()}
	c.initSend()
	return c, addHopsAndRelays(c, keys)
}

// relayDecodeForward models a cell traveling from the client to destHop: each
// hop 0..destHop peels its forward layer, and destHop verifies the digest.
func relayDecodeForward(t *testing.T, relays []*relayModel, destHop int, payload []byte) cell.RelayCell {
	t.Helper()
	for i := 0; i <= destHop; i++ {
		relays[i].fwdCipher.XORKeyStream(payload, payload)
	}
	if got := binary.BigEndian.Uint16(payload[cell.RelayRecognizedOffset:]); got != 0 {
		t.Fatalf("forward: recognized = %d at destHop %d, want 0", got, destHop)
	}
	var want [cell.RelayDigestLen]byte
	copy(want[:], payload[cell.RelayDigestOffset:])
	hashable := append([]byte(nil), payload...)
	for j := range cell.RelayDigestLen {
		hashable[cell.RelayDigestOffset+j] = 0
	}
	if !relays[destHop].fwdDigest.VerifyAndCommit(hashable, want[:]) {
		t.Fatalf("forward: digest mismatch at destHop %d", destHop)
	}
	rc, ok := cell.DecodeRelay(payload)
	if !ok {
		t.Fatalf("forward: DecodeRelay failed")
	}
	return rc
}

// relayOriginateBackward models destHop originating a cell back to the client.
func relayOriginateBackward(relays []*relayModel, srcHop int, rc cell.RelayCell) []byte {
	rc.Recognized = 0
	rc.Digest = [4]byte{}
	payload := rc.Encode()
	relays[srcHop].bwdDigest.Update(payload)
	snap := relays[srcHop].bwdDigest.Snapshot()
	copy(payload[cell.RelayDigestOffset:cell.RelayDigestOffset+cell.RelayDigestLen], snap[:cell.RelayDigestLen])
	for i := srcHop; i >= 0; i-- {
		relays[i].bwdCipher.XORKeyStream(payload, payload)
	}
	return payload
}

func TestOnionForwardRoundTrip(t *testing.T) {
	t.Parallel()
	keys := []hopKeys{newHopKeys(), newHopKeys(), newHopKeys()}
	c, relays := buildClientAndRelays(t, keys)

	// A sequence of cells to mixed destinations, exercising stream advancement.
	sends := []struct {
		dest int
		sid  uint16
		data []byte
	}{
		{2, 1, []byte("first to exit")},
		{1, 0, []byte("extend-style to middle")},
		{2, 1, []byte("second to exit")},
		{0, 0, []byte("to guard")},
		{2, 3, bytes.Repeat([]byte{0xa5}, 400)},
	}
	for n, s := range sends {
		c.mu.Lock()
		payload := c.encryptForwardLocked(s.dest, cell.RelayCell{Command: cell.RelayData, StreamID: s.sid, Data: s.data})
		c.mu.Unlock()

		rc := relayDecodeForward(t, relays, s.dest, payload)
		if rc.StreamID != s.sid {
			t.Fatalf("send %d: streamID = %d, want %d", n, rc.StreamID, s.sid)
		}
		if !bytes.Equal(rc.Data, s.data) {
			t.Fatalf("send %d: data mismatch", n)
		}
	}
}

func TestOnionBackwardRoundTrip(t *testing.T) {
	t.Parallel()
	keys := []hopKeys{newHopKeys(), newHopKeys(), newHopKeys()}
	c, relays := buildClientAndRelays(t, keys)

	sends := []struct {
		src  int
		data []byte
	}{
		{2, []byte("reply from exit")},
		{2, []byte("another from exit")},
		{1, []byte("from middle")},
		{0, []byte("from guard")},
	}
	for n, s := range sends {
		payload := relayOriginateBackward(relays, s.src, cell.RelayCell{Command: cell.RelayData, StreamID: 7, Data: s.data})

		c.mu.Lock()
		hopIdx, rc, ok := c.decryptInboundLocked(payload)
		c.mu.Unlock()
		if !ok {
			t.Fatalf("recv %d: not recognized", n)
		}
		if hopIdx != s.src {
			t.Fatalf("recv %d: recognized at hop %d, want %d", n, hopIdx, s.src)
		}
		if !bytes.Equal(rc.Data, s.data) {
			t.Fatalf("recv %d: data = %q, want %q", n, rc.Data, s.data)
		}
	}
}

// mockLink records sent cells and lets tests inject inbound cells. sent is
// mutex-guarded because the turnstile and the detached SENDME both call SendCell
// from different goroutines.
type mockLink struct {
	mu      sync.Mutex
	sent    []cell.Cell
	inbox   chan *cell.Cell
	done    chan struct{}
	sendErr error // when non-nil, SendCell returns it
}

func newMockLink() *mockLink {
	return &mockLink{inbox: make(chan *cell.Cell, 16), done: make(chan struct{})}
}

func (m *mockLink) SendCell(c cell.Cell) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, c)
	return m.sendErr
}

// sentCells returns a snapshot copy of the recorded cells under the lock.
func (m *mockLink) sentCells() []cell.Cell {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]cell.Cell(nil), m.sent...)
}

func (m *mockLink) AllocCircuit() (uint32, <-chan *cell.Cell, <-chan struct{}, error) {
	return 0x80000001, m.inbox, m.done, nil
}
func (m *mockLink) FreeCircuit(uint32) {}

func TestRelayEarlyBudget(t *testing.T) {
	t.Parallel()
	link := newMockLink()
	c := &Circuit{
		ch:         link,
		log:        slog.Default(),
		createdCh:  make(chan []byte, 1),
		extendedCh: make(chan []byte, 1),
		destroyed:  make(chan struct{}),
	}
	c.initSend()
	// One hop so sendRelay has a destination.
	k := newHopKeys()
	fwd, _ := torcrypto.NewCTR(k.kf)
	bwd, _ := torcrypto.NewCTR(k.kb)
	c.hops = append(c.hops, &hop{
		fwdCipher: fwd, bwdCipher: bwd,
		fwdDigest: torcrypto.NewRunningDigestSHA1(k.df),
		bwdDigest: torcrypto.NewRunningDigestSHA1(k.db),
	})

	for i := range maxRelayEarly {
		if err := c.sendRelay(0, cell.RelayCell{Command: cell.RelayData}, true); err != nil {
			t.Fatalf("early send %d: %v", i, err)
		}
	}
	if err := c.sendRelay(0, cell.RelayCell{Command: cell.RelayData}, true); err != ErrRelayEarlyExpired {
		t.Fatalf("9th early send: err = %v, want ErrRelayEarlyExpired", err)
	}
	// Non-early sends still work.
	if err := c.sendRelay(0, cell.RelayCell{Command: cell.RelayData}, false); err != nil {
		t.Fatalf("non-early send: %v", err)
	}
}

// TestSendRelayFailsCircuitOnWriteError verifies that a failed cell write tears
// the circuit down (so the pool evicts it) rather than leaving it open with
// forward crypto state silently ahead of the relay.
func TestSendRelayFailsCircuitOnWriteError(t *testing.T) {
	t.Parallel()
	link := newMockLink()
	link.sendErr = errors.New("write failed")
	c := &Circuit{
		ch:         link,
		log:        slog.Default(),
		createdCh:  make(chan []byte, 1),
		extendedCh: make(chan []byte, 1),
		destroyed:  make(chan struct{}),
	}
	c.initSend()
	k := newHopKeys()
	fwd, _ := torcrypto.NewCTR(k.kf)
	bwd, _ := torcrypto.NewCTR(k.kb)
	c.hops = append(c.hops, &hop{
		fwdCipher: fwd, bwdCipher: bwd,
		fwdDigest: torcrypto.NewRunningDigestSHA1(k.df),
		bwdDigest: torcrypto.NewRunningDigestSHA1(k.db),
	})

	if err := c.SendRelay(cell.RelayCell{Command: cell.RelayData}); err == nil {
		t.Fatal("SendRelay should surface the write error")
	}
	if !c.Closed() {
		t.Fatal("circuit must be closed (pool-evicted) after a write error")
	}
}

// newLiveCircuit builds a circuit wired to link with len(keys) hops and a running
// recvLoop, plus the mirror relay models. Unlike buildClientAndRelays it can send
// and receive real cells through the mock link.
func newLiveCircuit(t *testing.T, link *mockLink, keys []hopKeys) (*Circuit, []*relayModel) {
	t.Helper()
	c := &Circuit{
		ch:                link,
		id:                0x80000001,
		inbox:             link.inbox,
		linkDone:          link.done,
		log:               slog.Default(),
		createdCh:         make(chan []byte, 1),
		extendedCh:        make(chan []byte, 1),
		destroyed:         make(chan struct{}),
		circDeliverWindow: circWindowStart,
	}
	c.initSend()
	relays := addHopsAndRelays(c, keys)
	go c.recvLoop()
	return c, relays
}

// TestSendRelayConcurrentTurnstile drives many concurrent SendRelay goroutines
// plus an inbound-data flood (exercising the detached circuit-level SENDME) and
// asserts wire order == encryption order: decoding the recorded cells in arrival
// order through the relay model must keep the forward running digest valid at
// every step. A reordering bug surfaces as a digest mismatch. It also asserts the
// turnstile fully drains (no stranded/leaked writeAtTurn goroutine).
func TestSendRelayConcurrentTurnstile(t *testing.T) {
	const (
		nForward   = 64
		nInbound   = 200                            // a multiple of the increment
		wantSendme = nInbound / circWindowIncrement // → 2 detached SENDMEs
	)
	baseGoroutines := runtime.NumGoroutine()

	keys := []hopKeys{newHopKeys(), newHopKeys(), newHopKeys()}
	link := newMockLink()
	c, relays := newLiveCircuit(t, link, keys)
	exit := len(c.hops) - 1

	// Pre-generate the inbound flood: backward RELAY_DATA cells originated at the
	// exit, in a fixed order the relay model and recvLoop both decrypt in lockstep.
	flood := make([]*cell.Cell, nInbound)
	for i := range flood {
		payload := relayOriginateBackward(relays, exit, cell.RelayCell{
			Command: cell.RelayData, StreamID: 1, Data: []byte{byte(i), byte(i >> 8)},
		})
		flood[i] = &cell.Cell{CircID: c.id, Command: cell.CmdRelay, Payload: payload}
	}

	var wg sync.WaitGroup
	wg.Add(nForward)
	for n := range nForward {
		go func(n int) {
			defer wg.Done()
			data := []byte{0xF0, byte(n), byte(n >> 8)}
			if err := c.SendRelay(cell.RelayCell{Command: cell.RelayData, StreamID: 2, Data: data}); err != nil {
				t.Errorf("forward send %d: %v", n, err)
			}
		}(n)
	}
	// Drive the inbound flood concurrently to exercise the detached SENDME writes.
	for _, raw := range flood {
		link.inbox <- raw
	}
	wg.Wait()

	// Wait until every claimed ticket (forward sends + detached SENDMEs) has been
	// written and the turnstile drained — sendTurn == sendNext proves no
	// writeAtTurn goroutine is stranded.
	readTurn := func() uint64 { c.sendMu.Lock(); defer c.sendMu.Unlock(); return c.sendTurn }
	readNext := func() uint64 { c.mu.Lock(); defer c.mu.Unlock(); return c.sendNext }
	if !waitFor(5*time.Second, func() bool {
		return readNext() == uint64(nForward+wantSendme) && readTurn() == readNext()
	}) {
		t.Fatalf("turnstile did not drain: turn=%d next=%d want next=%d",
			readTurn(), readNext(), nForward+wantSendme)
	}

	// Decode every recorded wire cell in arrival order. All target the exit, so the
	// relay forward digest must validate at each step (asserted inside
	// relayDecodeForward via t.Fatalf on mismatch).
	sent := link.sentCells()
	if len(sent) != nForward+wantSendme {
		t.Fatalf("recorded %d cells, want %d", len(sent), nForward+wantSendme)
	}
	var gotData, gotSendme int
	seen := make(map[uint16]bool)
	for i, cl := range sent {
		if cl.Command != cell.CmdRelay {
			t.Fatalf("cell %d: command = %v, want CmdRelay", i, cl.Command)
		}
		rc := relayDecodeForward(t, relays, exit, append([]byte(nil), cl.Payload...))
		switch rc.Command {
		case cell.RelayData:
			gotData++
			if len(rc.Data) == 3 && rc.Data[0] == 0xF0 {
				seen[uint16(rc.Data[1])|uint16(rc.Data[2])<<8] = true
			}
		case cell.RelaySendme:
			gotSendme++
		default:
			t.Fatalf("cell %d: unexpected relay command %v", i, rc.Command)
		}
	}
	if gotData != nForward {
		t.Fatalf("decoded %d data cells, want %d", gotData, nForward)
	}
	if gotSendme != wantSendme {
		t.Fatalf("decoded %d SENDME cells, want %d", gotSendme, wantSendme)
	}
	if len(seen) != nForward {
		t.Fatalf("saw %d distinct forward payloads, want %d", len(seen), nForward)
	}

	// Tearing the circuit down must let recvLoop and every detached SENDME exit —
	// the goroutine count must return to its pre-test baseline.
	c.Destroy()
	if !waitFor(2*time.Second, func() bool { return runtime.NumGoroutine() <= baseGoroutines+1 }) {
		t.Fatalf("goroutine leak: have %d, baseline %d", runtime.NumGoroutine(), baseGoroutines)
	}
}

// stuckLink blocks the first SendCell until released, modeling TCP backpressure;
// later writes return immediately.
type stuckLink struct {
	mu       sync.Mutex
	sent     []cell.Cell
	gotFirst bool
	entered  chan struct{} // closed when the first SendCell is reached
	release  chan error    // the first SendCell returns whatever is sent here
}

func newStuckLink() *stuckLink {
	return &stuckLink{entered: make(chan struct{}), release: make(chan error, 1)}
}

func (l *stuckLink) SendCell(c cell.Cell) error {
	l.mu.Lock()
	l.sent = append(l.sent, c)
	first := !l.gotFirst
	l.gotFirst = true
	l.mu.Unlock()
	if first {
		close(l.entered)
		return <-l.release
	}
	return nil
}

func (l *stuckLink) sentCells() []cell.Cell {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]cell.Cell(nil), l.sent...)
}

func (l *stuckLink) AllocCircuit() (uint32, <-chan *cell.Cell, <-chan struct{}, error) {
	return 0x80000001, nil, nil, nil
}
func (l *stuckLink) FreeCircuit(uint32) {}

// TestSendRelayTurnAdvancesOnStuckWrite verifies that a stalled (then failed)
// network write does not strand later writers: while the first ticket blocks in
// SendCell, follower tickets park in the turnstile; once the first write fails it
// advances the turn, fails the circuit, and every parked writer wakes and returns.
func TestSendRelayTurnAdvancesOnStuckWrite(t *testing.T) {
	const followers = 5
	link := newStuckLink()
	c := &Circuit{
		ch:         link,
		log:        slog.Default(),
		createdCh:  make(chan []byte, 1),
		extendedCh: make(chan []byte, 1),
		destroyed:  make(chan struct{}),
	}
	c.initSend()
	addHopsAndRelays(c, []hopKeys{newHopKeys()})

	// Ticket 0: blocks inside SendCell.
	first := make(chan error, 1)
	go func() {
		first <- c.SendRelay(cell.RelayCell{Command: cell.RelayData, Data: []byte("first")})
	}()
	select {
	case <-link.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first SendCell never entered")
	}

	// Followers claim tickets 1..N and park in the turnstile (turn still 0).
	var wg sync.WaitGroup
	wg.Add(followers)
	for i := range followers {
		go func(i int) {
			defer wg.Done()
			_ = c.SendRelay(cell.RelayCell{Command: cell.RelayData, Data: []byte{byte(i)}})
		}(i)
	}

	// Give the followers time to park, then confirm only the stuck first cell has
	// reached the wire — the turnstile is holding everyone else back.
	if !waitFor(2*time.Second, func() bool { return readNext(c) == uint64(1+followers) }) {
		t.Fatalf("not all tickets claimed: next=%d want %d", readNext(c), 1+followers)
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(link.sentCells()); n != 1 {
		t.Fatalf("expected only the stuck first cell on the wire, got %d", n)
	}

	// Fail the stuck write; ticket 0 advances the turn and fails the circuit.
	link.release <- errors.New("stuck write failed")

	select {
	case err := <-first:
		if err == nil {
			t.Fatal("first SendRelay must return the write error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first SendRelay did not return")
	}

	// Every parked follower must wake and return — a hang here means a stranded
	// ticket / deadlock.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("parked writers did not wake — stranded ticket / deadlock")
	}

	if !c.Closed() {
		t.Fatal("circuit must be closed after the stuck write failed")
	}
	// All tickets eventually flushed and the turnstile drained.
	c.sendMu.Lock()
	turn := c.sendTurn
	c.sendMu.Unlock()
	if turn != uint64(1+followers) {
		t.Fatalf("turnstile did not drain: turn=%d want %d", turn, 1+followers)
	}
}

// readNext reads the next ticket counter under c.mu.
func readNext(c *Circuit) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sendNext
}
