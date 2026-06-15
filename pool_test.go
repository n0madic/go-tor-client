package tor

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/n0madic/go-tor-client/pkg/cell"
	"github.com/n0madic/go-tor-client/pkg/circuit"
	"github.com/n0madic/go-tor-client/pkg/directory"
)

func TestCircuitReusable(t *testing.T) {
	t.Parallel()
	now := time.Now()
	const maxDirty = 10 * time.Minute
	cases := []struct {
		name                     string
		born                     time.Time
		retired, closed, matches bool
		want                     bool
	}{
		{"fresh and matching", now, false, false, true, true},
		{"just within dirtiness", now.Add(-9 * time.Minute), false, false, true, true},
		{"port/host mismatch", now, false, false, false, false},
		{"expired", now.Add(-11 * time.Minute), false, false, true, false},
		{"retired", now, true, false, true, false},
		{"closed", now, false, true, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := circuitReusable(tc.born, now, maxDirty, tc.retired, tc.closed, tc.matches)
			if got != tc.want {
				t.Fatalf("circuitReusable = %v, want %v", got, tc.want)
			}
		})
	}
}

// fakeConn is a net.Conn whose only meaningful method is Close (counted).
type fakeConn struct {
	net.Conn
	closes int
}

func (f *fakeConn) Close() error { f.closes++; return nil }

func TestTrackedConnCloseReleasesStreamOnce(t *testing.T) {
	t.Parallel()
	c := newPoolTestClient()
	pc := &pooledCircuit{born: time.Now(), streams: 1} // circ nil: not retired/expired, never touched
	fc := &fakeConn{}
	tc := c.newTrackedConn(pc, fc)

	if err := tc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if fc.closes != 1 {
		t.Fatalf("underlying Close called %d times, want 1", fc.closes)
	}
	if pc.streams != 0 {
		t.Fatalf("streams = %d after Close, want 0", pc.streams)
	}

	// A second Close must be a no-op: no extra underlying close, no extra release.
	if err := tc.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if fc.closes != 1 {
		t.Fatalf("double Close called underlying again: %d", fc.closes)
	}
	if pc.streams != 0 {
		t.Fatalf("streams = %d after double Close, want 0", pc.streams)
	}
}

func TestNewIdentityRetiresAndDestroys(t *testing.T) {
	t.Parallel()
	link := &fakeLink{}
	t.Cleanup(link.closeAll)
	c := newPoolTestClient()

	idle := newPooledTest(t, link, "", 0)
	busy := newPooledTest(t, link, "", 1)
	c.clearnetPool = []*pooledCircuit{idle, busy}

	c.NewIdentity()

	if !idle.circ.Closed() {
		t.Error("idle circuit should be destroyed by NewIdentity")
	}
	if !busy.retired {
		t.Error("in-use circuit should be retired")
	}
	if busy.circ.Closed() {
		t.Error("in-use circuit must stay alive until its last stream closes")
	}
	if got := c.Stats().ClearnetCircuits; got != 1 {
		t.Fatalf("ClearnetCircuits = %d after NewIdentity, want 1 (idle reaped, busy retained)", got)
	}

	// Closing the retired circuit's last stream reaps it.
	c.releaseStream(busy)
	if !busy.circ.Closed() {
		t.Error("retired circuit should be destroyed once its last stream closes")
	}
	if got := c.Stats().ClearnetCircuits; got != 0 {
		t.Fatalf("ClearnetCircuits = %d after releasing busy, want 0", got)
	}
}

func TestAcquireClearnetReusesPortMatch(t *testing.T) {
	t.Parallel()
	link := &fakeLink{}
	t.Cleanup(link.closeAll)
	c := newPoolTestClient()

	pc := newPooledTest(t, link, "", 0)
	pc.exitMD = directory.Microdescriptor{ExitPolicy: directory.ExitPolicy{
		IsAccept: true,
		Ports:    []directory.PortRange{{Lo: 443, Hi: 443}},
	}}
	c.clearnetPool = []*pooledCircuit{pc}

	if got := c.acquireClearnet(80); got != nil {
		t.Fatal("port 80 must not reuse an accept-443-only exit")
	}
	if got := c.acquireClearnet(443); got != pc {
		t.Fatal("port 443 should reuse the pooled circuit")
	}
	if pc.streams != 1 {
		t.Fatalf("streams = %d after reuse, want 1", pc.streams)
	}
	if got := c.Stats().Reused; got != 1 {
		t.Fatalf("Reused = %d, want 1", got)
	}
}

func TestReapRemovesExpiredAndDeadIdle(t *testing.T) {
	t.Parallel()
	link := &fakeLink{}
	t.Cleanup(link.closeAll)
	c := newPoolTestClient()

	expired := newPooledTest(t, link, "", 0)
	expired.born = time.Now().Add(-11 * time.Minute)
	fresh := newPooledTest(t, link, "", 0)
	dead := newPooledTest(t, link, "", 0)
	dead.circ.Destroy() // mark closed
	busyExpired := newPooledTest(t, link, "", 1)
	busyExpired.born = time.Now().Add(-11 * time.Minute)
	c.clearnetPool = []*pooledCircuit{expired, fresh, dead, busyExpired}

	c.reap()

	remaining := map[*pooledCircuit]bool{}
	for _, pc := range c.clearnetPool {
		remaining[pc] = true
	}
	if remaining[expired] {
		t.Error("expired idle circuit should be reaped")
	}
	if remaining[dead] {
		t.Error("dead circuit should be reaped")
	}
	if !remaining[fresh] {
		t.Error("fresh idle circuit should be kept")
	}
	if !remaining[busyExpired] {
		t.Error("expired but in-use circuit should be kept (still has a stream)")
	}
	if !expired.circ.Closed() {
		t.Error("reaped circuit should be destroyed")
	}
}

// --- test seams ---

func newPoolTestClient() *Client {
	return &Client{
		maxDirty:  defaultMaxCircuitDirtiness,
		onionPool: make(map[string][]*pooledCircuit),
	}
}

// newPooledTest builds a pooledCircuit backed by a real circuit over a fake link,
// so destroy/reap paths exercise circuit.Destroy without any network.
func newPooledTest(t *testing.T, link *fakeLink, onionHost string, streams int) *pooledCircuit {
	t.Helper()
	circ, err := circuit.New(link, nil)
	if err != nil {
		t.Fatalf("circuit.New: %v", err)
	}
	return &pooledCircuit{
		circ:    circ,
		born:    time.Now(),
		onion:   onionHost,
		streams: streams,
	}
}

// fakeLink is a minimal circuit.Link for tests: it never delivers cells and
// records nothing, but lets circuits be created and destroyed.
type fakeLink struct {
	mu     sync.Mutex
	nextID uint32
	dones  []chan struct{}
}

func (l *fakeLink) SendCell(cell.Cell) error { return nil }

func (l *fakeLink) AllocCircuit() (uint32, <-chan *cell.Cell, <-chan struct{}, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.nextID++
	inbox := make(chan *cell.Cell)
	done := make(chan struct{})
	l.dones = append(l.dones, done)
	return l.nextID, inbox, done, nil
}

func (l *fakeLink) FreeCircuit(uint32) {}

// closeAll signals every circuit's done channel so the circuits' receive loops
// exit, avoiding leaked goroutines after the test.
func (l *fakeLink) closeAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, d := range l.dones {
		close(d)
	}
}
