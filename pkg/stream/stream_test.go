package stream

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/n0madic/go-tor-client/pkg/cell"
)

// mockCarrier emulates a circuit's exit for stream tests.
type mockCarrier struct {
	mu          sync.Mutex
	handler     func(cell.RelayCell)
	sentRelay   []cell.RelayCell
	sentData    [][]byte
	autoConnect bool
}

func (m *mockCarrier) SetStreamHandler(fn func(cell.RelayCell)) { m.handler = fn }

func (m *mockCarrier) SendRelay(rc cell.RelayCell) error {
	m.mu.Lock()
	m.sentRelay = append(m.sentRelay, rc)
	m.mu.Unlock()
	if m.autoConnect && (rc.Command == cell.RelayBegin || rc.Command == cell.RelayBeginDir) {
		go m.inject(cell.RelayCell{Command: cell.RelayConnected, StreamID: rc.StreamID})
	}
	return nil
}

func (m *mockCarrier) SendData(_ context.Context, _ uint16, data []byte) error {
	m.mu.Lock()
	m.sentData = append(m.sentData, append([]byte(nil), data...))
	m.mu.Unlock()
	return nil
}

func (m *mockCarrier) inject(rc cell.RelayCell) { m.handler(rc) }

func (m *mockCarrier) relayCount(cmd cell.RelayCommand) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, rc := range m.sentRelay {
		if rc.Command == cmd {
			n++
		}
	}
	return n
}

func TestStreamConnectAndEcho(t *testing.T) {
	t.Parallel()
	mc := &mockCarrier{autoConnect: true}
	m := NewManager(mc, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s, err := m.Begin(ctx, "example.com:80")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	payload := []byte("GET / HTTP/1.0\r\n\r\n")
	if _, err := s.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	mc.mu.Lock()
	gotData := append([][]byte(nil), mc.sentData...)
	mc.mu.Unlock()
	if len(gotData) != 1 || !bytes.Equal(gotData[0], payload) {
		t.Fatalf("exit did not receive request data: %v", gotData)
	}

	// Echo a response back.
	resp := []byte("HTTP/1.0 200 OK\r\n\r\nhello")
	mc.inject(cell.RelayCell{Command: cell.RelayData, StreamID: s.id, Data: resp})

	buf := make([]byte, len(resp))
	if _, err := io.ReadFull(s, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(buf, resp) {
		t.Fatalf("read = %q, want %q", buf, resp)
	}
}

func TestStreamEndEOF(t *testing.T) {
	t.Parallel()
	mc := &mockCarrier{autoConnect: true}
	m := NewManager(mc, nil)
	s, err := m.Begin(context.Background(), "example.com:80")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	mc.inject(cell.RelayCell{Command: cell.RelayData, StreamID: s.id, Data: []byte("tail")})
	mc.inject(cell.RelayCell{Command: cell.RelayEnd, StreamID: s.id, Data: []byte{endReasonDone}})

	// Buffered data drains first, then EOF.
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, []byte("tail")) {
		t.Fatalf("data = %q, want tail", got)
	}
}

// TestStreamEndRemovesAndDropsLateData verifies that an exit-initiated RELAY_END
// drops the stream from the manager (no leak / stream-ID exhaustion) and that
// data arriving after the end is not buffered unboundedly.
func TestStreamEndRemovesAndDropsLateData(t *testing.T) {
	t.Parallel()
	mc := &mockCarrier{autoConnect: true}
	m := NewManager(mc, nil)
	s, err := m.Begin(context.Background(), "example.com:80")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	m.mu.Lock()
	_, registered := m.streams[s.id]
	m.mu.Unlock()
	if !registered {
		t.Fatal("stream not registered after Begin")
	}

	mc.inject(cell.RelayCell{Command: cell.RelayEnd, StreamID: s.id, Data: []byte{endReasonDone}})

	m.mu.Lock()
	_, present := m.streams[s.id]
	m.mu.Unlock()
	if present {
		t.Fatal("stream still in manager map after RELAY_END (leak)")
	}

	for range 100 {
		s.onData([]byte("late"))
	}
	s.readMu.Lock()
	n := len(s.readChunks)
	s.readMu.Unlock()
	if n != 0 {
		t.Fatalf("buffered %d post-END chunks, want 0", n)
	}
}

func TestStreamBeginRefused(t *testing.T) {
	t.Parallel()
	mc := &mockCarrier{} // no autoConnect
	m := NewManager(mc, nil)

	// Respond to BEGIN with END(exit policy) asynchronously.
	go func() {
		for {
			if mc.relayCount(cell.RelayBegin) > 0 {
				mc.mu.Lock()
				id := mc.sentRelay[0].StreamID
				mc.mu.Unlock()
				mc.inject(cell.RelayCell{Command: cell.RelayEnd, StreamID: id, Data: []byte{endReasonExitPolicy}})
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	_, err := m.Begin(context.Background(), "blocked.example:25")
	var endErr *EndError
	if !errors.As(err, &endErr) || endErr.Reason != endReasonExitPolicy {
		t.Fatalf("Begin err = %v, want EndError(exit policy)", err)
	}
}

// TestStreamBeginContextCanceledSendsEnd verifies that cancelling the context
// after BEGIN was sent (but before CONNECTED arrives) tears the half-open stream
// down with a RELAY_END and drops it from the manager, instead of leaking it.
func TestStreamBeginContextCanceledSendsEnd(t *testing.T) {
	t.Parallel()
	mc := &mockCarrier{} // no autoConnect: BEGIN never completes
	m := NewManager(mc, nil)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			if mc.relayCount(cell.RelayBegin) > 0 {
				cancel()
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	s, err := m.Begin(ctx, "example.com:80")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Begin err = %v, want context.Canceled", err)
	}
	if s != nil {
		t.Fatal("Begin returned a stream despite cancellation")
	}
	if got := mc.relayCount(cell.RelayEnd); got != 1 {
		t.Fatalf("RELAY_END after cancellation = %d, want 1", got)
	}
	m.mu.Lock()
	n := len(m.streams)
	m.mu.Unlock()
	if n != 0 {
		t.Fatalf("manager still tracks %d streams after cancellation, want 0", n)
	}
}

func TestStreamConsumptionSendme(t *testing.T) {
	t.Parallel()
	mc := &mockCarrier{autoConnect: true}
	m := NewManager(mc, nil)
	s, err := m.Begin(context.Background(), "example.com:80")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	// Deliver streamWindowIncrement data cells. Flow control is now
	// consumption-based, so no SENDME should be sent before the app reads.
	for range streamWindowIncrement {
		mc.inject(cell.RelayCell{Command: cell.RelayData, StreamID: s.id, Data: []byte{0x01}})
	}
	if got := mc.relayCount(cell.RelaySendme); got != 0 {
		t.Fatalf("SENDME before consumption = %d, want 0 (backpressure)", got)
	}

	// Reading all of it (one full cell at a time) triggers exactly one SENDME.
	buf := make([]byte, 1)
	for range streamWindowIncrement {
		if _, err := io.ReadFull(s, buf); err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	if got := mc.relayCount(cell.RelaySendme); got != 1 {
		t.Fatalf("stream SENDME after consuming a window = %d, want 1", got)
	}
}

func TestStreamReadDeadline(t *testing.T) {
	t.Parallel()
	mc := &mockCarrier{autoConnect: true}
	m := NewManager(mc, nil)
	s, err := m.Begin(context.Background(), "example.com:80")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	s.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 8)
	_, err = s.Read(buf)
	var ne interface{ Timeout() bool }
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("Read err = %v, want timeout", err)
	}
}
