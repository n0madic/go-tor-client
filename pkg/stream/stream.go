package stream

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/n0madic/go-tor-client/internal/byteutil"
	"github.com/n0madic/go-tor-client/pkg/cell"
)

// RELAY_END reason codes (tor-spec §6.3).
const (
	endReasonMisc           = 1
	endReasonResolveFailed  = 2
	endReasonConnectRefused = 3
	endReasonExitPolicy     = 4
	endReasonDestroy        = 5
	endReasonDone           = 6
	endReasonTimeout        = 7
	endReasonConnReset      = 11
)

// EndError reports that the exit closed (or refused) the stream with a non-DONE
// reason.
type EndError struct{ Reason byte }

func (e *EndError) Error() string {
	return fmt.Sprintf("stream: closed by exit (reason %d: %s)", e.Reason, endReasonString(e.Reason))
}

func endReasonString(r byte) string {
	switch r {
	case endReasonMisc:
		return "misc"
	case endReasonResolveFailed:
		return "resolve failed"
	case endReasonConnectRefused:
		return "connection refused"
	case endReasonExitPolicy:
		return "exit policy"
	case endReasonDestroy:
		return "destroyed"
	case endReasonDone:
		return "done"
	case endReasonTimeout:
		return "timeout"
	case endReasonConnReset:
		return "connection reset"
	default:
		return "unknown"
	}
}

// Stream is an application stream over a Tor circuit; it implements net.Conn.
type Stream struct {
	mgr *Manager
	id  uint16

	ctx    context.Context
	cancel context.CancelFunc

	readMu     sync.Mutex
	readChunks [][]byte // deque of arrived RELAY_DATA payloads (one per cell)
	readErr    error
	readSig    chan struct{}
	// consumedCells counts cells fully read by the application but not yet
	// acknowledged with a SENDME — flow control is consumption-based, so a slow
	// reader naturally back-pressures the sender (bounded buffering).
	consumedCells int

	connectCh chan error
	connected bool

	pkgTokens chan struct{} // stream-level package window permits

	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time

	closeOnce sync.Once
}

func newStream(m *Manager, id uint16) *Stream {
	ctx, cancel := context.WithCancel(context.Background())
	return &Stream{
		mgr:       m,
		id:        id,
		ctx:       ctx,
		cancel:    cancel,
		readSig:   make(chan struct{}, 1),
		connectCh: make(chan error, 1),
		pkgTokens: byteutil.MakeTokens(streamWindowStart),
	}
}

// handleCell processes an inbound stream-level relay cell from the dispatcher.
func (s *Stream) handleCell(rc cell.RelayCell) {
	switch rc.Command {
	case cell.RelayConnected:
		s.readMu.Lock()
		s.connected = true
		s.readMu.Unlock()
		select {
		case s.connectCh <- nil:
		default:
		}
	case cell.RelayData:
		s.onData(rc.Data)
	case cell.RelayEnd:
		reason := byte(endReasonMisc)
		if len(rc.Data) > 0 {
			reason = rc.Data[0]
		}
		s.onEnd(reason)
	case cell.RelaySendme:
		s.creditPackage(streamWindowIncrement)
	default:
		s.mgr.log.Debug("stream: unexpected cell", "id", s.id, "cmd", rc.Command)
	}
}

func (s *Stream) onData(data []byte) {
	if len(data) == 0 {
		return
	}
	s.readMu.Lock()
	if s.readErr != nil {
		// Stream already ended or was closed; drop post-END data instead of
		// buffering it unboundedly (a malicious/buggy exit could otherwise grow
		// readChunks without limit).
		s.readMu.Unlock()
		return
	}
	s.readChunks = append(s.readChunks, data)
	s.readMu.Unlock()
	s.signalRead()
}

// sendStreamSendme emits an unauthenticated (v0) stream-level SENDME, crediting
// the sender to deliver streamWindowIncrement more cells.
func (s *Stream) sendStreamSendme() {
	if err := s.mgr.circ.SendRelay(cell.RelayCell{Command: cell.RelaySendme, StreamID: s.id}); err != nil {
		s.mgr.log.Debug("stream: send SENDME failed", "id", s.id, "err", err)
	}
}

func (s *Stream) onEnd(reason byte) {
	s.readMu.Lock()
	if s.readErr == nil {
		if reason == endReasonDone {
			s.readErr = io.EOF
		} else {
			s.readErr = &EndError{Reason: reason}
		}
	}
	endErr := s.readErr
	s.readMu.Unlock()
	s.signalRead()

	// Unblock a pending Begin with the failure reason.
	select {
	case s.connectCh <- endErr:
	default:
	}
	s.cancel()
	// Drop the stream from the manager so no further inbound cells route to it
	// and its ID/slot are reclaimed; the application keeps its *Stream reference
	// (via the tracked conn) and can still drain any buffered data and Close().
	s.mgr.remove(s.id)
}

func (s *Stream) creditPackage(n int) {
	for range n {
		select {
		case s.pkgTokens <- struct{}{}:
		default:
			return
		}
	}
}

func (s *Stream) signalRead() {
	select {
	case s.readSig <- struct{}{}:
	default:
	}
}

// Read implements net.Conn. It returns buffered stream data, blocking until
// data arrives, the stream ends, or the read deadline passes.
func (s *Stream) Read(p []byte) (int, error) {
	for {
		s.readMu.Lock()
		if len(s.readChunks) > 0 {
			n, sendmes := s.drainLocked(p)
			s.readMu.Unlock()
			for range sendmes {
				s.sendStreamSendme()
			}
			return n, nil
		}
		err := s.readErr
		s.readMu.Unlock()
		if err != nil {
			return 0, err
		}

		timeout, stop := s.deadlineChan(true)
		select {
		case <-s.readSig:
		case <-timeout:
			stop()
			return 0, timeoutError{}
		case <-s.ctx.Done():
			stop()
			s.readMu.Lock()
			err := s.readErr
			hasData := len(s.readChunks) > 0
			s.readMu.Unlock()
			if hasData {
				continue
			}
			if err == nil {
				err = net.ErrClosed
			}
			return 0, err
		}
		stop()
	}
}

// drainLocked copies as much as fits into p from the chunk deque, counting each
// fully-consumed cell and returning how many stream SENDMEs to emit (one per
// streamWindowIncrement cells consumed). Must hold readMu.
func (s *Stream) drainLocked(p []byte) (n, sendmes int) {
	for n < len(p) && len(s.readChunks) > 0 {
		c := s.readChunks[0]
		k := copy(p[n:], c)
		n += k
		if k == len(c) {
			s.readChunks[0] = nil
			s.readChunks = s.readChunks[1:]
			s.consumedCells++
			if s.consumedCells >= streamWindowIncrement {
				s.consumedCells -= streamWindowIncrement
				sendmes++
			}
		} else {
			s.readChunks[0] = c[k:]
		}
	}
	return n, sendmes
}

// Write implements net.Conn, chunking p into RELAY_DATA cells and honoring both
// stream- and circuit-level package windows.
func (s *Stream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > cell.RelayDataLen {
			chunk = chunk[:cell.RelayDataLen]
		}

		// Acquire a stream-level permit.
		timeout, stop := s.deadlineChan(false)
		select {
		case <-s.pkgTokens:
		case <-timeout:
			stop()
			return total, timeoutError{}
		case <-s.ctx.Done():
			stop()
			return total, s.writeErr()
		}
		stop()

		ctx, cancel := s.writeContext()
		err := s.mgr.circ.SendData(ctx, s.id, chunk)
		cancel()
		if err != nil {
			return total, fmt.Errorf("stream: write: %w", err)
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (s *Stream) writeErr() error {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if s.readErr != nil && s.readErr != io.EOF {
		return s.readErr
	}
	return net.ErrClosed
}

// writeContext derives a context honoring the write deadline and stream
// lifetime for the circuit-level send.
func (s *Stream) writeContext() (context.Context, context.CancelFunc) {
	s.deadlineMu.Lock()
	dl := s.writeDeadline
	s.deadlineMu.Unlock()
	if dl.IsZero() {
		return context.WithCancel(s.ctx)
	}
	return context.WithDeadline(s.ctx, dl)
}

// Close sends RELAY_END and tears down the stream.
func (s *Stream) Close() error {
	s.closeOnce.Do(func() {
		_ = s.mgr.circ.SendRelay(cell.RelayCell{
			Command:  cell.RelayEnd,
			StreamID: s.id,
			Data:     []byte{endReasonDone},
		})
		s.readMu.Lock()
		if s.readErr == nil {
			s.readErr = net.ErrClosed
		}
		s.readMu.Unlock()
		s.signalRead()
		s.cancel()
		s.mgr.remove(s.id)
	})
	return nil
}

// deadlineChan returns a channel that fires at the configured deadline (nil if
// none) plus a stop function to release any timer.
func (s *Stream) deadlineChan(read bool) (<-chan time.Time, func()) {
	s.deadlineMu.Lock()
	dl := s.writeDeadline
	if read {
		dl = s.readDeadline
	}
	s.deadlineMu.Unlock()

	if dl.IsZero() {
		return nil, func() {}
	}
	d := time.Until(dl)
	if d <= 0 {
		ch := make(chan time.Time, 1)
		ch <- time.Now()
		return ch, func() {}
	}
	t := time.NewTimer(d)
	return t.C, func() { t.Stop() }
}

// net.Conn deadline methods.

func (s *Stream) SetDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	s.readDeadline = t
	s.writeDeadline = t
	s.deadlineMu.Unlock()
	s.signalRead()
	return nil
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	s.readDeadline = t
	s.deadlineMu.Unlock()
	s.signalRead()
	return nil
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	s.writeDeadline = t
	s.deadlineMu.Unlock()
	return nil
}

// LocalAddr and RemoteAddr satisfy net.Conn with synthetic Tor addresses.
func (s *Stream) LocalAddr() net.Addr  { return torAddr{role: "tor-client"} }
func (s *Stream) RemoteAddr() net.Addr { return torAddr{role: "tor-exit"} }

type torAddr struct{ role string }

func (torAddr) Network() string  { return "tor" }
func (a torAddr) String() string { return a.role }

// timeoutError implements net.Error with Timeout() == true.
type timeoutError struct{}

func (timeoutError) Error() string   { return "stream: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

var _ net.Conn = (*Stream)(nil)
var _ net.Error = timeoutError{}
