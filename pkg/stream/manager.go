// Package stream multiplexes application streams over a single Tor circuit:
// RELAY_BEGIN/CONNECTED/DATA/END exchange, stream-ID allocation, and
// stream-level flow control via SENDME cells. Each stream is exposed as a
// net.Conn.
package stream

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/n0madic/go-tor-client/internal/byteutil"
	"github.com/n0madic/go-tor-client/pkg/cell"
)

// Stream-level flow control windows (tor-spec §7.3).
const (
	streamWindowStart     = 500
	streamWindowIncrement = 50
)

// RELAY_BEGIN flags (tor-spec §6.2). Zero means default IPv4 connectivity.
const beginFlagIPv6OK = 1

// Carrier is the subset of *circuit.Circuit the stream layer needs.
type Carrier interface {
	SendRelay(rc cell.RelayCell) error
	SendData(ctx context.Context, streamID uint16, data []byte) error
	SetStreamHandler(fn func(rc cell.RelayCell))
}

// Manager multiplexes streams over one circuit.
type Manager struct {
	circ Carrier
	log  *slog.Logger

	mu      sync.Mutex
	streams map[uint16]*Stream
	nextID  uint16
}

// NewManager wires a stream manager to a circuit and registers its cell handler.
func NewManager(circ Carrier, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	m := &Manager{
		circ:    circ,
		log:     log,
		streams: make(map[uint16]*Stream),
		nextID:  1,
	}
	circ.SetStreamHandler(m.dispatch)
	return m
}

// Begin opens a stream to addr ("host:port") through the circuit's exit.
func (m *Manager) Begin(ctx context.Context, addr string) (*Stream, error) {
	body := byteutil.NewWriter(len(addr) + 5).
		Write([]byte(addr)).
		Byte(0). // null-terminated ADDRPORT
		U32(beginFlagIPv6OK).
		Bytes()
	return m.begin(ctx, cell.RelayBegin, body)
}

// BeginDir opens a directory stream (BEGIN_DIR) to the circuit's last hop, used
// to tunnel directory requests after bootstrap.
func (m *Manager) BeginDir(ctx context.Context) (*Stream, error) {
	return m.begin(ctx, cell.RelayBeginDir, nil)
}

func (m *Manager) begin(ctx context.Context, command cell.RelayCommand, body []byte) (*Stream, error) {
	s, err := m.newStream()
	if err != nil {
		return nil, err
	}
	if err := m.circ.SendRelay(cell.RelayCell{Command: command, StreamID: s.id, Data: body}); err != nil {
		m.remove(s.id)
		return nil, fmt.Errorf("stream: send BEGIN: %w", err)
	}

	select {
	case err := <-s.connectCh:
		if err != nil {
			m.remove(s.id)
			return nil, err
		}
		return s, nil
	case <-ctx.Done():
		// BEGIN was already sent; tell the relay to discard the now-orphaned
		// half-open stream with a RELAY_END instead of leaving it to time out
		// (and stop a late CONNECTED/DATA arriving as "unknown stream" traffic).
		_ = m.circ.SendRelay(cell.RelayCell{Command: cell.RelayEnd, StreamID: s.id, Data: []byte{endReasonDone}})
		m.remove(s.id)
		return nil, ctx.Err()
	}
}

func (m *Manager) newStream() (*Stream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for range 0x10000 {
		id := m.nextID
		m.nextID++
		if m.nextID == 0 {
			m.nextID = 1
		}
		if id == 0 {
			continue
		}
		if _, exists := m.streams[id]; exists {
			continue
		}
		s := newStream(m, id)
		m.streams[id] = s
		return s, nil
	}
	return nil, errors.New("stream: no free stream IDs")
}

func (m *Manager) remove(id uint16) {
	m.mu.Lock()
	delete(m.streams, id)
	m.mu.Unlock()
}

// dispatch routes a decrypted stream-level relay cell to its stream.
func (m *Manager) dispatch(rc cell.RelayCell) {
	if rc.StreamID == 0 {
		return // circuit-level cells are handled in the circuit layer
	}
	m.mu.Lock()
	s := m.streams[rc.StreamID]
	m.mu.Unlock()
	if s == nil {
		m.log.Debug("stream: cell for unknown stream", "id", rc.StreamID, "cmd", rc.Command)
		return
	}
	s.handleCell(rc)
}
