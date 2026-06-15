// Package channel implements a Tor link connection (an "OR connection") to a
// single relay: a TLS transport, the VERSIONS/CERTS/NETINFO link handshake for
// link protocol v4/v5, verification of the relay's Ed25519 identity, and
// multiplexed cell framing for the circuits running over it.
package channel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/n0madic/go-tor-client/internal/byteutil"
	"github.com/n0madic/go-tor-client/pkg/cell"
)

// Supported link protocol versions, highest preferred.
var supportedLinkVersions = []uint16{5, 4}

const (
	netinfoAddrIPv4 = 4
	netinfoAddrIPv6 = 6

	circuitInboxDepth = 256

	// cellWriteTimeout bounds a single cell write so a stalled peer (a full TCP
	// send window) cannot block a writer — and, since writes happen under the
	// circuit lock, the inbound demux path — indefinitely.
	cellWriteTimeout = 30 * time.Second
)

// circEntry is a circuit's inbound cell queue plus a done channel that is closed
// when the circuit is freed or the whole channel dies. The read pump selects on
// done so it can drop a torn-down circuit's in-flight cell instead of panicking
// on a closed inbox (a send-on-closed-channel race); the inbox itself is never
// closed.
type circEntry struct {
	inbox chan *cell.Cell
	done  chan struct{}
}

// Channel is a live link connection to one relay.
type Channel struct {
	conn net.Conn
	br   *bufio.Reader
	log  *slog.Logger

	writeMu sync.Mutex

	linkVersion uint16
	edIdentity  []byte // verified relay Ed25519 identity key

	mu       sync.Mutex
	circuits map[uint32]*circEntry
	closed   bool
	closeErr error
	done     chan struct{}
}

// Config tunes a channel Dial. The zero value is valid.
type Config struct {
	// ExpectedEd25519, when non-nil, must equal the relay's verified identity
	// key or Dial fails. Callers pass the identity from the consensus.
	ExpectedEd25519 []byte
	// Logger receives debug logs; defaults to slog.Default().
	Logger *slog.Logger
	// now overrides the clock for certificate validation in tests.
	now func() time.Time
}

// Dial connects to a relay at addr ("ip:port"), performs the TLS and link
// handshakes, verifies the relay identity, and returns a ready Channel.
func Dial(ctx context.Context, addr string, cfg Config) (*Channel, error) {
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	nowFn := cfg.now
	if nowFn == nil {
		nowFn = time.Now
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // Tor authenticates via CERTS, not the PKI.
		MinVersion:         tls.VersionTLS12,
	}
	dialer := &tls.Dialer{Config: tlsCfg}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("channel: TLS dial %s: %w", addr, err)
	}
	tlsConn := rawConn.(*tls.Conn)

	ch := &Channel{
		conn:     tlsConn,
		br:       bufio.NewReaderSize(tlsConn, 1<<16),
		log:      log,
		circuits: make(map[uint32]*circEntry),
		done:     make(chan struct{}),
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	}
	if err := ch.handshake(addr, cfg.ExpectedEd25519, nowFn()); err != nil {
		tlsConn.Close()
		return nil, err
	}
	_ = tlsConn.SetDeadline(time.Time{}) // clear handshake deadline

	go ch.readLoop()
	return ch, nil
}

// EdIdentity returns the relay's verified Ed25519 identity key.
func (ch *Channel) EdIdentity() []byte { return ch.edIdentity }

// LinkVersion returns the negotiated link protocol version.
func (ch *Channel) LinkVersion() uint16 { return ch.linkVersion }

func (ch *Channel) handshake(addr string, expectedEd []byte, now time.Time) error {
	// 1. Send VERSIONS with a 2-byte circuit ID.
	if err := ch.writeCell(cell.Cell{Command: cell.CmdVersions, Payload: encodeVersions(supportedLinkVersions)}, cell.CircIDLenShort); err != nil {
		return fmt.Errorf("channel: send VERSIONS: %w", err)
	}

	// 2. Receive the responder's VERSIONS (also 2-byte circuit ID).
	verCell, err := cell.ReadCell(ch.br, cell.CircIDLenShort)
	if err != nil {
		return fmt.Errorf("channel: read VERSIONS: %w", err)
	}
	if verCell.Command != cell.CmdVersions {
		return fmt.Errorf("channel: expected VERSIONS, got %v", verCell.Command)
	}
	ch.linkVersion, err = negotiateVersion(verCell.Payload)
	if err != nil {
		return err
	}
	ch.log.Debug("link version negotiated", "version", ch.linkVersion, "relay", addr)

	// 3. Read CERTS, AUTH_CHALLENGE, NETINFO (4-byte circuit IDs now).
	var certsPayload []byte
	var gotNetinfo bool
	for !gotNetinfo {
		c, err := cell.ReadCell(ch.br, cell.CircIDLenWide)
		if err != nil {
			return fmt.Errorf("channel: read handshake cell: %w", err)
		}
		switch c.Command {
		case cell.CmdCerts:
			certsPayload = c.Payload
		case cell.CmdAuthChallenge:
			// Client does not authenticate; ignore.
		case cell.CmdNetinfo:
			gotNetinfo = true
		case cell.CmdPadding, cell.CmdVPadding:
			// ignore padding
		default:
			ch.log.Debug("unexpected handshake cell", "cmd", c.Command)
		}
	}
	if certsPayload == nil {
		return errors.New("channel: no CERTS cell received")
	}

	// 4. Verify the relay's certificate chain against the TLS leaf cert.
	tlsConn := ch.conn.(*tls.Conn)
	peerCerts := tlsConn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		return errors.New("channel: no TLS peer certificate")
	}
	identity, err := verifyCerts(certsPayload, peerCerts[0].Raw, now)
	if err != nil {
		return err
	}
	if expectedEd != nil && !bytes.Equal(identity, expectedEd) {
		return fmt.Errorf("channel: relay identity mismatch: got %x, want %x", identity, expectedEd)
	}
	ch.edIdentity = identity

	// 5. Send our NETINFO to complete the handshake.
	if err := ch.writeCell(cell.Cell{Command: cell.CmdNetinfo, Payload: encodeClientNetinfo(addr, now)}, cell.CircIDLenWide); err != nil {
		return fmt.Errorf("channel: send NETINFO: %w", err)
	}
	return nil
}

// SendCell writes a cell to the relay using the negotiated 4-byte circuit ID.
func (ch *Channel) SendCell(c cell.Cell) error {
	return ch.writeCell(c, cell.CircIDLenWide)
}

func (ch *Channel) writeCell(c cell.Cell, circIDLen int) error {
	enc := c.Encode(circIDLen)
	ch.writeMu.Lock()
	defer ch.writeMu.Unlock()
	_ = ch.conn.SetWriteDeadline(time.Now().Add(cellWriteTimeout))
	if _, err := ch.conn.Write(enc); err != nil {
		return fmt.Errorf("channel: write cell: %w", err)
	}
	_ = ch.conn.SetWriteDeadline(time.Time{})
	return nil
}

// AllocCircuit reserves a fresh client-initiated circuit ID (MSB set per
// tor-spec) and returns its inbound cell channel plus a done channel that the
// read pump and the circuit's receive loop watch for teardown.
func (ch *Channel) AllocCircuit() (uint32, <-chan *cell.Cell, <-chan struct{}, error) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if ch.closed {
		return 0, nil, nil, ch.closeErr
	}
	for {
		id := randUint32() | 0x80000000
		if _, exists := ch.circuits[id]; exists {
			continue
		}
		ent := &circEntry{
			inbox: make(chan *cell.Cell, circuitInboxDepth),
			done:  make(chan struct{}),
		}
		ch.circuits[id] = ent
		return id, ent.inbox, ent.done, nil
	}
}

// FreeCircuit removes a circuit's entry so its ID can be reused and signals its
// done channel. The inbox is never closed, so the read pump can never send on a
// closed channel; it sees done instead and drops any in-flight cell.
func (ch *Channel) FreeCircuit(id uint32) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if ent, ok := ch.circuits[id]; ok {
		delete(ch.circuits, id)
		close(ent.done)
	}
}

func (ch *Channel) readLoop() {
	for {
		c, err := cell.ReadCell(ch.br, cell.CircIDLenWide)
		if err != nil {
			ch.failAll(err)
			return
		}
		if c.CircID == 0 {
			continue // channel-level cells (padding); ignored
		}
		ch.mu.Lock()
		ent := ch.circuits[c.CircID]
		ch.mu.Unlock()
		if ent == nil {
			continue // unknown/torn-down circuit
		}
		cc := c
		select {
		case ent.inbox <- &cc:
		case <-ent.done:
			// Circuit was freed/torn down; drop its in-flight cell. The inbox is
			// never closed, so this can never panic.
		case <-ch.done:
			return
		}
	}
}

func (ch *Channel) failAll(err error) {
	ch.mu.Lock()
	if ch.closed {
		ch.mu.Unlock()
		return
	}
	ch.closed = true
	ch.closeErr = err
	for id, ent := range ch.circuits {
		close(ent.done)
		delete(ch.circuits, id)
	}
	close(ch.done)
	ch.mu.Unlock()
	if !errors.Is(err, io.EOF) {
		ch.log.Debug("channel read loop ended", "err", err)
	}
}

// Close tears down the channel and all its circuits.
func (ch *Channel) Close() error {
	ch.failAll(errors.New("channel: closed"))
	return ch.conn.Close()
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func randUint32() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("channel: crypto/rand failed: %v", err))
	}
	return binary.BigEndian.Uint32(b[:])
}

func encodeVersions(versions []uint16) []byte {
	w := byteutil.NewWriter(len(versions) * 2)
	for _, v := range versions {
		w.U16(v)
	}
	return w.Bytes()
}

// negotiateVersion picks the highest link version supported by both peers.
func negotiateVersion(payload []byte) (uint16, error) {
	r := byteutil.NewReader(payload)
	offered := make(map[uint16]bool)
	for r.Remaining() >= 2 {
		offered[r.U16()] = true
	}
	for _, v := range supportedLinkVersions {
		if offered[v] {
			return v, nil
		}
	}
	return 0, errors.New("channel: no common link protocol version")
}

// encodeClientNetinfo builds the client's NETINFO cell payload: the current
// time, the relay's address as OTHER_OR_ADDRESS, and zero of our own addresses.
func encodeClientNetinfo(relayAddr string, now time.Time) []byte {
	w := byteutil.NewWriter(16)
	w.U32(uint32(now.Unix()))

	host, _, err := net.SplitHostPort(relayAddr)
	var ip net.IP
	if err == nil {
		ip = net.ParseIP(host)
	}
	writeNetinfoAddr(w, ip)

	w.Byte(0) // NUM_ADDRESSES: clients advertise none
	return w.Bytes()
}

func writeNetinfoAddr(w *byteutil.Writer, ip net.IP) {
	if ip4 := ip.To4(); ip4 != nil {
		w.Byte(netinfoAddrIPv4).Byte(4).Write(ip4)
		return
	}
	if ip16 := ip.To16(); ip16 != nil {
		w.Byte(netinfoAddrIPv6).Byte(16).Write(ip16)
		return
	}
	w.Byte(netinfoAddrIPv4).Byte(0) // unknown: zero-length
}
