package channel

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/n0madic/go-tor-client/internal/byteutil"
	"github.com/n0madic/go-tor-client/pkg/cell"
)

func selfSignedTLSCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mock-relay"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

func buildEdCert(innerType byte, certifiedKey []byte, exts []edExtension, signer ed25519.PrivateKey, exp uint32) []byte {
	w := byteutil.NewWriter(0)
	w.Byte(edCertVersion)
	w.Byte(innerType)
	w.U32(exp)
	w.Byte(1) // key type: ed25519
	w.Write(certifiedKey)
	w.Byte(byte(len(exts)))
	for _, e := range exts {
		w.U16(uint16(len(e.data)))
		w.Byte(e.typ)
		w.Byte(e.flags)
		w.Write(e.data)
	}
	body := w.Bytes()
	sig := ed25519.Sign(signer, body)
	return append(append([]byte(nil), body...), sig...)
}

func buildCertsCell(certs map[byte][]byte) []byte {
	w := byteutil.NewWriter(0)
	w.Byte(byte(len(certs)))
	for typ, body := range certs {
		w.Byte(typ)
		w.U16(uint16(len(body)))
		w.Write(body)
	}
	return w.Bytes()
}

// mockRelay performs the responder side of the link handshake. It runs in a
// goroutine and deliberately uses no *testing.T methods (the client may abort
// the connection legitimately, e.g. on an identity mismatch).
func mockRelay(conn net.Conn, certsPayload []byte) {
	defer conn.Close()

	if _, err := cell.ReadCell(conn, cell.CircIDLenShort); err != nil {
		return
	}
	write := func(c cell.Cell, w int) bool {
		_, err := conn.Write(c.Encode(w))
		return err == nil
	}
	if !write(cell.Cell{Command: cell.CmdVersions, Payload: encodeVersions([]uint16{5, 4})}, cell.CircIDLenShort) {
		return
	}
	if !write(cell.Cell{Command: cell.CmdCerts, Payload: certsPayload}, cell.CircIDLenWide) {
		return
	}
	if !write(cell.Cell{Command: cell.CmdAuthChallenge, Payload: make([]byte, 34)}, cell.CircIDLenWide) {
		return
	}
	if !write(cell.Cell{Command: cell.CmdNetinfo, Payload: make([]byte, 8)}, cell.CircIDLenWide) {
		return
	}
	// Read the client's NETINFO to complete the handshake (best effort).
	_, _ = cell.ReadCell(conn, cell.CircIDLenWide)
}

func startMockRelay(t *testing.T) (addr string, identity ed25519.PublicKey) {
	t.Helper()
	idPub, idPriv, _ := ed25519.GenerateKey(rand.Reader)
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	tlsCert := selfSignedTLSCert(t)

	exp := uint32(time.Now().Add(24*time.Hour).Unix() / 3600)
	cert4 := buildEdCert(edCertInnerTypeSigning, signPub, []edExtension{{typ: edCertExtSignedWithKey, data: idPub}}, idPriv, exp)
	linkDigest := sha256.Sum256(tlsCert.Certificate[0])
	cert5 := buildEdCert(edCertInnerTypeLinkAuth, linkDigest[:], nil, signPriv, exp)
	certsPayload := buildCertsCell(map[byte][]byte{
		certTypeEd25519SigningCert: cert4,
		certTypeEd25519LinkCert:    cert5,
	})

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{tlsCert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		mockRelay(conn, certsPayload)
	}()
	return ln.Addr().String(), idPub
}

func TestChannelHandshakeSuccess(t *testing.T) {
	addr, identity := startMockRelay(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := Dial(ctx, addr, Config{ExpectedEd25519: identity})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer ch.Close()

	if !bytes.Equal(ch.EdIdentity(), identity) {
		t.Fatalf("identity = %x, want %x", ch.EdIdentity(), identity)
	}
	if ch.LinkVersion() != 5 {
		t.Errorf("link version = %d, want 5", ch.LinkVersion())
	}
}

// TestFreeCircuitSignalsDoneNotInbox locks in the fix for the send-on-closed
// panic: FreeCircuit must close the circuit's done channel (so the read pump
// stops delivering) but must NOT close the inbox (which the pump may be sending
// on concurrently).
func TestFreeCircuitSignalsDoneNotInbox(t *testing.T) {
	t.Parallel()
	ch := &Channel{
		circuits: make(map[uint32]*circEntry),
		done:     make(chan struct{}),
	}
	id, inbox, done, err := ch.AllocCircuit()
	if err != nil {
		t.Fatalf("AllocCircuit: %v", err)
	}

	ch.FreeCircuit(id)

	select {
	case <-done:
	default:
		t.Fatal("FreeCircuit did not close the circuit's done channel")
	}

	select {
	case _, ok := <-inbox:
		if !ok {
			t.Fatal("FreeCircuit closed the inbox; the read pump could panic sending on it")
		}
	default:
		// empty and still open — correct.
	}

	// A second free is a no-op (entry already removed), not a double close.
	ch.FreeCircuit(id)
}

func TestChannelHandshakeIdentityMismatch(t *testing.T) {
	addr, _ := startMockRelay(t)
	wrong := bytes.Repeat([]byte{0x00}, ed25519PublicKeyLen)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Dial(ctx, addr, Config{ExpectedEd25519: wrong}); err == nil {
		t.Fatal("expected identity mismatch error, got nil")
	}
}
