package torcrypto

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha1"
	"crypto/sha256"
	"testing"
)

// ntorServerHandshake is an independent, spec-following server implementation
// of ntor v1, used only to round-trip-test the client. Keeping it in the test
// file (not production code) ensures the client and server were written
// separately, so a passing round trip exercises the byte ordering for real.
func ntorServerHandshake(t *testing.T, nodeID []byte, serverNtor *X25519KeyPair, clientData []byte, keyLen int) (serverData, keys []byte) {
	t.Helper()
	if len(clientData) != NtorClientDataLen {
		t.Fatalf("client data len = %d, want %d", len(clientData), NtorClientDataLen)
	}
	gotNodeID := clientData[:NodeIDLen]
	b := clientData[NodeIDLen : NodeIDLen+Curve25519KeyLen]
	x := clientData[NodeIDLen+Curve25519KeyLen:]
	if !bytes.Equal(gotNodeID, nodeID) {
		t.Fatalf("server: unexpected nodeID")
	}
	if !bytes.Equal(b, serverNtor.Public()) {
		t.Fatalf("server: client used wrong onion key")
	}

	ephY, err := GenerateX25519(nil)
	if err != nil {
		t.Fatalf("server eph: %v", err)
	}
	y := ephY.Public()

	expXy, err := ephY.ECDH(x) // EXP(X, y)
	if err != nil {
		t.Fatalf("EXP(X,y): %v", err)
	}
	expXb, err := serverNtor.ECDH(x) // EXP(X, b)
	if err != nil {
		t.Fatalf("EXP(X,b): %v", err)
	}

	secretInput := concat(expXy, expXb, nodeID, serverNtor.Public(), x, y, ntorProtoB)
	keySeed := HMACSHA256(ntorTKey, secretInput)
	verify := HMACSHA256(ntorTVerify, secretInput)
	authInput := concat(verify, nodeID, serverNtor.Public(), y, x, ntorProtoB, ntorServerL)
	auth := HMACSHA256(ntorTMac, authInput)

	serverData = append(append([]byte{}, y...), auth...)
	keys, err = hkdf.Expand(sha256.New, keySeed, ntorMExpand, keyLen)
	if err != nil {
		t.Fatalf("server hkdf: %v", err)
	}
	return serverData, keys
}

func TestNtorRoundTrip(t *testing.T) {
	t.Parallel()
	nodeID := bytes.Repeat([]byte{0x42}, NodeIDLen)
	serverNtor, err := GenerateX25519(nil)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}

	clientData, state, err := NtorClientHandshake(nodeID, serverNtor.Public())
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	serverData, serverKeys := ntorServerHandshake(t, nodeID, serverNtor, clientData, NtorKeyMaterialLen)

	clientKeys, err := state.Complete(serverData, NtorKeyMaterialLen)
	if err != nil {
		t.Fatalf("client complete: %v", err)
	}
	if !bytes.Equal(clientKeys, serverKeys) {
		t.Fatalf("derived keys differ\n client=%x\n server=%x", clientKeys, serverKeys)
	}

	rk, ok := SplitNtorKeys(clientKeys)
	if !ok {
		t.Fatal("SplitNtorKeys failed")
	}
	if len(rk.Df) != 20 || len(rk.Db) != 20 || len(rk.Kf) != 16 || len(rk.Kb) != 16 || len(rk.KH) != 20 {
		t.Fatalf("unexpected key lengths: %+v", rk)
	}
}

func TestNtorAuthFailure(t *testing.T) {
	t.Parallel()
	nodeID := bytes.Repeat([]byte{0x11}, NodeIDLen)
	serverNtor, _ := GenerateX25519(nil)
	clientData, state, err := NtorClientHandshake(nodeID, serverNtor.Public())
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	serverData, _ := ntorServerHandshake(t, nodeID, serverNtor, clientData, NtorKeyMaterialLen)

	// Flip a bit in the AUTH tag.
	tampered := append([]byte(nil), serverData...)
	tampered[len(tampered)-1] ^= 0x80
	if _, err := state.Complete(tampered, NtorKeyMaterialLen); err != ErrNtorAuth {
		t.Fatalf("expected ErrNtorAuth, got %v", err)
	}
}

func TestRunningDigestSHA1KAT(t *testing.T) {
	t.Parallel()
	seed := []byte("Df-seed-material-20b")
	d := NewRunningDigestSHA1(seed)
	want := sha1.Sum(seed)
	if !bytes.Equal(d.Snapshot()[:], want[:]) {
		t.Fatalf("digest of seed = %x, want %x", d.Snapshot(), want)
	}

	// Snapshot must not disturb the rolling state: a second snapshot after an
	// update reflects the update, and equals an independently computed value.
	cell := bytes.Repeat([]byte{0x07}, 509)
	d.Update(cell)
	got := d.Snapshot()

	ref := sha1.New()
	ref.Write(seed)
	ref.Write(cell)
	refSum := ref.Sum(nil)
	if !bytes.Equal(got, refSum) {
		t.Fatalf("rolling digest = %x, want %x", got, refSum)
	}
}

func TestAESCTRRoundTrip(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x9a}, 16)
	plain := []byte("two relay cells worth of streamed keystream data!!")

	enc, err := NewCTR(key)
	if err != nil {
		t.Fatalf("enc: %v", err)
	}
	ct := make([]byte, len(plain))
	enc.XORKeyStream(ct, plain)

	dec, err := NewCTR(key)
	if err != nil {
		t.Fatalf("dec: %v", err)
	}
	out := make([]byte, len(ct))
	dec.XORKeyStream(out, ct)
	if !bytes.Equal(out, plain) {
		t.Fatalf("round trip mismatch: %q", out)
	}
}

func TestAESCTRPersistentCounter(t *testing.T) {
	t.Parallel()
	// Encrypting [a][b] with one persistent stream must differ from encrypting
	// each block with a fresh stream (which would reuse the counter).
	key := bytes.Repeat([]byte{0x5c}, 16)
	a := bytes.Repeat([]byte{0x01}, 16)
	b := bytes.Repeat([]byte{0x02}, 16)

	persistent, _ := NewCTR(key)
	p1 := make([]byte, 16)
	p2 := make([]byte, 16)
	persistent.XORKeyStream(p1, a)
	persistent.XORKeyStream(p2, b)

	fresh, _ := NewCTR(key)
	f2 := make([]byte, 16)
	fresh.XORKeyStream(make([]byte, 16), a)
	freshAgain, _ := NewCTR(key)
	freshAgain.XORKeyStream(f2, b)

	if bytes.Equal(p2, f2) {
		t.Fatal("persistent counter did not advance between blocks")
	}
}

func TestBlindPublicKeyConsistency(t *testing.T) {
	t.Parallel()
	// A valid ed25519 public key (the basepoint encoding).
	pub := []byte{
		0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	}
	const periodLen = 1440

	a1, err := BlindPublicKey(pub, 1000, periodLen)
	if err != nil {
		t.Fatalf("blind: %v", err)
	}
	if len(a1) != Ed25519PubKeyLen {
		t.Fatalf("blinded key len = %d", len(a1))
	}
	// Deterministic for the same inputs.
	a1b, _ := BlindPublicKey(pub, 1000, periodLen)
	if !bytes.Equal(a1, a1b) {
		t.Fatal("blinding not deterministic")
	}
	// Different period => different blinded key.
	a2, _ := BlindPublicKey(pub, 1001, periodLen)
	if bytes.Equal(a1, a2) {
		t.Fatal("blinded key did not change across periods")
	}
}

func TestBlindPublicKeyRejectsBadLength(t *testing.T) {
	t.Parallel()
	if _, err := BlindPublicKey(make([]byte, 31), 1, 1440); err == nil {
		t.Fatal("expected error for short pubkey")
	}
}
