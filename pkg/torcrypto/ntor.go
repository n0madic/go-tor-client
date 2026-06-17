package torcrypto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
)

// ntor v1 handshake (tor-spec §5.1.4). PROTOID and the four tweak strings below
// frame every HMAC and the HKDF expansion.
const (
	ntorProtoID = "ntor-curve25519-sha256-1"

	// NodeIDLen is the length of a relay's legacy RSA identity digest (the
	// NODEID field of an ntor handshake).
	NodeIDLen = 20

	// NtorClientDataLen is the CREATE2 client handshake length:
	// NODEID(20) | KEYID(32) | CLIENT_PK(32).
	NtorClientDataLen = NodeIDLen + Curve25519KeyLen + Curve25519KeyLen
	// NtorServerDataLen is the CREATED2 server handshake length:
	// SERVER_PK(32) | AUTH(32).
	NtorServerDataLen = Curve25519KeyLen + sha256.Size
)

var (
	ntorTMac    = []byte(ntorProtoID + ":mac")
	ntorTKey    = []byte(ntorProtoID + ":key_extract")
	ntorTVerify = []byte(ntorProtoID + ":verify")
	ntorMExpand = ntorProtoID + ":key_expand"
	ntorServerL = []byte("Server")
	ntorProtoB  = []byte(ntorProtoID)
)

// ErrNtorAuth is returned when the server's AUTH tag fails to verify, meaning
// the handshake was tampered with or the wrong onion key was used.
var ErrNtorAuth = errors.New("torcrypto: ntor AUTH verification failed")

// NtorClient holds the client-side state between sending CREATE2 and receiving
// CREATED2.
type NtorClient struct {
	eph      *X25519KeyPair
	nodeID   []byte // 20-byte relay RSA identity digest
	onionKey []byte // 32-byte relay ntor onion key (B)
}

// NtorClientHandshake begins an ntor handshake against a relay identified by
// its 20-byte RSA identity digest and 32-byte ntor onion key. It returns the
// 84-byte client handshake data for the CREATE2/EXTEND2 cell and the state
// needed to finish.
func NtorClientHandshake(nodeID, ntorOnionKey []byte) (clientData []byte, state *NtorClient, err error) {
	eph, err := GenerateX25519(nil)
	if err != nil {
		return nil, nil, err
	}
	return finishClientHandshake(nodeID, ntorOnionKey, eph)
}

func finishClientHandshake(nodeID, ntorOnionKey []byte, eph *X25519KeyPair) ([]byte, *NtorClient, error) {
	if len(nodeID) != NodeIDLen {
		return nil, nil, fmt.Errorf("ntor: nodeID must be %d bytes, got %d", NodeIDLen, len(nodeID))
	}
	if len(ntorOnionKey) != Curve25519KeyLen {
		return nil, nil, fmt.Errorf("ntor: onion key must be %d bytes, got %d", Curve25519KeyLen, len(ntorOnionKey))
	}
	st := &NtorClient{
		eph:      eph,
		nodeID:   append([]byte(nil), nodeID...),
		onionKey: append([]byte(nil), ntorOnionKey...),
	}
	data := make([]byte, 0, NtorClientDataLen)
	data = append(data, st.nodeID...)
	data = append(data, st.onionKey...)
	data = append(data, eph.Public()...)
	return data, st, nil
}

// Complete consumes the 64-byte CREATED2/EXTENDED2 server handshake
// (SERVER_PK | AUTH), verifies the AUTH tag, and expands keyLen bytes of key
// material from the shared secret.
func (c *NtorClient) Complete(serverData []byte, keyLen int) ([]byte, error) {
	if len(serverData) < NtorServerDataLen {
		return nil, fmt.Errorf("ntor: server data must be at least %d bytes, got %d", NtorServerDataLen, len(serverData))
	}
	serverPK := serverData[:Curve25519KeyLen]
	authRecv := serverData[Curve25519KeyLen : Curve25519KeyLen+sha256.Size]

	expYx, err := c.eph.ECDH(serverPK) // EXP(Y, x)
	if err != nil {
		return nil, fmt.Errorf("ntor EXP(Y,x): %w", err)
	}
	expBx, err := c.eph.ECDH(c.onionKey) // EXP(B, x)
	if err != nil {
		return nil, fmt.Errorf("ntor EXP(B,x): %w", err)
	}

	clientPK := c.eph.Public()

	// secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
	secretInput := concat(expYx, expBx, c.nodeID, c.onionKey, clientPK, serverPK, ntorProtoB)
	keySeed := HMACSHA256(ntorTKey, secretInput)
	verify := HMACSHA256(ntorTVerify, secretInput)

	// auth_input = verify | ID | B | Y | X | PROTOID | "Server"
	authInput := concat(verify, c.nodeID, c.onionKey, serverPK, clientPK, ntorProtoB, ntorServerL)
	authExpected := HMACSHA256(ntorTMac, authInput)

	if subtle.ConstantTimeCompare(authExpected, authRecv) != 1 {
		return nil, ErrNtorAuth
	}

	// K = HKDF-Expand-SHA256(KEY_SEED, m_expand, keyLen)
	out, err := hkdf.Expand(sha256.New, keySeed, ntorMExpand, keyLen)
	if err != nil {
		return nil, fmt.Errorf("ntor HKDF expand: %w", err)
	}
	return out, nil
}

// concat returns the concatenation of the given byte slices in a fresh buffer.
func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
