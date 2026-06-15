package torcrypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
)

// Curve25519KeyLen is the byte length of an X25519 public or private key.
const Curve25519KeyLen = 32

// X25519KeyPair is an ephemeral Curve25519 keypair used by the ntor handshakes.
type X25519KeyPair struct {
	priv *ecdh.PrivateKey
}

// GenerateX25519 creates a fresh ephemeral X25519 keypair. A nil reader means
// crypto/rand.Reader, which is what every production caller relies on (Go's
// ecdh.GenerateKey panics on a nil reader rather than defaulting it).
func GenerateX25519(reader io.Reader) (*X25519KeyPair, error) {
	if reader == nil {
		reader = rand.Reader
	}
	priv, err := ecdh.X25519().GenerateKey(reader)
	if err != nil {
		return nil, fmt.Errorf("generate x25519: %w", err)
	}
	return &X25519KeyPair{priv: priv}, nil
}

// newX25519FromSeed builds a keypair from a fixed 32-byte private scalar. It is
// used by tests to reproduce handshake vectors deterministically.
func newX25519FromSeed(seed []byte) (*X25519KeyPair, error) {
	priv, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return nil, fmt.Errorf("x25519 from seed: %w", err)
	}
	return &X25519KeyPair{priv: priv}, nil
}

// Public returns the 32-byte public key.
func (kp *X25519KeyPair) Public() []byte { return kp.priv.PublicKey().Bytes() }

// X25519SharedSecret computes the X25519 shared secret between a 32-byte
// private key and a 32-byte peer public key (used to derive onion client-auth
// descriptor cookie keys).
func X25519SharedSecret(privateKey, peerPublic []byte) ([]byte, error) {
	kp, err := newX25519FromSeed(privateKey)
	if err != nil {
		return nil, err
	}
	return kp.ECDH(peerPublic)
}

// ECDH computes the X25519 shared secret with the given 32-byte peer public
// key. It returns an error for low-order peer keys (all-zero output), matching
// Tor's requirement to abort the handshake in that case.
func (kp *X25519KeyPair) ECDH(peerPublic []byte) ([]byte, error) {
	peer, err := ecdh.X25519().NewPublicKey(peerPublic)
	if err != nil {
		return nil, fmt.Errorf("parse peer x25519 key: %w", err)
	}
	secret, err := kp.priv.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("x25519 ecdh: %w", err)
	}
	return secret, nil
}
