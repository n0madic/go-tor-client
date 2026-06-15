// Package onion implements the v3 onion-service client: address parsing, the
// time-period / shared-random HSDir hash ring, two-layer descriptor decryption,
// and the intro/rendezvous handshake plumbing (hs_ntor).
package onion

import (
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/n0madic/go-tor-client/pkg/torcrypto"
)

const (
	onionSuffix    = ".onion"
	addressB32Len  = 56
	versionV3      = 0x03
	pubKeyLen      = 32
	checksumPrefix = ".onion checksum"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Address is a parsed v3 onion address: the 32-byte ed25519 master identity
// public key A.
type Address struct {
	PublicKey []byte
}

// ParseAddress parses a "<56-char-base32>.onion" host (case-insensitive) and
// verifies its checksum and version byte.
func ParseAddress(host string) (Address, error) {
	h := strings.ToLower(strings.TrimSuffix(strings.ToLower(host), onionSuffix))
	if len(h) != addressB32Len {
		return Address{}, fmt.Errorf("onion: address must be %d base32 chars, got %d", addressB32Len, len(h))
	}
	raw, err := b32.DecodeString(strings.ToUpper(h))
	if err != nil {
		return Address{}, fmt.Errorf("onion: base32 decode: %w", err)
	}
	if len(raw) != pubKeyLen+2+1 {
		return Address{}, fmt.Errorf("onion: decoded length %d, want 35", len(raw))
	}
	pub := raw[:pubKeyLen]
	checksum := raw[pubKeyLen : pubKeyLen+2]
	version := raw[pubKeyLen+2]
	if version != versionV3 {
		return Address{}, fmt.Errorf("onion: unsupported version %d", version)
	}
	want := addressChecksum(pub)
	if want[0] != checksum[0] || want[1] != checksum[1] {
		return Address{}, fmt.Errorf("onion: bad address checksum")
	}
	return Address{PublicKey: pub}, nil
}

// String renders the address back to its "<base32>.onion" form.
func (a Address) String() string {
	buf := make([]byte, 0, 35)
	buf = append(buf, a.PublicKey...)
	cs := addressChecksum(a.PublicKey)
	buf = append(buf, cs[0], cs[1], versionV3)
	return strings.ToLower(b32.EncodeToString(buf)) + onionSuffix
}

func addressChecksum(pub []byte) [2]byte {
	h := torcrypto.SHA3_256([]byte(checksumPrefix), pub, []byte{versionV3})
	return [2]byte{h[0], h[1]}
}

// Credential returns SHA3-256("credential" | A).
func Credential(identityPub []byte) []byte {
	return torcrypto.SHA3_256([]byte("credential"), identityPub)
}

// Subcredential returns SHA3-256("subcredential" | credential | A') for a time
// period's blinded public key.
func Subcredential(identityPub, blindedPub []byte) []byte {
	cred := Credential(identityPub)
	return torcrypto.SHA3_256([]byte("subcredential"), cred, blindedPub)
}
