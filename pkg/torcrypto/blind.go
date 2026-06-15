package torcrypto

import (
	"encoding/binary"
	"fmt"

	"filippo.io/edwards25519"
)

// Ed25519PubKeyLen is the length of an ed25519 public key.
const Ed25519PubKeyLen = 32

// Key-blinding constants (rend-spec-v3 §A.2). blindString includes the trailing
// NUL byte (INT_1(0)); the basepoint string is the exact ASCII form Tor hashes.
const (
	blindString      = "Derive temporary signing key\x00"
	ed25519Basepoint = "(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"
	keyBlindPrefix   = "key-blind"
)

// blindingFactor computes the clamped 32-byte blinding scalar h for an ed25519
// identity public key A over a time period:
//
//	h = SHA3-256(BLIND_STRING | A | ed25519_basepoint | N)
//	N = "key-blind" | INT_8(period_number) | INT_8(period_length)
//
// Both INT_8 values are 8-byte big-endian unsigned integers.
func blindingFactor(pubkey []byte, periodNumber, periodLength uint64) []byte {
	nonce := make([]byte, 0, len(keyBlindPrefix)+16)
	nonce = append(nonce, keyBlindPrefix...)
	nonce = binary.BigEndian.AppendUint64(nonce, periodNumber)
	nonce = binary.BigEndian.AppendUint64(nonce, periodLength)

	h := SHA3_256([]byte(blindString), pubkey, []byte(ed25519Basepoint), nonce)
	h[0] &= 248
	h[31] &= 63
	h[31] |= 64
	return h
}

// BlindPublicKey returns A' = h·A, the blinded ed25519 public key used to look
// up and decrypt a v3 onion-service descriptor in a given time period.
func BlindPublicKey(pubkey []byte, periodNumber, periodLength uint64) ([]byte, error) {
	if len(pubkey) != Ed25519PubKeyLen {
		return nil, fmt.Errorf("blind: pubkey must be %d bytes, got %d", Ed25519PubKeyLen, len(pubkey))
	}
	h := blindingFactor(pubkey, periodNumber, periodLength)

	var s edwards25519.Scalar
	if _, err := s.SetBytesWithClamping(h); err != nil {
		return nil, fmt.Errorf("blind: scalar: %w", err)
	}
	var a edwards25519.Point
	if _, err := a.SetBytes(pubkey); err != nil {
		return nil, fmt.Errorf("blind: decode pubkey: %w", err)
	}
	var aprime edwards25519.Point
	aprime.ScalarMult(&s, &a)
	return aprime.Bytes(), nil
}
