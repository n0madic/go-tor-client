// Package torcrypto implements the cryptographic primitives used by the Tor
// client: the ntor v1 and hs_ntor handshakes, AES-CTR relay keystreams, the
// running relay digest, HKDF-SHA256, SHA3-256/SHAKE256 helpers, X25519 ECDH,
// and ed25519 key blinding for v3 onion services.
//
// This is the most correctness-critical package in the project; every exported
// function mirrors a construction defined in tor-spec or rend-spec-v3.
package torcrypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha3"
	"hash"
)

// SHA256 returns the SHA-256 digest of the concatenation of parts.
func SHA256(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// SHA3_256 returns the SHA3-256 digest of the concatenation of parts.
func SHA3_256(parts ...[]byte) []byte {
	h := sha3.New256()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// HMACSHA256 computes HMAC-SHA256(key, msg). Tor-spec's H(x, t) notation maps
// to HMACSHA256(t, x): the second spec argument is the HMAC key.
func HMACSHA256(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// SHAKE256 returns outLen bytes squeezed from SHAKE256 over the concatenation
// of parts.
func SHAKE256(outLen int, parts ...[]byte) []byte {
	s := sha3.NewSHAKE256()
	for _, p := range parts {
		s.Write(p)
	}
	out := make([]byte, outLen)
	s.Read(out)
	return out
}

// sha3New256 is the hash constructor for SHA3-256, used by RunningDigest for
// hidden-service end-to-end circuits.
func sha3New256() hash.Hash { return sha3.New256() }
