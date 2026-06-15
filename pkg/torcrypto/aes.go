package torcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// NewCTR returns an AES-CTR cipher.Stream keyed with key and started from an
// all-zero counter, as used for Tor relay-cell encryption. The key length
// selects AES-128 (16 bytes, ntor v1 relay crypto) or AES-256 (32 bytes,
// hidden-service end-to-end crypto).
//
// The returned Stream is stateful: one Stream must persist for the lifetime of
// a hop's direction so the counter advances across cells. Re-creating it per
// cell corrupts the stream.
func NewCTR(key []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new aes cipher: %w", err)
	}
	iv := make([]byte, aes.BlockSize) // zero IV / counter
	return cipher.NewCTR(block, iv), nil
}
