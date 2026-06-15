package torcrypto

import (
	"crypto/sha1"
	"crypto/subtle"
	"hash"
)

// RunningDigest maintains the rolling hash used to authenticate relay cells on
// a circuit hop. Every relay cell (with its digest field zeroed) is fed in
// order; the leading bytes of the current hash become that cell's digest field,
// and the full digest is snapshotted for authenticated SENDME cells.
//
// ntor v1 hops use SHA-1; hidden-service end-to-end hops use SHA3-256.
type RunningDigest struct {
	h hash.Hash
}

// NewRunningDigestSHA1 seeds a SHA-1 running digest with the Df/Db key from the
// ntor KDF output.
func NewRunningDigestSHA1(seed []byte) *RunningDigest {
	h := sha1.New()
	h.Write(seed)
	return &RunningDigest{h: h}
}

// NewRunningDigestSHA3 seeds a SHA3-256 running digest, used for the
// rendezvous (hidden-service) end-to-end circuit.
func NewRunningDigestSHA3(seed []byte) *RunningDigest {
	h := sha3New256()
	h.Write(seed)
	return &RunningDigest{h: h}
}

// Update feeds one relay cell's bytes (509-byte payload, digest field zeroed)
// into the rolling hash, advancing its state.
func (d *RunningDigest) Update(cell []byte) {
	d.h.Write(cell)
}

// Snapshot returns the full current digest without disturbing the rolling
// state, so hashing can continue with the next cell. The first 4 bytes are the
// value written into a cell's digest field; the full slice is the SENDME tag.
func (d *RunningDigest) Snapshot() []byte {
	return d.h.Sum(nil)
}

// VerifyAndCommit advances a clone of the rolling state with cellPayload (whose
// digest field must already be zeroed), then compares the leading len(want)
// bytes of the resulting hash against want. On match it commits the advance and
// returns true; on mismatch the rolling state is left untouched. This lets the
// receiver test whether an inbound cell is "recognized" at a hop without
// corrupting that hop's digest when it is not.
func (d *RunningDigest) VerifyAndCommit(cellPayload, want []byte) bool {
	cloner, ok := d.h.(hash.Cloner)
	if !ok {
		return false
	}
	clone, err := cloner.Clone()
	if err != nil {
		return false
	}
	clone.Write(cellPayload)
	sum := clone.Sum(nil)
	if len(want) > len(sum) || subtle.ConstantTimeCompare(sum[:len(want)], want) != 1 {
		return false
	}
	d.h = clone
	return true
}
