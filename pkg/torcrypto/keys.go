package torcrypto

// Relay-crypto key sizes for ntor v1 hops.
const (
	digestKeyLen = 20 // Df, Db (SHA-1 seed) and KH
	aesKeyLen    = 16 // Kf, Kb (AES-128)

	// NtorKeyMaterialLen is the number of bytes the ntor KDF must expand to
	// fill the relay key set: Df|Db|Kf|Kb|KH.
	NtorKeyMaterialLen = digestKeyLen + digestKeyLen + aesKeyLen + aesKeyLen + digestKeyLen // 92
)

// RelayKeys is the per-hop key set derived from an ntor handshake. Df/Db seed
// the forward/backward running SHA-1 digests; Kf/Kb key the forward/backward
// AES-128-CTR keystreams; KH is the handshake key hash.
type RelayKeys struct {
	Df []byte // forward digest seed (20)
	Db []byte // backward digest seed (20)
	Kf []byte // forward AES-128 key (16)
	Kb []byte // backward AES-128 key (16)
	KH []byte // key hash (20)
}

// SplitNtorKeys carves the 92-byte ntor KDF output into the relay key set in
// the canonical Df|Db|Kf|Kb|KH order. It returns false if material is too short.
func SplitNtorKeys(material []byte) (RelayKeys, bool) {
	if len(material) < NtorKeyMaterialLen {
		return RelayKeys{}, false
	}
	off := 0
	take := func(n int) []byte {
		b := material[off : off+n]
		off += n
		return b
	}
	return RelayKeys{
		Df: take(digestKeyLen),
		Db: take(digestKeyLen),
		Kf: take(aesKeyLen),
		Kb: take(aesKeyLen),
		KH: take(digestKeyLen),
	}, true
}
