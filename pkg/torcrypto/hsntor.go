package torcrypto

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// hs_ntor handshake (rend-spec-v3 §3.3.1, "NTOR-WITH-EXTRA-DATA"). Used by a
// client to introduce to and rendezvous with a v3 onion service.
const (
	hsNtorProtoID = "tor-hs-ntor-curve25519-sha3-256-1"

	hsKeyLen = 32 // S_KEY_LEN (AES-256)
	hsMacLen = 32 // MAC_LEN (SHA3-256)

	// HSNtorKeySeedLen and the e2e key material length.
	hsE2EKeyMaterialLen = 2*32 + 2*32 // Df|Db|Kf|Kb = 128
)

var (
	hsTEnc    = []byte(hsNtorProtoID + ":hs_key_extract")
	hsTVerify = []byte(hsNtorProtoID + ":hs_verify")
	hsTMac    = []byte(hsNtorProtoID + ":hs_mac")
	hsMExpand = []byte(hsNtorProtoID + ":hs_key_expand")
	hsProtoB  = []byte(hsNtorProtoID)
	hsServerL = []byte("Server")
)

// ErrHSNtorAuth is returned when the service's RENDEZVOUS2 AUTH tag is invalid.
var ErrHSNtorAuth = errors.New("torcrypto: hs_ntor AUTH verification failed")

// HSMac exposes the hidden-service MAC construction MAC(key, msg) =
// SHA3-256(INT_8(len(key)) | key | msg) for building INTRODUCE1 message MACs.
func HSMac(key []byte, msg ...[]byte) []byte { return hsMac(key, msg...) }

// hsMac computes MAC(key, msg) = SHA3-256(INT_8(len(key)) | key | msg), the MAC
// construction used throughout the hidden-service protocols.
func hsMac(key []byte, msg ...[]byte) []byte {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(key)))
	parts := append([][]byte{lenBuf[:], key}, msg...)
	return SHA3_256(parts...)
}

// HSNtorClient holds client state between the INTRODUCE1 and RENDEZVOUS2 steps.
type HSNtorClient struct {
	eph     *X25519KeyPair
	encKey  []byte // B, the intro point's service ntor encryption key
	authKey []byte // AUTH_KEY, the intro point auth key (ed25519)
	clientX []byte // X
}

// HSNtorClientIntro begins the hs_ntor handshake for an INTRODUCE1 message. It
// returns the symmetric ENC_KEY and MAC_KEY used to encrypt/authenticate the
// INTRODUCE1 body, the client public key X, and the handshake state.
func HSNtorClientIntro(serviceEncKey, authKey, subcredential []byte) (encKey, macKey, clientX []byte, state *HSNtorClient, err error) {
	eph, err := GenerateX25519(nil)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return hsNtorIntroWith(serviceEncKey, authKey, subcredential, eph)
}

func hsNtorIntroWith(serviceEncKey, authKey, subcredential []byte, eph *X25519KeyPair) ([]byte, []byte, []byte, *HSNtorClient, error) {
	if len(serviceEncKey) != Curve25519KeyLen {
		return nil, nil, nil, nil, fmt.Errorf("hs_ntor: enc key must be %d bytes", Curve25519KeyLen)
	}
	if len(authKey) != Ed25519PubKeyLen {
		return nil, nil, nil, nil, fmt.Errorf("hs_ntor: auth key must be %d bytes", Ed25519PubKeyLen)
	}
	st := &HSNtorClient{
		eph:     eph,
		encKey:  append([]byte(nil), serviceEncKey...),
		authKey: append([]byte(nil), authKey...),
		clientX: eph.Public(),
	}

	expBx, err := eph.ECDH(serviceEncKey) // EXP(B,x)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("hs_ntor EXP(B,x): %w", err)
	}
	// intro_secret_hs_input = EXP(B,x) | AUTH_KEY | X | B | PROTOID
	introSecret := concat(expBx, st.authKey, st.clientX, st.encKey, hsProtoB)
	// hs_keys = SHAKE256(intro_secret | t_hsenc | (m_hsexpand | subcred), 64)
	hsKeys := SHAKE256(hsKeyLen+hsMacLen, introSecret, hsTEnc, hsMExpand, subcredential)
	return hsKeys[:hsKeyLen], hsKeys[hsKeyLen : hsKeyLen+hsMacLen], st.clientX, st, nil
}

// Finish completes the handshake from the RENDEZVOUS2 server reply
// (SERVER_PK=Y, AUTH), verifying AUTH and returning NTOR_KEY_SEED.
func (c *HSNtorClient) Finish(serverY, authRecv []byte) (ntorKeySeed []byte, err error) {
	if len(serverY) != Curve25519KeyLen {
		return nil, fmt.Errorf("hs_ntor: server PK must be %d bytes", Curve25519KeyLen)
	}
	expYx, err := c.eph.ECDH(serverY) // EXP(Y,x)
	if err != nil {
		return nil, fmt.Errorf("hs_ntor EXP(Y,x): %w", err)
	}
	expBx, err := c.eph.ECDH(c.encKey) // EXP(B,x)
	if err != nil {
		return nil, fmt.Errorf("hs_ntor EXP(B,x): %w", err)
	}
	// rend_secret_hs_input = EXP(Y,x) | EXP(B,x) | AUTH_KEY | B | X | Y | PROTOID
	// In MAC(a, b) the first argument is the key and the second is the message
	// (Tor's hs_ntor_mac(key, msg)).
	rendSecret := concat(expYx, expBx, c.authKey, c.encKey, c.clientX, serverY, hsProtoB)
	seed := hsMac(rendSecret, hsTEnc)
	verify := hsMac(rendSecret, hsTVerify)
	authInput := concat(verify, c.authKey, c.encKey, serverY, c.clientX, hsProtoB, hsServerL)
	authExpected := hsMac(authInput, hsTMac)
	if !constantTimeEqual(authExpected, authRecv) {
		return nil, ErrHSNtorAuth
	}
	return seed, nil
}

// HSNtorExpandKeys derives the end-to-end rendezvous circuit keys from
// NTOR_KEY_SEED: K = SHAKE256(NTOR_KEY_SEED | m_hsexpand, 128) split into
// Df|Db|Kf|Kb. Df/Db seed SHA3-256 digests; Kf/Kb key AES-256-CTR.
func HSNtorExpandKeys(ntorKeySeed []byte) (df, db, kf, kb []byte) {
	k := SHAKE256(hsE2EKeyMaterialLen, ntorKeySeed, hsMExpand)
	return k[0:32], k[32:64], k[64:96], k[96:128]
}

func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
