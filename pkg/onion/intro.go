package onion

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/n0madic/go-tor-client/internal/byteutil"
	"github.com/n0madic/go-tor-client/pkg/torcrypto"
)

// INTRODUCE1 / cell constants (rend-spec-v3 [FMT_INTRO1]).
const (
	introAuthKeyTypeEd25519 = 0x02
	introOnionKeyTypeNtor   = 0x01
	rendezvousCookieLen     = 20
	introPlaintextPad       = 246 // pad inner plaintext to a fixed size
)

// BuildIntroduce1Plaintext builds the encrypted-portion plaintext of an
// INTRODUCE1 cell: the rendezvous cookie, the rendezvous point's ntor onion
// key, and its link specifiers, zero-padded to a fixed length.
func BuildIntroduce1Plaintext(cookie, rpNtorKey, rpLinkSpecs []byte) []byte {
	w := byteutil.NewWriter(64)
	w.Write(cookie)               // RENDEZVOUS_COOKIE [20]
	w.Byte(0)                     // N_EXTENSIONS = 0
	w.Byte(introOnionKeyTypeNtor) // ONION_KEY_TYPE = ntor
	w.U16(uint16(len(rpNtorKey))) // ONION_KEY_LEN
	w.Write(rpNtorKey)            // ONION_KEY (RP ntor key)
	w.Write(rpLinkSpecs)          // NSPEC | link specifiers
	body := w.Bytes()
	if len(body) < introPlaintextPad {
		body = append(body, make([]byte, introPlaintextPad-len(body))...)
	}
	return body
}

// BuildIntroduce1 assembles a full INTRODUCE1 cell body for an intro point:
// H | CLIENT_PK | ENCRYPTED_DATA | MAC, where H is the cleartext header,
// ENCRYPTED_DATA = AES-256-CTR(ENC_KEY) XOR plaintext, and MAC = HSMac(MAC_KEY,
// H | CLIENT_PK | ENCRYPTED_DATA).
func BuildIntroduce1(authKey, encKey, macKey, clientX, plaintext []byte) ([]byte, error) {
	header := byteutil.NewWriter(56).
		Write(make([]byte, 20)). // LEGACY_KEY_ID (zeros)
		Byte(introAuthKeyTypeEd25519).
		U16(uint16(len(authKey))).
		Write(authKey).
		Byte(0). // N_EXTENSIONS
		Bytes()

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, len(plaintext))
	cipher.NewCTR(block, make([]byte, aes.BlockSize)).XORKeyStream(encrypted, plaintext)

	mac := torcrypto.HSMac(macKey, header, clientX, encrypted)

	out := byteutil.NewWriter(len(header) + len(clientX) + len(encrypted) + len(mac)).
		Write(header).
		Write(clientX).
		Write(encrypted).
		Write(mac).
		Bytes()
	return out, nil
}

// ParseRendezvous2 splits a RENDEZVOUS2 body into SERVER_PK (Y) and AUTH.
func ParseRendezvous2(body []byte) (serverPK, auth []byte, ok bool) {
	if len(body) < 64 {
		return nil, nil, false
	}
	return body[:32], body[32:64], true
}
