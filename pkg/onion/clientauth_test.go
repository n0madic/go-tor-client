package onion

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/n0madic/go-tor-client/pkg/torcrypto"
)

// TestDecryptDescriptorCookie validates the onion client-authorization cookie
// recovery by constructing a middle-layer plaintext the way a service would.
func TestDecryptDescriptorCookie(t *testing.T) {
	t.Parallel()
	subcred := bytes.Repeat([]byte{0x5a}, 32)
	cookie := bytes.Repeat([]byte{0xc7}, descCookieLen)

	// Client keypair (the user holds the private key).
	clientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientPub := clientPriv.PublicKey().Bytes()

	// Service per-descriptor ephemeral keypair.
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ephPub := ephPriv.PublicKey().Bytes()

	// Service-side: SECRET_SEED = x25519(eph_priv, client_pub).
	secretSeed, err := torcrypto.X25519SharedSecret(ephPriv.Bytes(), clientPub)
	if err != nil {
		t.Fatal(err)
	}
	keys := torcrypto.SHAKE256(authKeysLen, subcred, secretSeed)
	clientID := keys[:authClientIDLen]
	cookieKey := keys[authClientIDLen:authKeysLen]

	iv := bytes.Repeat([]byte{0x33}, authIVLen)
	block, _ := aes.NewCipher(cookieKey)
	encCookie := make([]byte, descCookieLen)
	cipher.NewCTR(block, iv).XORKeyStream(encCookie, cookie)

	b64 := base64.StdEncoding.EncodeToString
	middle := []byte(fmt.Sprintf(
		"desc-auth-type x25519\ndesc-auth-ephemeral-key %s\nauth-client %s %s %s\nencrypted\n",
		b64(ephPub), b64(clientID), b64(iv), b64(encCookie),
	))

	// Client-side recovery using the client's private key.
	got, err := decryptDescriptorCookie(middle, subcred, clientPriv.Bytes())
	if err != nil {
		t.Fatalf("decryptDescriptorCookie: %v", err)
	}
	if !bytes.Equal(got, cookie) {
		t.Fatalf("recovered cookie = %x, want %x", got, cookie)
	}

	// No auth key -> no cookie (public service path).
	if got, _ := decryptDescriptorCookie(middle, subcred, nil); got != nil {
		t.Fatal("expected nil cookie without an auth key")
	}

	// Wrong client key -> no matching auth-client entry.
	wrong, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if got, _ := decryptDescriptorCookie(middle, subcred, wrong.Bytes()); got != nil {
		t.Fatal("expected nil cookie with a non-matching auth key")
	}
}
