package onion

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"strings"

	"github.com/n0madic/go-tor-client/pkg/torcrypto"
)

// Onion client-authorization (restricted discovery) sizes (rend-spec-v3 §2.5.1).
const (
	descCookieLen   = 16
	authClientIDLen = 8
	authIVLen       = 16
	authKeysLen     = 40 // CLIENT-ID(8) | COOKIE-KEY(32)
)

// decryptDescriptorCookie recovers the descriptor cookie that unlocks the second
// descriptor layer of a client-authorized onion service. It returns (nil, nil)
// when clientAuthKey is nil (public service) or when no matching auth-client
// entry is found (the second layer will then be decrypted without a cookie).
func decryptDescriptorCookie(middle, subcred, clientAuthKey []byte) ([]byte, error) {
	if len(clientAuthKey) == 0 {
		return nil, nil
	}

	ephemPub, clients := parseAuthClients(middle)
	if len(ephemPub) != 32 || len(clients) == 0 {
		return nil, nil // descriptor is not client-authorized
	}

	secretSeed, err := torcrypto.X25519SharedSecret(clientAuthKey, ephemPub)
	if err != nil {
		return nil, fmt.Errorf("onion: client-auth ECDH: %w", err)
	}
	keys := torcrypto.SHAKE256(authKeysLen, subcred, secretSeed)
	wantClientID := keys[:authClientIDLen]
	cookieKey := keys[authClientIDLen:authKeysLen]

	for _, ac := range clients {
		if !bytes.Equal(ac.clientID, wantClientID) {
			continue
		}
		if len(ac.iv) != authIVLen || len(ac.encryptedCookie) != descCookieLen {
			continue
		}
		block, err := aes.NewCipher(cookieKey)
		if err != nil {
			return nil, err
		}
		cookie := make([]byte, descCookieLen)
		cipher.NewCTR(block, ac.iv).XORKeyStream(cookie, ac.encryptedCookie)
		return cookie, nil
	}
	return nil, nil
}

type authClient struct {
	clientID        []byte
	iv              []byte
	encryptedCookie []byte
}

// parseAuthClients extracts the service's ephemeral x25519 public key and the
// auth-client entries from the first-layer (middle) plaintext.
func parseAuthClients(middle []byte) (ephemPub []byte, clients []authClient) {
	sc := bufio.NewScanner(bytes.NewReader(middle))
	sc.Buffer(make([]byte, 0, 8192), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		switch {
		case len(f) >= 2 && f[0] == "desc-auth-ephemeral-key":
			ephemPub = decodeB64(f[1])
		case len(f) >= 4 && f[0] == "auth-client":
			clients = append(clients, authClient{
				clientID:        decodeB64(f[1]),
				iv:              decodeB64(f[2]),
				encryptedCookie: decodeB64(f[3]),
			})
		}
	}
	return ephemPub, clients
}
