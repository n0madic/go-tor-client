package onion

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// descSigPrefix prefixes the signed portion of a v3 descriptor (rend-spec-v3).
const descSigPrefix = "Tor onion service descriptor sig v3"

// VerifyDescriptorSignature checks the outer descriptor's authenticity: the
// descriptor-signing-key-cert must be signed by the period's blinded key, and
// the descriptor signature must verify under the certified signing key. This
// prevents a malicious HSDir from substituting a forged descriptor.
func VerifyDescriptorSignature(raw, blindedKey []byte) error {
	certDER := extractCert(raw, "descriptor-signing-key-cert")
	if certDER == nil {
		return errors.New("onion: descriptor missing signing-key cert")
	}
	signingKey, err := verifyDescCert(certDER, blindedKey)
	if err != nil {
		return err
	}

	marker := []byte("\nsignature ")
	idx := bytes.Index(raw, marker)
	if idx < 0 {
		return errors.New("onion: descriptor missing signature line")
	}
	// The signed data covers the descriptor up to and including the newline
	// that precedes the "signature" keyword (the keyword itself is excluded),
	// prefixed by the constant string.
	signed := append([]byte(descSigPrefix), raw[:idx+1]...)

	// The signature value follows the "signature " token to end of line.
	rest := raw[idx+len(marker):]
	if nl := bytes.IndexByte(rest, '\n'); nl >= 0 {
		rest = rest[:nl]
	}
	sig := decodeB64(strings.TrimSpace(string(rest)))
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("onion: bad descriptor signature length %d", len(sig))
	}
	if !ed25519.Verify(signingKey, signed, sig) {
		return errors.New("onion: descriptor signature invalid")
	}
	return nil
}

// verifyDescCert parses a Tor ed25519 cert, checks it is signed by blindedKey
// (carried in the signed-with-ed25519-key extension and matching the expected
// blinded key), and returns the certified signing key.
func verifyDescCert(cert, blindedKey []byte) ([]byte, error) {
	// VER(1)|TYPE(1)|EXP(4)|KEYTYPE(1)|CERTIFIED_KEY(32)|N_EXT(1)|exts|SIG(64)
	if len(cert) < 1+1+4+1+32+1+64 {
		return nil, errors.New("onion: short descriptor cert")
	}
	signingKey := append([]byte(nil), cert[7:39]...)
	nExt := int(cert[39])
	pos := 40
	var signer []byte
	for range nExt {
		if pos+4 > len(cert) {
			return nil, errors.New("onion: truncated cert extension")
		}
		extLen := int(cert[pos])<<8 | int(cert[pos+1])
		extType := cert[pos+2]
		pos += 4
		if pos+extLen > len(cert) {
			return nil, errors.New("onion: cert extension overflow")
		}
		if extType == 0x04 && extLen == 32 {
			signer = append([]byte(nil), cert[pos:pos+32]...)
		}
		pos += extLen
	}
	if signer == nil {
		return nil, errors.New("onion: cert missing signer-key extension")
	}
	if !bytes.Equal(signer, blindedKey) {
		return nil, errors.New("onion: cert not signed by expected blinded key")
	}
	if pos+64 > len(cert) {
		return nil, errors.New("onion: cert missing signature")
	}
	sig := cert[len(cert)-64:]
	signed := cert[:len(cert)-64]
	if !ed25519.Verify(signer, signed, sig) {
		return nil, errors.New("onion: descriptor cert signature invalid")
	}
	return signingKey, nil
}

// extractCert returns the decoded bytes of the ED25519 CERT PEM block that
// follows the given keyword line.
func extractCert(raw []byte, keyword string) []byte {
	kw := []byte("\n" + keyword + "\n")
	idx := bytes.Index(raw, kw)
	start := 0
	if idx < 0 {
		if bytes.HasPrefix(raw, []byte(keyword+"\n")) {
			start = len(keyword) + 1
		} else {
			return nil
		}
	} else {
		start = idx + len(kw)
	}
	begin := []byte("-----BEGIN ED25519 CERT-----")
	end := []byte("-----END ED25519 CERT-----")
	bIdx := bytes.Index(raw[start:], begin)
	if bIdx < 0 {
		return nil
	}
	bIdx += start
	eIdx := bytes.Index(raw[bIdx:], end)
	if eIdx < 0 {
		return nil
	}
	b64 := raw[bIdx+len(begin) : bIdx+eIdx]
	cleaned := strings.ReplaceAll(strings.ReplaceAll(string(b64), "\n", ""), "\r", "")
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cleaned))
	if err != nil {
		return nil
	}
	return dec
}
