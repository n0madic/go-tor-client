package onion

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

// descSigPrefix prefixes the signed portion of a v3 descriptor (rend-spec-v3).
const descSigPrefix = "Tor onion service descriptor sig v3"

// descriptor-signing-key-cert fields (cert-spec.txt / rend-spec-v3 [DESC-OUTER]):
// an ed25519 cert (version 1), type [08] (cross-certified by the period's
// blinded key), certifying an ed25519 key (key type [01]).
const (
	descCertVersion  = 0x01
	descCertType     = 0x08 // blinded key -> descriptor signing key cross-cert
	introAuthCertID  = 0x09 // descriptor signing key -> intro point auth key
	descCertKeyType  = 0x01 // certified key is an ed25519 key
	certExtSignerKey = 0x04 // signed-with-ed25519-key extension
)

// VerifyDescriptorSignature checks the outer descriptor's authenticity: the
// descriptor-signing-key-cert must be signed by the period's blinded key, and
// the descriptor signature must verify under the certified signing key. This
// prevents a malicious HSDir from substituting a forged descriptor.
func VerifyDescriptorSignature(raw, blindedKey []byte, now time.Time) error {
	_, err := verifyDescriptorSignature(raw, blindedKey, now)
	return err
}

// verifyDescriptorSignature is VerifyDescriptorSignature that also returns the
// certified descriptor signing key, so the caller can verify the intro-point
// auth-key certificates carried in the inner layer against it.
func verifyDescriptorSignature(raw, blindedKey []byte, now time.Time) ([]byte, error) {
	certDER := extractCert(raw, "descriptor-signing-key-cert")
	if certDER == nil {
		return nil, errors.New("onion: descriptor missing signing-key cert")
	}
	signingKey, err := verifyTorCert(certDER, blindedKey, descCertType, now)
	if err != nil {
		return nil, err
	}

	marker := []byte("\nsignature ")
	idx := bytes.Index(raw, marker)
	if idx < 0 {
		return nil, errors.New("onion: descriptor missing signature line")
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
		return nil, fmt.Errorf("onion: bad descriptor signature length %d", len(sig))
	}
	if !ed25519.Verify(signingKey, signed, sig) {
		return nil, errors.New("onion: descriptor signature invalid")
	}
	return signingKey, nil
}

// verifyTorCert parses a Tor ed25519 cert (cert-spec.txt), enforces its version,
// the expected cert type, and ed25519 key type, checks expiration, verifies it
// is signed by expectedSigner (which must also appear in the
// signed-with-ed25519-key extension), and returns the 32-byte certified key.
func verifyTorCert(cert, expectedSigner []byte, wantType byte, now time.Time) ([]byte, error) {
	// VER(1)|TYPE(1)|EXP(4)|KEYTYPE(1)|CERTIFIED_KEY(32)|N_EXT(1)|exts|SIG(64)
	if len(cert) < 1+1+4+1+32+1+64 {
		return nil, errors.New("onion: short ed25519 cert")
	}
	if cert[0] != descCertVersion {
		return nil, fmt.Errorf("onion: cert version %d, want %d", cert[0], descCertVersion)
	}
	if cert[1] != wantType {
		return nil, fmt.Errorf("onion: cert type 0x%02x, want 0x%02x", cert[1], wantType)
	}
	if cert[6] != descCertKeyType {
		return nil, fmt.Errorf("onion: cert key type 0x%02x, want 0x%02x", cert[6], descCertKeyType)
	}
	// EXP is hours since the Unix epoch (cert-spec.txt); reject a stale cert.
	expiry := time.Unix(int64(binary.BigEndian.Uint32(cert[2:6]))*3600, 0)
	if now.After(expiry) {
		return nil, fmt.Errorf("onion: cert expired at %s", expiry.UTC().Format(time.RFC3339))
	}
	certifiedKey := append([]byte(nil), cert[7:39]...)
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
		if extType == certExtSignerKey && extLen == 32 {
			signer = append([]byte(nil), cert[pos:pos+32]...)
		}
		pos += extLen
	}
	if signer == nil {
		return nil, errors.New("onion: cert missing signer-key extension")
	}
	if expectedSigner != nil && !bytes.Equal(signer, expectedSigner) {
		return nil, errors.New("onion: cert not signed by expected key")
	}
	if pos+64 > len(cert) {
		return nil, errors.New("onion: cert missing signature")
	}
	sig := cert[len(cert)-64:]
	signed := cert[:len(cert)-64]
	if !ed25519.Verify(signer, signed, sig) {
		return nil, errors.New("onion: cert signature invalid")
	}
	return certifiedKey, nil
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
