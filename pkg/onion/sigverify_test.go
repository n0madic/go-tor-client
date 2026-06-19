package onion

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"os"
	"testing"
	"time"
)

// buildTorCert assembles a Tor ed25519 certificate (cert-spec.txt) certifying
// certifiedKey, signed by signerPriv, with the signer key carried in the
// signed-with-ed25519-key extension.
func buildTorCert(certType byte, certifiedKey []byte, signerPub ed25519.PublicKey, signerPriv ed25519.PrivateKey, exp uint32) []byte {
	b := []byte{0x01, certType, byte(exp >> 24), byte(exp >> 16), byte(exp >> 8), byte(exp), 0x01}
	b = append(b, certifiedKey...) // CERTIFIED_KEY (32)
	b = append(b, 0x01)            // N_EXT
	b = append(b, 0x00, 0x20, certExtSignerKey, 0x00)
	b = append(b, signerPub...) // ext data: signer key (32)
	return append(b, ed25519.Sign(signerPriv, b)...)
}

// TestVerifyTorCertAuthKey exercises verifyTorCert on intro-point auth-key
// certs (type [09]): a valid cert yields its certified key, and wrong signer,
// wrong type, expiry, and a tampered signature are all rejected.
func TestVerifyTorCertAuthKey(t *testing.T) {
	t.Parallel()
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	authPub, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	exp := uint32(now.Add(24*time.Hour).Unix() / 3600)

	cert := buildTorCert(introAuthCertID, authPub, signPub, signPriv, exp)
	got, err := verifyTorCert(cert, signPub, introAuthCertID, now)
	if err != nil {
		t.Fatalf("verifyTorCert on a valid auth cert: %v", err)
	}
	if !bytes.Equal(got, authPub) {
		t.Fatalf("certified key = %x, want %x", got, authPub)
	}

	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := verifyTorCert(cert, otherPub, introAuthCertID, now); err == nil {
		t.Error("accepted a cert with the wrong expected signer")
	}
	if _, err := verifyTorCert(cert, signPub, descCertType, now); err == nil {
		t.Error("accepted a cert with the wrong cert type")
	}
	expired := buildTorCert(introAuthCertID, authPub, signPub, signPriv, uint32(now.Add(-time.Hour).Unix()/3600))
	if _, err := verifyTorCert(expired, signPub, introAuthCertID, now); err == nil {
		t.Error("accepted an expired cert")
	}
	tampered := append([]byte(nil), cert...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := verifyTorCert(tampered, signPub, introAuthCertID, now); err == nil {
		t.Error("accepted a cert with a tampered signature")
	}
}

// TestDescriptorSignatureFixture verifies the descriptor signature path against
// a real captured v3 descriptor (the Tor Project onion) and its blinded key.
func TestDescriptorSignatureFixture(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/descriptor.txt")
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	blinded, err := os.ReadFile("testdata/blinded.bin")
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}

	// The captured cert has long since expired in wall-clock terms, so anchor
	// "now" just before its own expiration (EXP is hours since the epoch at
	// cert[2:6]) to exercise the signature path without a stale-cert rejection.
	cert := extractCert(raw, "descriptor-signing-key-cert")
	if cert == nil {
		t.Fatal("fixture missing descriptor-signing-key-cert")
	}
	expiry := time.Unix(int64(binary.BigEndian.Uint32(cert[2:6]))*3600, 0)
	now := expiry.Add(-time.Hour)

	if err := VerifyDescriptorSignature(raw, blinded, now); err != nil {
		t.Fatalf("VerifyDescriptorSignature on real descriptor: %v", err)
	}

	// A cert past its expiration must be rejected.
	if err := VerifyDescriptorSignature(raw, blinded, expiry.Add(time.Hour)); err == nil {
		t.Fatal("expected expired-cert rejection")
	}

	// Tampering with a signed byte must fail verification.
	tampered := append([]byte(nil), raw...)
	// Flip a byte inside descriptor-lifetime value (within the signed region).
	if i := bytes.Index(tampered, []byte("descriptor-lifetime ")); i >= 0 {
		tampered[i+20] ^= 0x01
		if err := VerifyDescriptorSignature(tampered, blinded, now); err == nil {
			t.Fatal("expected signature failure on tampered descriptor")
		}
	}
}
