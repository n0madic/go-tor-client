package onion

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
	"time"
)

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
