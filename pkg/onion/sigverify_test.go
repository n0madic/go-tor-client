package onion

import (
	"bytes"
	"os"
	"testing"
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

	if err := VerifyDescriptorSignature(raw, blinded); err != nil {
		t.Fatalf("VerifyDescriptorSignature on real descriptor: %v", err)
	}

	// Tampering with a signed byte must fail verification.
	tampered := append([]byte(nil), raw...)
	// Flip a byte inside descriptor-lifetime value (within the signed region).
	if i := bytes.Index(tampered, []byte("descriptor-lifetime ")); i >= 0 {
		tampered[i+20] ^= 0x01
		if err := VerifyDescriptorSignature(tampered, blinded); err == nil {
			t.Fatal("expected signature failure on tampered descriptor")
		}
	}
}
