package circuit

import "testing"

// TestLinkSpecifiersPortParsing locks in strict ORPort parsing: a port with
// trailing garbage or out of range is rejected rather than silently truncated.
func TestLinkSpecifiersPortParsing(t *testing.T) {
	t.Parallel()
	base := RelayInfo{
		Nickname:     "r",
		RSAIDDigest:  make([]byte, 20),
		EdIdentity:   make([]byte, 32),
		NtorOnionKey: make([]byte, 32),
	}

	valid := base
	valid.ORAddr = "1.2.3.4:443"
	if _, err := valid.LinkSpecifiers(); err != nil {
		t.Fatalf("valid port 443 was rejected: %v", err)
	}

	for _, bad := range []string{
		"1.2.3.4:443x",  // trailing garbage
		"1.2.3.4:99999", // out of 16-bit range
		"1.2.3.4:-1",    // negative
		"1.2.3.4: 443",  // leading space
		"1.2.3.4:0x1bb", // hex
	} {
		ri := base
		ri.ORAddr = bad
		if _, err := ri.LinkSpecifiers(); err == nil {
			t.Errorf("LinkSpecifiers(ORAddr=%q) accepted a bad port", bad)
		}
	}
}
