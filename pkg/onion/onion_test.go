package onion

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func TestAddressRoundTrip(t *testing.T) {
	t.Parallel()
	pub := make([]byte, 32)
	if _, err := rand.Read(pub); err != nil {
		t.Fatal(err)
	}
	addr := Address{PublicKey: pub}
	s := addr.String()
	if len(s) != addressB32Len+len(onionSuffix) {
		t.Fatalf("address length = %d", len(s))
	}

	parsed, err := ParseAddress(s)
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}
	if !bytes.Equal(parsed.PublicKey, pub) {
		t.Fatal("round-trip public key mismatch")
	}

	// Corrupting the checksum (flip a char) must fail.
	bad := []byte(s)
	bad[0] = pickDifferent(bad[0])
	if _, err := ParseAddress(string(bad)); err == nil {
		t.Fatal("expected checksum failure on corrupted address")
	}
}

func pickDifferent(c byte) byte {
	if c == 'a' {
		return 'b'
	}
	return 'a'
}

func TestTimePeriodVector(t *testing.T) {
	t.Parallel()
	// rend-spec-v3 example: 24341715 minutes since epoch -> time period 16903.
	now := time.Unix(24341715*60, 0)
	num, length := TimePeriod(now)
	if num != 16903 {
		t.Fatalf("time period = %d, want 16903", num)
	}
	if length != 1440 {
		t.Fatalf("period length = %d, want 1440", length)
	}
}

func TestSRVForFetchWindow(t *testing.T) {
	t.Parallel()
	cur := bytes.Repeat([]byte{0x11}, 32)
	prev := bytes.Repeat([]byte{0x22}, 32)

	afternoon := time.Date(2026, 6, 14, 13, 0, 0, 0, time.UTC) // [12,24) -> current
	if got := SRVForFetch(afternoon, cur, prev); !bytes.Equal(got, cur) {
		t.Fatal("afternoon should select current SRV")
	}
	morning := time.Date(2026, 6, 14, 1, 0, 0, 0, time.UTC) // [0,12) -> previous
	if got := SRVForFetch(morning, cur, prev); !bytes.Equal(got, prev) {
		t.Fatal("morning should select previous SRV")
	}
}

func TestResponsibleHSDirsDeterministic(t *testing.T) {
	t.Parallel()
	nodes := make([]RingNode, 30)
	for i := range nodes {
		ed := make([]byte, 32)
		ed[0] = byte(i)
		ed[1] = 0x5a
		nodes[i] = RingNode{EdID: ed, Payload: i}
	}
	blinded := bytes.Repeat([]byte{0x07}, 32)
	srv := bytes.Repeat([]byte{0x09}, 32)

	a := ResponsibleHSDirs(blinded, 16903, 1440, srv, nodes)
	b := ResponsibleHSDirs(blinded, 16903, 1440, srv, nodes)
	if len(a) == 0 || len(a) > hsDirNReplicas*hsDirSpreadFetch {
		t.Fatalf("got %d responsible dirs", len(a))
	}
	if len(a) != len(b) {
		t.Fatal("non-deterministic selection")
	}
	for i := range a {
		if a[i].Payload != b[i].Payload {
			t.Fatal("selection order differs between runs")
		}
	}
	// Distinct nodes only.
	seen := map[any]bool{}
	for _, n := range a {
		if seen[n.Payload] {
			t.Fatal("duplicate HSDir in result")
		}
		seen[n.Payload] = true
	}
}

// TestReadCertBlockNoSwallow checks that a PEM cert block missing its END marker
// does not consume the following introduction-point fields (regression: a
// malformed auth-key block used to swallow subsequent intro points).
func TestReadCertBlockNoSwallow(t *testing.T) {
	t.Parallel()

	// Valid block: returns decoded bytes and the index just past END.
	valid := []string{
		"-----BEGIN ED25519 CERT-----",
		"AAAA",
		"-----END ED25519 CERT-----",
		"enc-key ntor abc",
	}
	cert, next := readCertBlock(valid, 0)
	if len(cert) != 3 {
		t.Fatalf("valid block: decoded %d bytes, want 3", len(cert))
	}
	if next != 3 {
		t.Fatalf("valid block: next = %d, want 3 (the enc-key line)", next)
	}

	// Missing END: stop at the next keyword WITHOUT consuming it.
	malformed := []string{
		"-----BEGIN ED25519 CERT-----",
		"AAAA",
		"introduction-point second",
		"onion-key ntor xyz",
	}
	cert, next = readCertBlock(malformed, 0)
	if cert != nil {
		t.Fatalf("malformed block: want nil, got %d bytes", len(cert))
	}
	if next != 2 {
		t.Fatalf("malformed block: next = %d, want 2 (the introduction-point line, not consumed)", next)
	}

	// No block at the position: consume nothing.
	if cert, next = readCertBlock([]string{"onion-key ntor xyz"}, 0); cert != nil || next != 0 {
		t.Fatalf("no block: got (%v, %d), want (nil, 0)", cert, next)
	}
}
