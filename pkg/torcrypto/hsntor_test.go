package torcrypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// TestHSNtorVector validates the hs_ntor handshake against the official test
// vector in rend-spec-v3 Appendix G.
func TestHSNtorVector(t *testing.T) {
	t.Parallel()
	authKey := mustHex(t, "34E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F")
	encKeyB := mustHex(t, "8E5127A40E83AABF6493E41F142B6EE3604B85A3961CD7E38D247239AFF71979")
	subcred := mustHex(t, "0085D26A9DEBA252263BF0231AEAC59B17CA11BAD8A218238AD6487CBAD68B57")
	x := mustHex(t, "60B4D6BF5234DCF87A4E9D7487BDF3F4A69B6729835E825CA29089CFDDA1E341")
	wantX := mustHex(t, "BF04348B46D09AED726F1D66C618FDEA1DE58E8CB8B89738D7356A0C59111D5D")
	wantEncKey := mustHex(t, "9B8917BA3D05F3130DACCE5300C3DC27F6D012912F1C733036F822D0ED238706")
	wantMacKey := mustHex(t, "FC4058DA59D4DF61E7B40985D122F502FD59336BC21C30CAF5E7F0D4A2C38FD5")
	serverY := mustHex(t, "8FBE0DB4D4A9C7FF46701E3E0EE7FD05CD28BE4F302460ADDEEC9E93354EE700")
	wantAuth := mustHex(t, "4A92E8437B8424D5E5EC279245D5C72B25A0327ACF6DAF902079FCB643D8B208")
	wantSeed := mustHex(t, "4D0C72FE8AFF35559D95ECC18EB5A36883402B28CDFD48C8A530A5A3D7D578DB")

	eph, err := newX25519FromSeed(x)
	if err != nil {
		t.Fatalf("seed key: %v", err)
	}

	encKey, macKey, clientX, state, err := hsNtorIntroWith(encKeyB, authKey, subcred, eph)
	if err != nil {
		t.Fatalf("HSNtorClientIntro: %v", err)
	}
	if !bytes.Equal(clientX, wantX) {
		t.Fatalf("X = %X, want %X", clientX, wantX)
	}
	if !bytes.Equal(encKey, wantEncKey) {
		t.Fatalf("ENC_KEY = %X, want %X", encKey, wantEncKey)
	}
	if !bytes.Equal(macKey, wantMacKey) {
		t.Fatalf("MAC_KEY = %X, want %X", macKey, wantMacKey)
	}

	seed, err := state.Finish(serverY, wantAuth)
	if err != nil {
		t.Fatalf("Finish (AUTH verification): %v", err)
	}
	if !bytes.Equal(seed, wantSeed) {
		t.Fatalf("NTOR_KEY_SEED = %X, want %X", seed, wantSeed)
	}
}

func TestHSNtorAuthRejected(t *testing.T) {
	t.Parallel()
	authKey := mustHex(t, "34E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F")
	encKeyB := mustHex(t, "8E5127A40E83AABF6493E41F142B6EE3604B85A3961CD7E38D247239AFF71979")
	subcred := mustHex(t, "0085D26A9DEBA252263BF0231AEAC59B17CA11BAD8A218238AD6487CBAD68B57")
	x := mustHex(t, "60B4D6BF5234DCF87A4E9D7487BDF3F4A69B6729835E825CA29089CFDDA1E341")
	serverY := mustHex(t, "8FBE0DB4D4A9C7FF46701E3E0EE7FD05CD28BE4F302460ADDEEC9E93354EE700")
	badAuth := mustHex(t, "0000000000000000000000000000000000000000000000000000000000000000")

	eph, _ := newX25519FromSeed(x)
	_, _, _, state, err := hsNtorIntroWith(encKeyB, authKey, subcred, eph)
	if err != nil {
		t.Fatalf("intro: %v", err)
	}
	if _, err := state.Finish(serverY, badAuth); err != ErrHSNtorAuth {
		t.Fatalf("Finish err = %v, want ErrHSNtorAuth", err)
	}
}
