package directory

import (
	"encoding/hex"
	"testing"
)

func mustHexID(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseFamily(t *testing.T) {
	t.Parallel()
	got := parseFamily([]string{
		"$AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555",
		"$ffff0000ffff0000ffff0000ffff0000ffff0000=nick",
		"$1234567890123456789012345678901234567890~other",
		"plainnickname", // ignored
		"$short",        // ignored
	})
	want := []string{
		"AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555",
		"FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000",
		"1234567890123456789012345678901234567890",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSameFamilyMutual(t *testing.T) {
	t.Parallel()
	idA := mustHexID(t, "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555")
	idB := mustHexID(t, "1234567890123456789012345678901234567890")

	// Mutual declaration -> same family.
	a := Microdescriptor{Family: []string{"1234567890123456789012345678901234567890"}}
	b := Microdescriptor{Family: []string{"AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"}}
	if !SameFamily(a, idA, b, idB) {
		t.Fatal("mutual family not detected")
	}

	// One-sided declaration -> NOT same family (Tor requires mutual).
	bOneSided := Microdescriptor{Family: nil}
	if SameFamily(a, idA, bOneSided, idB) {
		t.Fatal("one-sided declaration must not count as same family")
	}

	// Unrelated relays.
	if SameFamily(Microdescriptor{}, idA, Microdescriptor{}, idB) {
		t.Fatal("unrelated relays flagged as family")
	}
}
