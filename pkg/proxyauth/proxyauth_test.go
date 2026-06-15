package proxyauth

import "testing"

func TestIsoKey(t *testing.T) {
	cases := []struct {
		name       string
		user, pass string
		want       string
	}{
		{"no auth", "", "", ""},
		{"user and pass", "alice", "secret", "alice\x00secret"},
		{"empty pass", "alice", "", "alice\x00"},
		{"empty user", "", "secret", "\x00secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsoKey(tc.user, tc.pass); got != tc.want {
				t.Fatalf("IsoKey(%q, %q) = %q, want %q", tc.user, tc.pass, got, tc.want)
			}
		})
	}
}

// TestIsoKeyDistinct guards the property the isolation boundary relies on: the
// NUL separator makes the (user, pass) → key mapping unambiguous, so identities
// that differ only in where the split falls never collide.
func TestIsoKeyDistinct(t *testing.T) {
	if IsoKey("a", "bc") == IsoKey("ab", "c") {
		t.Fatal("IsoKey collided for (a, bc) and (ab, c); the separator must keep them distinct")
	}
	if IsoKey("", "") == IsoKey("", "x") {
		t.Fatal("no-auth identity must not collide with a credentialed one")
	}
}
