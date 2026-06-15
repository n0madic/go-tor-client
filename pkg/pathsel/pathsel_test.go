package pathsel

import (
	"testing"

	"github.com/n0madic/go-tor-client/pkg/directory"
)

func relay(nick, ip string, bw int, flags ...string) directory.RouterStatus {
	fm := map[string]bool{}
	for _, f := range flags {
		fm[f] = true
	}
	return directory.RouterStatus{
		Nickname:      nick,
		Identity:      []byte(nick + "_id_padding_to20!!"[:20-len(nick)]),
		IP:            ip,
		Bandwidth:     bw,
		MicrodescHash: "hash-" + nick,
		Flags:         fm,
	}
}

func testConsensus() *directory.Consensus {
	return &directory.Consensus{
		Weights: map[string]int{
			"Wgg": 10000, "Wgd": 5000,
			"Wmg": 5000, "Wme": 0, "Wmd": 0, "Wmm": 10000,
			"Wee": 10000, "Wed": 5000,
		},
		Routers: []directory.RouterStatus{
			relay("guardA", "10.1.0.1", 1000, "Running", "Valid", "Guard", "Fast", "Stable"),
			relay("guardB", "10.1.0.2", 1000, "Running", "Valid", "Guard", "Fast", "Stable"),
			relay("middleA", "10.2.0.1", 1000, "Running", "Valid", "Fast"),
			relay("exitA", "10.3.0.1", 1000, "Running", "Valid", "Exit", "Fast"),
			relay("exitB", "10.3.0.2", 1000, "Running", "Valid", "Exit", "Fast", "BadExit"),
			relay("downX", "10.9.0.1", 1000, "Valid", "Guard", "Fast", "Stable"), // not Running
		},
	}
}

func TestSelectGuard(t *testing.T) {
	t.Parallel()
	s := New(testConsensus())
	for range 50 {
		g, err := s.SelectGuard()
		if err != nil {
			t.Fatalf("SelectGuard: %v", err)
		}
		if !g.HasFlag("Guard") || !g.HasFlag("Running") {
			t.Fatalf("guard %s lacks required flags", g.Nickname)
		}
		if g.Nickname == "downX" {
			t.Fatal("selected a non-Running relay")
		}
	}
}

func TestSelectExitSkipsBadExit(t *testing.T) {
	t.Parallel()
	s := New(testConsensus())
	for range 50 {
		e, err := s.SelectExit(nil)
		if err != nil {
			t.Fatalf("SelectExit: %v", err)
		}
		if e.Nickname == "exitB" {
			t.Fatal("selected a BadExit relay")
		}
		if e.Nickname != "exitA" {
			t.Fatalf("unexpected exit %s", e.Nickname)
		}
	}
}

func TestExclusionSameSlash16(t *testing.T) {
	t.Parallel()
	s := New(testConsensus())
	guardA := &s.cons.Routers[0] // 10.1.0.1
	// guardB is 10.1.0.2, same /16 -> must be excluded, leaving none.
	if _, err := s.SelectGuard(guardA); err != ErrNoRelay {
		t.Fatalf("expected ErrNoRelay after /16 exclusion, got %v", err)
	}
}

func TestExitPolicyFilter(t *testing.T) {
	t.Parallel()
	s := New(testConsensus())
	// Allow only a relay that does not exist as exit -> ErrNoRelay.
	_, err := s.SelectExit(func(r *directory.RouterStatus) bool { return r.Nickname == "nope" })
	if err != ErrNoRelay {
		t.Fatalf("expected ErrNoRelay, got %v", err)
	}
}
