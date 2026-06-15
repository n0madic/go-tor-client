// Package pathsel selects circuit paths from a verified consensus: flag
// filtering, bandwidth-weighted sampling, and basic position exclusions
// (same relay, same /16). Family exclusion is not yet implemented (it requires
// per-relay family data) and is noted as a stage-1 simplification.
package pathsel

import (
	"crypto/rand"
	"errors"
	"math/big"
	"net"

	"github.com/n0madic/go-tor-client/pkg/directory"
)

// ErrNoRelay is returned when no eligible relay matches a position.
var ErrNoRelay = errors.New("pathsel: no eligible relay")

// Selector picks relays from a consensus.
type Selector struct {
	cons *directory.Consensus
}

// New builds a selector over a verified consensus.
func New(cons *directory.Consensus) *Selector { return &Selector{cons: cons} }

// Consensus exposes the underlying consensus.
func (s *Selector) Consensus() *directory.Consensus { return s.cons }

// SelectGuard chooses an entry guard (Guard+Fast+Stable), weighted for the
// guard position.
func (s *Selector) SelectGuard(exclude ...*directory.RouterStatus) (*directory.RouterStatus, error) {
	return s.selectWeighted(
		func(r *directory.RouterStatus) bool {
			return r.HasFlag("Guard") && r.HasFlag("Fast") && r.HasFlag("Stable")
		},
		func(r *directory.RouterStatus) int64 {
			key := "Wgg"
			if r.HasFlag("Exit") {
				key = "Wgd"
			}
			return s.weightedBw(r, key)
		},
		exclude,
	)
}

// SelectMiddle chooses a middle relay (Fast), weighted for the middle position.
func (s *Selector) SelectMiddle(exclude ...*directory.RouterStatus) (*directory.RouterStatus, error) {
	return s.selectWeighted(
		func(r *directory.RouterStatus) bool { return r.HasFlag("Fast") },
		func(r *directory.RouterStatus) int64 {
			key := middleWeightKey(r)
			return s.weightedBw(r, key)
		},
		exclude,
	)
}

// SelectExit chooses an exit (Exit+Fast and not BadExit) matching allow,
// weighted for the exit position. allow may be nil.
func (s *Selector) SelectExit(allow func(*directory.RouterStatus) bool, exclude ...*directory.RouterStatus) (*directory.RouterStatus, error) {
	return s.selectWeighted(
		func(r *directory.RouterStatus) bool {
			if !r.HasFlag("Exit") || !r.HasFlag("Fast") || r.HasFlag("BadExit") {
				return false
			}
			return allow == nil || allow(r)
		},
		func(r *directory.RouterStatus) int64 {
			key := "Wee"
			if r.HasFlag("Guard") {
				key = "Wed"
			}
			return s.weightedBw(r, key)
		},
		exclude,
	)
}

// SelectDirCache chooses a relay that can serve directory documents over
// BEGIN_DIR (Fast + V2Dir), weighted for the middle position.
func (s *Selector) SelectDirCache(exclude ...*directory.RouterStatus) (*directory.RouterStatus, error) {
	return s.selectWeighted(
		func(r *directory.RouterStatus) bool { return r.HasFlag("Fast") && r.HasFlag("V2Dir") },
		func(r *directory.RouterStatus) int64 { return s.weightedBw(r, middleWeightKey(r)) },
		exclude,
	)
}

func middleWeightKey(r *directory.RouterStatus) string {
	guard, exit := r.HasFlag("Guard"), r.HasFlag("Exit")
	switch {
	case guard && exit:
		return "Wmd"
	case guard:
		return "Wmg"
	case exit:
		return "Wme"
	default:
		return "Wmm"
	}
}

// weightedBw returns the relay's effective bandwidth for a position weight key.
func (s *Selector) weightedBw(r *directory.RouterStatus, key string) int64 {
	w, ok := s.cons.Weights[key]
	if !ok {
		w = 10000
	}
	return int64(r.Bandwidth) * int64(w) / 10000
}

func (s *Selector) selectWeighted(
	eligible func(*directory.RouterStatus) bool,
	weight func(*directory.RouterStatus) int64,
	exclude []*directory.RouterStatus,
) (*directory.RouterStatus, error) {
	type cand struct {
		r *directory.RouterStatus
		w int64
	}
	var cands []cand
	var total int64
	for i := range s.cons.Routers {
		r := &s.cons.Routers[i]
		if !baseEligible(r) || !eligible(r) {
			continue
		}
		if excludedBy(r, exclude) {
			continue
		}
		w := weight(r)
		if w <= 0 {
			continue
		}
		cands = append(cands, cand{r, w})
		total += w
	}
	if total == 0 {
		return nil, ErrNoRelay
	}
	pick := randInt63n(total)
	for _, c := range cands {
		if pick < c.w {
			return c.r, nil
		}
		pick -= c.w
	}
	return cands[len(cands)-1].r, nil
}

func baseEligible(r *directory.RouterStatus) bool {
	return r.HasFlag("Running") && r.HasFlag("Valid") && r.Bandwidth > 0 && r.MicrodescHash != ""
}

// excludedBy reports whether r duplicates, or shares a /16 with, any excluded
// relay.
func excludedBy(r *directory.RouterStatus, exclude []*directory.RouterStatus) bool {
	rIP := net.ParseIP(r.IP)
	for _, e := range exclude {
		if e == nil {
			continue
		}
		if string(r.Identity) == string(e.Identity) {
			return true
		}
		if sameSlash16(rIP, net.ParseIP(e.IP)) {
			return true
		}
	}
	return false
}

func sameSlash16(a, b net.IP) bool {
	a4, b4 := a.To4(), b.To4()
	if a4 == nil || b4 == nil {
		return false
	}
	return a4[0] == b4[0] && a4[1] == b4[1]
}

func randInt63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		panic("pathsel: crypto/rand failed: " + err.Error())
	}
	return v.Int64()
}
