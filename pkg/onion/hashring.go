package onion

import (
	"bytes"
	"encoding/binary"
	"sort"

	"github.com/n0madic/go-tor-client/pkg/torcrypto"
)

// RingNode is an HSDir candidate: its Ed25519 identity (for the ring index) and
// an opaque payload the caller uses to connect to it.
type RingNode struct {
	EdID    []byte
	Payload any
}

// ResponsibleHSDirs returns the HSDirs responsible for a blinded key in a time
// period, given the shared-random value. It mirrors rend-spec-v3
// [WHERE-HSDESC]: for each replica, take the first hsDirSpreadFetch nodes whose
// ring index immediately follows the service index, skipping duplicates.
func ResponsibleHSDirs(blindedKey []byte, periodNum, periodLength uint64, srv []byte, nodes []RingNode) []RingNode {
	type ringEntry struct {
		idx  []byte
		node RingNode
	}
	ring := make([]ringEntry, 0, len(nodes))
	for _, n := range nodes {
		if len(n.EdID) != 32 {
			continue
		}
		ring = append(ring, ringEntry{idx: nodeIndex(n.EdID, srv, periodNum, periodLength), node: n})
	}
	sort.Slice(ring, func(i, j int) bool {
		return bytes.Compare(ring[i].idx, ring[j].idx) < 0
	})
	if len(ring) == 0 {
		return nil
	}

	chosen := make(map[string]bool)
	var out []RingNode
	for replica := uint64(1); replica <= hsDirNReplicas; replica++ {
		svcIdx := serviceIndex(blindedKey, replica, periodLength, periodNum)
		// First node whose index is > svcIdx (wrapping).
		start := sort.Search(len(ring), func(i int) bool {
			return bytes.Compare(ring[i].idx, svcIdx) > 0
		})
		taken := 0
		for off := 0; off < len(ring) && taken < hsDirSpreadFetch; off++ {
			e := ring[(start+off)%len(ring)]
			key := string(e.node.EdID)
			if chosen[key] {
				continue
			}
			chosen[key] = true
			out = append(out, e.node)
			taken++
		}
	}
	return out
}

// serviceIndex = SHA3-256("store-at-idx" | blinded_pubkey | INT_8(replica) |
// INT_8(period_length) | INT_8(period_num)).
func serviceIndex(blindedKey []byte, replica, periodLength, periodNum uint64) []byte {
	return torcrypto.SHA3_256(
		[]byte("store-at-idx"),
		blindedKey,
		int8be(replica),
		int8be(periodLength),
		int8be(periodNum),
	)
}

// nodeIndex = SHA3-256("node-idx" | node_ed_identity | srv | INT_8(period_num) |
// INT_8(period_length)).
func nodeIndex(edID, srv []byte, periodNum, periodLength uint64) []byte {
	return torcrypto.SHA3_256(
		[]byte("node-idx"),
		edID,
		srv,
		int8be(periodNum),
		int8be(periodLength),
	)
}

func int8be(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}
