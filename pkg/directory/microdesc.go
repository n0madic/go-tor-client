package directory

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
)

// Microdescriptor holds the relay data a client needs that is not in the
// consensus: the ntor onion key, the Ed25519 identity, and the exit policy
// summary.
type Microdescriptor struct {
	NtorOnionKey []byte
	Ed25519ID    []byte
	ExitPolicy   ExitPolicy
	Digest       string   // base64 (unpadded) SHA-256, matches a consensus "m" line
	Raw          []byte   // exact bytes of this microdescriptor (for caching)
	Family       []string // declared family member RSA fingerprints (upper hex)
}

// ExitPolicy is the relay's port-summary policy ("p" line).
type ExitPolicy struct {
	IsAccept bool
	Ports    []PortRange
}

// PortRange is an inclusive port interval.
type PortRange struct{ Lo, Hi int }

// Allows reports whether the policy permits exiting to the given TCP port.
func (p ExitPolicy) Allows(port int) bool {
	in := false
	for _, r := range p.Ports {
		if port >= r.Lo && port <= r.Hi {
			in = true
			break
		}
	}
	if p.IsAccept {
		return in
	}
	return !in
}

// ParseMicrodescriptors splits and parses a concatenated microdescriptor
// document, computing each one's digest so callers can match consensus "m"
// lines.
func ParseMicrodescriptors(raw []byte) []Microdescriptor {
	marker := []byte("onion-key\n")
	var starts []int
	for i := 0; i+len(marker) <= len(raw); i++ {
		if (i == 0 || raw[i-1] == '\n') && bytes.HasPrefix(raw[i:], marker) {
			starts = append(starts, i)
		}
	}

	var mds []Microdescriptor
	for idx, s := range starts {
		end := len(raw)
		if idx+1 < len(starts) {
			end = starts[idx+1]
		}
		seg := raw[s:end]
		md, ok := parseOneMicrodesc(seg)
		if !ok {
			continue
		}
		sum := sha256.Sum256(seg)
		md.Digest = base64.RawStdEncoding.EncodeToString(sum[:])
		md.Raw = append([]byte(nil), seg...)
		mds = append(mds, md)
	}
	return mds
}

func parseOneMicrodesc(seg []byte) (Microdescriptor, bool) {
	var md Microdescriptor
	sc := bufio.NewScanner(bytes.NewReader(seg))
	sc.Buffer(make([]byte, 0, 8192), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "ntor-onion-key":
			if len(f) >= 2 {
				md.NtorOnionKey = decodeBase64Flex(f[1])
			}
		case "id":
			if len(f) >= 3 && f[1] == "ed25519" {
				md.Ed25519ID = decodeBase64Flex(f[2])
			}
		case "p":
			if len(f) >= 3 {
				md.ExitPolicy = parseExitPolicy(f[1], f[2])
			}
		case "family":
			md.Family = parseFamily(f[1:])
		}
	}
	if len(md.NtorOnionKey) != 32 {
		return Microdescriptor{}, false
	}
	return md, true
}

// SameFamily reports whether two relays mutually declare each other in their
// "family" lines — the classic Tor rule that prevents using relays from the
// same operator in one circuit. idA/idB are the 20-byte RSA identity digests.
func SameFamily(a Microdescriptor, idA []byte, b Microdescriptor, idB []byte) bool {
	return slices.Contains(a.Family, fpHex(idB)) && slices.Contains(b.Family, fpHex(idA))
}

func fpHex(id []byte) string { return strings.ToUpper(hex.EncodeToString(id)) }

// parseFamily extracts the RSA identity fingerprints ($-prefixed, 40 hex)
// declared in a microdescriptor "family" line, normalized to upper-case hex.
// Bare-nickname members are ignored (not reliably resolvable to an identity).
func parseFamily(members []string) []string {
	var out []string
	for _, m := range members {
		if !strings.HasPrefix(m, "$") {
			continue
		}
		fp := m[1:]
		// Members may be "$FP", "$FP=nick", or "$FP~nick".
		if i := strings.IndexAny(fp, "=~"); i >= 0 {
			fp = fp[:i]
		}
		if len(fp) == 40 {
			out = append(out, strings.ToUpper(fp))
		}
	}
	return out
}

func parseExitPolicy(action, ports string) ExitPolicy {
	p := ExitPolicy{IsAccept: action == "accept"}
	for part := range strings.SplitSeq(ports, ",") {
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			loN, _ := strconv.Atoi(lo)
			hiN, _ := strconv.Atoi(hi)
			p.Ports = append(p.Ports, PortRange{loN, hiN})
		} else {
			n, _ := strconv.Atoi(part)
			p.Ports = append(p.Ports, PortRange{n, n})
		}
	}
	return p
}

// decodeBase64Flex decodes standard base64 with or without padding.
func decodeBase64Flex(s string) []byte {
	s = strings.TrimRight(s, "=")
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}
