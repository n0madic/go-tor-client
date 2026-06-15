package directory

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// RouterStatus is one relay entry from the microdescriptor consensus.
type RouterStatus struct {
	Nickname      string
	Identity      []byte // 20-byte SHA-1 RSA identity digest (ntor NODEID)
	IP            string
	ORPort        int
	DirPort       int
	IPv6          string // "[addr]:port" if present
	MicrodescHash string // base64 (unpadded) SHA-256 of the microdescriptor
	Flags         map[string]bool
	Bandwidth     int
	Unmeasured    bool
}

// HasFlag reports whether the relay advertises the named consensus flag.
func (r *RouterStatus) HasFlag(f string) bool { return r.Flags[f] }

// consensusSig is one directory-signature block.
type consensusSig struct {
	alg          string
	identityFP   string // authority v3ident (upper hex)
	signingKeyFP string // signing key SHA-1 (upper hex)
	sig          []byte
}

// Consensus is a parsed (not yet verified) microdescriptor consensus.
type Consensus struct {
	ValidAfter time.Time
	FreshUntil time.Time
	ValidUntil time.Time
	Routers    []RouterStatus
	Weights    map[string]int // bandwidth-weights (W** => value)

	SharedRandPrevious []byte // 32 bytes, for onion HSDir ring (current period)
	SharedRandCurrent  []byte

	signedBody []byte // raw bytes covered by the directory signatures
	signatures []consensusSig
}

const dirSigMarker = "directory-signature "

// ParseConsensus parses a raw microdescriptor consensus document.
func ParseConsensus(raw []byte) (*Consensus, error) {
	c := &Consensus{Weights: map[string]int{}}

	// Capture the exact bytes the signatures cover: from the start through the
	// first "directory-signature " token (inclusive of its trailing space).
	idx := bytes.Index(raw, append([]byte("\n"), dirSigMarker...))
	if idx < 0 {
		return nil, fmt.Errorf("directory: consensus has no signatures")
	}
	c.signedBody = raw[:idx+1+len(dirSigMarker)]

	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var cur *RouterStatus
	flush := func() {
		if cur != nil {
			c.Routers = append(c.Routers, *cur)
			cur = nil
		}
	}

	inSig := false
	var sigLines []string
	var pending *consensusSig

	for sc.Scan() {
		line := sc.Text()

		if inSig {
			sigLines = append(sigLines, line)
			if strings.HasPrefix(line, "-----END") {
				block, _ := pem.Decode([]byte(strings.Join(sigLines, "\n") + "\n"))
				if block != nil && pending != nil {
					pending.sig = block.Bytes
					c.signatures = append(c.signatures, *pending)
				}
				inSig = false
				pending = nil
				sigLines = nil
			}
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "valid-after":
			c.ValidAfter = parseDirTime(fields[1:])
		case "fresh-until":
			c.FreshUntil = parseDirTime(fields[1:])
		case "valid-until":
			c.ValidUntil = parseDirTime(fields[1:])
		case "shared-rand-previous-value":
			if len(fields) >= 3 {
				c.SharedRandPrevious, _ = base64.StdEncoding.DecodeString(fields[2])
			}
		case "shared-rand-current-value":
			if len(fields) >= 3 {
				c.SharedRandCurrent, _ = base64.StdEncoding.DecodeString(fields[2])
			}
		case "r":
			flush()
			r, err := parseRouterLine(fields)
			if err != nil {
				// Skip a single malformed router entry rather than discarding the
				// entire signed consensus, as Tor clients do; m/s/w/a lines guard
				// on cur != nil, so they are ignored until the next valid "r".
				slog.Default().Debug("directory: skipping malformed router line", "err", err)
				cur = nil
				continue
			}
			cur = r
		case "a":
			if cur != nil && len(fields) >= 2 {
				cur.IPv6 = fields[1]
			}
		case "m":
			if cur != nil && len(fields) >= 2 {
				cur.MicrodescHash = fields[1]
			}
		case "s":
			if cur != nil {
				cur.Flags = make(map[string]bool, len(fields)-1)
				for _, f := range fields[1:] {
					cur.Flags[f] = true
				}
			}
		case "w":
			if cur != nil {
				parseBandwidthLine(cur, fields[1:])
			}
		case "bandwidth-weights":
			flush()
			for _, kv := range fields[1:] {
				if k, v, ok := splitKV(kv); ok {
					c.Weights[k] = v
				}
			}
		case "directory-signature":
			flush()
			pending = parseSigLine(fields[1:])
			inSig = true
			sigLines = nil
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("directory: scan consensus: %w", err)
	}
	if len(c.Routers) == 0 {
		return nil, fmt.Errorf("directory: consensus has no routers")
	}
	return c, nil
}

func parseRouterLine(f []string) (*RouterStatus, error) {
	// r nickname identity publication-date publication-time IP ORPort DirPort
	if len(f) < 8 {
		return nil, fmt.Errorf("directory: short r-line: %v", f)
	}
	id, err := base64.RawStdEncoding.DecodeString(f[2])
	if err != nil {
		return nil, fmt.Errorf("directory: bad identity base64 %q: %w", f[2], err)
	}
	orPort, _ := strconv.Atoi(f[6])
	dirPort, _ := strconv.Atoi(f[7])
	return &RouterStatus{
		Nickname: f[1],
		Identity: id,
		IP:       f[5],
		ORPort:   orPort,
		DirPort:  dirPort,
		Flags:    map[string]bool{},
	}, nil
}

func parseBandwidthLine(r *RouterStatus, kvs []string) {
	for _, kv := range kvs {
		k, v, ok := splitKV(kv)
		if !ok {
			continue
		}
		switch k {
		case "Bandwidth":
			r.Bandwidth = v
		case "Unmeasured":
			r.Unmeasured = v == 1
		}
	}
}

func parseSigLine(f []string) *consensusSig {
	// Either "<alg> <id-fp> <sk-fp>" or legacy "<id-fp> <sk-fp>" (alg=sha1).
	s := &consensusSig{alg: "sha1"}
	switch len(f) {
	case 3:
		s.alg = f[0]
		s.identityFP = strings.ToUpper(f[1])
		s.signingKeyFP = strings.ToUpper(f[2])
	case 2:
		s.identityFP = strings.ToUpper(f[0])
		s.signingKeyFP = strings.ToUpper(f[1])
	default:
		return nil
	}
	return s
}

func parseDirTime(f []string) time.Time {
	if len(f) < 2 {
		return time.Time{}
	}
	t, _ := time.Parse("2006-01-02 15:04:05", f[0]+" "+f[1])
	return t
}

func splitKV(kv string) (string, int, bool) {
	k, vs, ok := strings.Cut(kv, "=")
	if !ok {
		return "", 0, false
	}
	v, err := strconv.Atoi(vs)
	if err != nil {
		return "", 0, false
	}
	return k, v, true
}
