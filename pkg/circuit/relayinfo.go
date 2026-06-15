package circuit

import (
	"errors"
	"fmt"
	"net"

	"github.com/n0madic/go-tor-client/internal/byteutil"
)

// RelayInfo carries everything the circuit layer needs to handshake with and
// extend to a relay. Higher layers (directory/pathsel) populate it.
type RelayInfo struct {
	Nickname     string
	ORAddr       string // "ip:port" of the relay's ORPort
	RSAIDDigest  []byte // 20-byte SHA-1 of the RSA identity (ntor NODEID)
	EdIdentity   []byte // 32-byte Ed25519 identity key
	NtorOnionKey []byte // 32-byte ntor onion key (B)
}

// EXTEND2 link-specifier types (tor-spec §5.1.2).
const (
	linkSpecIPv4    = 0x00
	linkSpecIPv6    = 0x01
	linkSpecLegacy  = 0x02 // 20-byte SHA-1 RSA identity
	linkSpecEd25519 = 0x03 // 32-byte Ed25519 identity
)

// LinkSpecifiers encodes the relay's address and identities as a link-specifier
// list (NSPEC followed by (type, len, value) triples), as used by EXTEND2 and
// INTRODUCE1.
func (r RelayInfo) LinkSpecifiers() ([]byte, error) { return r.linkSpecifiers() }

// linkSpecifiers encodes the relay's address and identities as an EXTEND2
// link-specifier list: NSPEC followed by (type, len, value) triples.
func (r RelayInfo) linkSpecifiers() ([]byte, error) {
	host, portStr, err := net.SplitHostPort(r.ORAddr)
	if err != nil {
		return nil, fmt.Errorf("relayinfo: bad ORAddr %q: %w", r.ORAddr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("relayinfo: ORAddr host %q is not an IP", host)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return nil, fmt.Errorf("relayinfo: bad port %q: %w", portStr, err)
	}
	if len(r.RSAIDDigest) != 20 {
		return nil, errors.New("relayinfo: RSAIDDigest must be 20 bytes")
	}
	if len(r.EdIdentity) != 32 {
		return nil, errors.New("relayinfo: EdIdentity must be 32 bytes")
	}

	type spec struct {
		typ byte
		val []byte
	}
	var specs []spec

	if ip4 := ip.To4(); ip4 != nil {
		v := byteutil.NewWriter(6).Write(ip4).U16(port).Bytes()
		specs = append(specs, spec{linkSpecIPv4, v})
	} else {
		v := byteutil.NewWriter(18).Write(ip.To16()).U16(port).Bytes()
		specs = append(specs, spec{linkSpecIPv6, v})
	}
	specs = append(specs, spec{linkSpecLegacy, r.RSAIDDigest})
	specs = append(specs, spec{linkSpecEd25519, r.EdIdentity})

	w := byteutil.NewWriter(64)
	w.Byte(byte(len(specs)))
	for _, s := range specs {
		w.Byte(s.typ).Byte(byte(len(s.val))).Write(s.val)
	}
	return w.Bytes(), nil
}
