// Package cell implements the Tor link-protocol cell codec for link versions
// 4 and 5 (4-byte circuit IDs), plus the baseline relay-cell layout.
//
// A fixed-length cell is CircID | Command | Payload(509). A variable-length
// cell is CircID | Command | Length(2) | Body. The CircID width is 2 bytes for
// the very first VERSIONS exchange and 4 bytes once link v4+ is negotiated.
package cell

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/n0madic/go-tor-client/internal/byteutil"
)

// PayloadLen is the fixed payload size of a link cell (link v4+).
const PayloadLen = 509

// MaxVariableBody caps the body of a variable-length cell. The largest cell a
// client legitimately reads is CERTS (a few KiB); 16 KiB leaves generous
// headroom while preventing a peer from forcing a 64 KiB allocation per cell
// (e.g. a flood of max-length VPADDING) as an allocation-churn DoS.
const MaxVariableBody = 16 * 1024

// CircIDLenShort and CircIDLenWide are the two circuit-ID widths. The short
// width is used only for the initial VERSIONS cell.
const (
	CircIDLenShort = 2
	CircIDLenWide  = 4
)

// Command identifies a link-protocol cell type.
type Command uint8

// Link cell commands (tor-spec §3, §5).
const (
	CmdPadding          Command = 0
	CmdCreate           Command = 1
	CmdCreated          Command = 2
	CmdRelay            Command = 3
	CmdDestroy          Command = 4
	CmdCreateFast       Command = 5
	CmdCreatedFast      Command = 6
	CmdVersions         Command = 7
	CmdNetinfo          Command = 8
	CmdRelayEarly       Command = 9
	CmdCreate2          Command = 10
	CmdCreated2         Command = 11
	CmdPaddingNegotiate Command = 12

	CmdVPadding      Command = 128
	CmdCerts         Command = 129
	CmdAuthChallenge Command = 130
	CmdAuthenticate  Command = 131
	CmdAuthorize     Command = 132
)

// IsVariable reports whether a cell with this command is variable-length.
// VERSIONS (7) is always variable; all commands >= 128 are variable.
func (c Command) IsVariable() bool {
	return c == CmdVersions || c >= 128
}

func (c Command) String() string {
	switch c {
	case CmdPadding:
		return "PADDING"
	case CmdCreate:
		return "CREATE"
	case CmdCreated:
		return "CREATED"
	case CmdRelay:
		return "RELAY"
	case CmdDestroy:
		return "DESTROY"
	case CmdCreateFast:
		return "CREATE_FAST"
	case CmdCreatedFast:
		return "CREATED_FAST"
	case CmdVersions:
		return "VERSIONS"
	case CmdNetinfo:
		return "NETINFO"
	case CmdRelayEarly:
		return "RELAY_EARLY"
	case CmdCreate2:
		return "CREATE2"
	case CmdCreated2:
		return "CREATED2"
	case CmdPaddingNegotiate:
		return "PADDING_NEGOTIATE"
	case CmdVPadding:
		return "VPADDING"
	case CmdCerts:
		return "CERTS"
	case CmdAuthChallenge:
		return "AUTH_CHALLENGE"
	case CmdAuthenticate:
		return "AUTHENTICATE"
	case CmdAuthorize:
		return "AUTHORIZE"
	default:
		return fmt.Sprintf("CMD(%d)", uint8(c))
	}
}

// Cell is a decoded link cell. For fixed-length cells Payload is exactly
// PayloadLen bytes; for variable-length cells it is the cell body.
type Cell struct {
	CircID  uint32
	Command Command
	Payload []byte
}

// Encode serializes the cell to the wire using the given circuit-ID width
// (CircIDLenShort or CircIDLenWide). Fixed-length payloads are zero-padded or
// truncated to PayloadLen.
func (c Cell) Encode(circIDLen int) []byte {
	w := byteutil.NewWriter(circIDLen + 3 + len(c.Payload))
	if circIDLen == CircIDLenShort {
		w.U16(uint16(c.CircID))
	} else {
		w.U32(c.CircID)
	}
	w.Byte(byte(c.Command))
	if c.Command.IsVariable() {
		w.U16(uint16(len(c.Payload)))
		w.Write(c.Payload)
		return w.Bytes()
	}
	p := c.Payload
	if len(p) >= PayloadLen {
		w.Write(p[:PayloadLen])
	} else {
		w.Write(p)
		w.Write(make([]byte, PayloadLen-len(p)))
	}
	return w.Bytes()
}

// ReadCell reads one cell from r using the given circuit-ID width.
func ReadCell(r io.Reader, circIDLen int) (Cell, error) {
	header := make([]byte, circIDLen+1)
	if _, err := io.ReadFull(r, header); err != nil {
		return Cell{}, err
	}
	var circID uint32
	if circIDLen == CircIDLenShort {
		circID = uint32(binary.BigEndian.Uint16(header))
	} else {
		circID = binary.BigEndian.Uint32(header)
	}
	cmd := Command(header[circIDLen])

	if cmd.IsVariable() {
		var lenBuf [2]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return Cell{}, err
		}
		n := binary.BigEndian.Uint16(lenBuf[:])
		if int(n) > MaxVariableBody {
			return Cell{}, fmt.Errorf("cell: variable body %d exceeds max %d", n, MaxVariableBody)
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return Cell{}, err
		}
		return Cell{CircID: circID, Command: cmd, Payload: body}, nil
	}

	payload := make([]byte, PayloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Cell{}, err
	}
	return Cell{CircID: circID, Command: cmd, Payload: payload}, nil
}
