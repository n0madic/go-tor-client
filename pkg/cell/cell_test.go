package cell

import (
	"bytes"
	"testing"
)

func TestFixedCellRoundTrip(t *testing.T) {
	t.Parallel()
	payload := make([]byte, 10)
	for i := range payload {
		payload[i] = byte(i + 1)
	}
	orig := Cell{CircID: 0x01020304, Command: CmdRelay, Payload: payload}

	enc := orig.Encode(CircIDLenWide)
	if len(enc) != CircIDLenWide+1+PayloadLen {
		t.Fatalf("encoded length = %d, want %d", len(enc), CircIDLenWide+1+PayloadLen)
	}

	got, err := ReadCell(bytes.NewReader(enc), CircIDLenWide)
	if err != nil {
		t.Fatalf("ReadCell: %v", err)
	}
	if got.CircID != orig.CircID {
		t.Errorf("CircID = %#x, want %#x", got.CircID, orig.CircID)
	}
	if got.Command != orig.Command {
		t.Errorf("Command = %v, want %v", got.Command, orig.Command)
	}
	if len(got.Payload) != PayloadLen {
		t.Fatalf("payload len = %d, want %d", len(got.Payload), PayloadLen)
	}
	if !bytes.Equal(got.Payload[:len(payload)], payload) {
		t.Errorf("payload prefix mismatch")
	}
	for _, b := range got.Payload[len(payload):] {
		if b != 0 {
			t.Fatalf("payload not zero-padded")
		}
	}
}

func TestVersionsCellShortCircID(t *testing.T) {
	t.Parallel()
	// VERSIONS bodies are pairs of uint16 link versions.
	body := []byte{0, 4, 0, 5}
	orig := Cell{CircID: 0, Command: CmdVersions, Payload: body}

	enc := orig.Encode(CircIDLenShort)
	// CircID(2) | Cmd(1) | Len(2) | Body(4)
	want := []byte{0, 0, 7, 0, 4, 0, 4, 0, 5}
	if !bytes.Equal(enc, want) {
		t.Fatalf("encoded = %x, want %x", enc, want)
	}

	got, err := ReadCell(bytes.NewReader(enc), CircIDLenShort)
	if err != nil {
		t.Fatalf("ReadCell: %v", err)
	}
	if got.Command != CmdVersions || !bytes.Equal(got.Payload, body) {
		t.Fatalf("got %v %x, want VERSIONS %x", got.Command, got.Payload, body)
	}
}

func TestVariableCellRoundTrip(t *testing.T) {
	t.Parallel()
	body := bytes.Repeat([]byte{0xab}, 300)
	orig := Cell{CircID: 0xdeadbeef, Command: CmdCerts, Payload: body}

	enc := orig.Encode(CircIDLenWide)
	got, err := ReadCell(bytes.NewReader(enc), CircIDLenWide)
	if err != nil {
		t.Fatalf("ReadCell: %v", err)
	}
	if got.CircID != orig.CircID || got.Command != CmdCerts {
		t.Fatalf("header mismatch: %#x %v", got.CircID, got.Command)
	}
	if !bytes.Equal(got.Payload, body) {
		t.Fatalf("body mismatch")
	}
}

// TestReadCellRejectsOversizedVariable locks in the DoS guard: a variable cell
// whose length field exceeds MaxVariableBody is rejected without allocating it,
// while a body at exactly the cap is accepted.
func TestReadCellRejectsOversizedVariable(t *testing.T) {
	t.Parallel()

	// Header: CircID(4) | Command(VPADDING, variable) | Length(2).
	hdr := func(n uint16) []byte {
		b := []byte{0, 0, 0, 1, byte(CmdVPadding), byte(n >> 8), byte(n)}
		return b
	}

	// Oversized: length field one past the cap. ReadCell must error before it
	// tries to read (or allocate) the body.
	over := hdr(uint16(MaxVariableBody + 1))
	if _, err := ReadCell(bytes.NewReader(over), CircIDLenWide); err == nil {
		t.Fatal("ReadCell accepted an oversized variable cell; want error")
	}

	// At the cap: a full body of MaxVariableBody bytes is accepted.
	body := bytes.Repeat([]byte{0xcd}, MaxVariableBody)
	atCap := append(hdr(uint16(MaxVariableBody)), body...)
	got, err := ReadCell(bytes.NewReader(atCap), CircIDLenWide)
	if err != nil {
		t.Fatalf("ReadCell rejected a cell at the cap: %v", err)
	}
	if len(got.Payload) != MaxVariableBody {
		t.Fatalf("body length = %d, want %d", len(got.Payload), MaxVariableBody)
	}
}

func TestIsVariable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		cmd  Command
		want bool
	}{
		{CmdVersions, true},
		{CmdCerts, true},
		{CmdAuthChallenge, true},
		{CmdAuthenticate, true},
		{CmdRelay, false},
		{CmdRelayEarly, false},
		{CmdCreate2, false},
		{CmdNetinfo, false},
		{CmdDestroy, false},
	}
	for _, c := range cases {
		if got := c.cmd.IsVariable(); got != c.want {
			t.Errorf("%v.IsVariable() = %v, want %v", c.cmd, got, c.want)
		}
	}
}

func TestRelayCellRoundTrip(t *testing.T) {
	t.Parallel()
	data := []byte("hello tor relay payload")
	orig := RelayCell{
		Command:    RelayData,
		Recognized: 0,
		StreamID:   0x1234,
		Digest:     [4]byte{0xde, 0xad, 0xbe, 0xef},
		Data:       data,
	}
	enc := orig.Encode()
	if len(enc) != PayloadLen {
		t.Fatalf("relay payload len = %d, want %d", len(enc), PayloadLen)
	}

	got, ok := DecodeRelay(enc)
	if !ok {
		t.Fatal("DecodeRelay failed")
	}
	if got.Command != RelayData || got.StreamID != 0x1234 || got.Recognized != 0 {
		t.Fatalf("header mismatch: %+v", got)
	}
	if got.Digest != orig.Digest {
		t.Errorf("digest = %x, want %x", got.Digest, orig.Digest)
	}
	if !bytes.Equal(got.Data, data) {
		t.Errorf("data = %q, want %q", got.Data, data)
	}
}

func TestDecodeRelayRejectsBadLength(t *testing.T) {
	t.Parallel()
	if _, ok := DecodeRelay(make([]byte, 100)); ok {
		t.Error("DecodeRelay accepted short payload")
	}
	// Declared data length overflowing the cell must be rejected.
	bad := make([]byte, PayloadLen)
	bad[relayLengthOff] = 0xff
	bad[relayLengthOff+1] = 0xff
	if _, ok := DecodeRelay(bad); ok {
		t.Error("DecodeRelay accepted overflowing length")
	}
}
