package cell

import "encoding/binary"

// Relay-cell layout (tor1 baseline), occupying the 509-byte payload of a RELAY
// or RELAY_EARLY cell:
//
//	RelayCommand(1) | Recognized(2) | StreamID(2) | Digest(4) | Length(2) | Data(498)
const (
	RelayHeaderLen = 11
	RelayDataLen   = PayloadLen - RelayHeaderLen // 498

	relayRecognizedOff = 1
	relayStreamIDOff   = 3
	relayDigestOff     = 5
	relayLengthOff     = 9
	relayDataOff       = 11

	// RelayDigestOffset and RelayDigestLen locate the running-digest field
	// inside the 509-byte relay payload. The circuit layer zeroes this field
	// before hashing and writes the truncated digest back afterwards.
	RelayDigestOffset = relayDigestOff
	RelayDigestLen    = 4

	// RelayRecognizedOffset and RelayRecognizedLen locate the "recognized"
	// field, which is zero for cells addressed to the local endpoint.
	RelayRecognizedOffset = relayRecognizedOff
	RelayRecognizedLen    = 2
)

// RelayCommand identifies a relay-cell subtype (tor-spec §6, rend-spec).
type RelayCommand uint8

// Relay commands.
const (
	RelayBegin     RelayCommand = 1
	RelayData      RelayCommand = 2
	RelayEnd       RelayCommand = 3
	RelayConnected RelayCommand = 4
	RelaySendme    RelayCommand = 5
	RelayExtend    RelayCommand = 6
	RelayExtended  RelayCommand = 7
	RelayTruncate  RelayCommand = 8
	RelayTruncated RelayCommand = 9
	RelayDrop      RelayCommand = 10
	RelayResolve   RelayCommand = 11
	RelayResolved  RelayCommand = 12
	RelayBeginDir  RelayCommand = 13
	RelayExtend2   RelayCommand = 14
	RelayExtended2 RelayCommand = 15

	// Hidden-service (rendezvous) relay commands.
	RelayEstablishIntro        RelayCommand = 32
	RelayEstablishRendezvous   RelayCommand = 33
	RelayIntroduce1            RelayCommand = 34
	RelayIntroduce2            RelayCommand = 35
	RelayRendezvous1           RelayCommand = 36
	RelayRendezvous2           RelayCommand = 37
	RelayIntroEstablished      RelayCommand = 38
	RelayRendezvousEstablished RelayCommand = 39
	RelayIntroduceAck          RelayCommand = 40
)

func (rc RelayCommand) String() string {
	switch rc {
	case RelayBegin:
		return "BEGIN"
	case RelayData:
		return "DATA"
	case RelayEnd:
		return "END"
	case RelayConnected:
		return "CONNECTED"
	case RelaySendme:
		return "SENDME"
	case RelayExtend2:
		return "EXTEND2"
	case RelayExtended2:
		return "EXTENDED2"
	case RelayTruncated:
		return "TRUNCATED"
	case RelayBeginDir:
		return "BEGIN_DIR"
	case RelayEstablishRendezvous:
		return "ESTABLISH_RENDEZVOUS"
	case RelayIntroduce1:
		return "INTRODUCE1"
	case RelayRendezvous1:
		return "RENDEZVOUS1"
	case RelayRendezvous2:
		return "RENDEZVOUS2"
	case RelayIntroEstablished:
		return "INTRO_ESTABLISHED"
	case RelayRendezvousEstablished:
		return "RENDEZVOUS_ESTABLISHED"
	case RelayIntroduceAck:
		return "INTRODUCE_ACK"
	default:
		return "RELAY_CMD"
	}
}

// RelayCell is a decoded relay cell. Digest holds the 4 running-digest bytes as
// they appear on the wire; the circuit layer computes and verifies it.
type RelayCell struct {
	Command    RelayCommand
	Recognized uint16
	StreamID   uint16
	Digest     [4]byte
	Data       []byte
}

// Encode serializes the relay cell into a fresh 509-byte payload buffer. Data
// longer than RelayDataLen is truncated. The Digest field is written verbatim.
func (rc RelayCell) Encode() []byte {
	buf := make([]byte, PayloadLen)
	buf[0] = byte(rc.Command)
	binary.BigEndian.PutUint16(buf[relayRecognizedOff:], rc.Recognized)
	binary.BigEndian.PutUint16(buf[relayStreamIDOff:], rc.StreamID)
	copy(buf[relayDigestOff:], rc.Digest[:])
	n := min(len(rc.Data), RelayDataLen)
	binary.BigEndian.PutUint16(buf[relayLengthOff:], uint16(n))
	copy(buf[relayDataOff:], rc.Data[:n])
	return buf
}

// DecodeRelay parses a 509-byte relay payload. It returns false if the payload
// is the wrong length or the declared data length overflows the cell.
func DecodeRelay(payload []byte) (RelayCell, bool) {
	if len(payload) != PayloadLen {
		return RelayCell{}, false
	}
	n := int(binary.BigEndian.Uint16(payload[relayLengthOff:]))
	if n > RelayDataLen {
		return RelayCell{}, false
	}
	rc := RelayCell{
		Command:    RelayCommand(payload[0]),
		Recognized: binary.BigEndian.Uint16(payload[relayRecognizedOff:]),
		StreamID:   binary.BigEndian.Uint16(payload[relayStreamIDOff:]),
		Data:       append([]byte(nil), payload[relayDataOff:relayDataOff+n]...),
	}
	copy(rc.Digest[:], payload[relayDigestOff:])
	return rc, true
}
