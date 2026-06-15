package onion

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/n0madic/go-tor-client/pkg/torcrypto"
)

// Descriptor-encryption parameters (rend-spec-v3 [HS-DESC-ENCRYPTION-KEYS]).
const (
	descSaltLen   = 16
	descMacLen    = 32
	descKeyLen    = 32 // AES-256
	descIVLen     = 16
	descMacKeyLen = 32

	constSuperencrypted = "hsdir-superencrypted-data"
	constEncrypted      = "hsdir-encrypted-data"
)

// IntroPoint is a parsed introduction point from a decrypted descriptor.
type IntroPoint struct {
	LinkSpecifiers []byte // raw NSPEC|specs to reach the intro relay
	OnionKey       []byte // intro relay ntor onion key (curve25519)
	AuthKey        []byte // KP_hs_ipd_sid, ed25519 (INTRODUCE1 routing)
	EncKey         []byte // KP_hss_ntor, curve25519 (hs_ntor B)
}

// Descriptor is a decrypted v3 onion-service descriptor.
type Descriptor struct {
	RevisionCounter uint64
	IntroPoints     []IntroPoint
}

// DecodeDescriptor decrypts both descriptor layers and parses the introduction
// points. blindedKey is A' for the period; subcred is the subcredential.
// clientAuthKey is an optional 32-byte x25519 private key for services with
// restricted discovery (client authorization); pass nil for public services.
func DecodeDescriptor(raw []byte, blindedKey, subcred, clientAuthKey []byte) (*Descriptor, error) {
	// Authenticate the descriptor against the period's blinded key before
	// trusting any of its contents (defends against a malicious HSDir).
	if err := VerifyDescriptorSignature(raw, blindedKey); err != nil {
		return nil, err
	}
	revCounter, superBlob, err := parseOuter(raw)
	if err != nil {
		return nil, err
	}

	// First layer: SECRET_DATA = blinded public key.
	middle, err := decryptLayer(superBlob, blindedKey, subcred, revCounter, constSuperencrypted)
	if err != nil {
		return nil, fmt.Errorf("onion: first layer: %w", err)
	}

	// Second layer SECRET_DATA = blinded | descriptor_cookie (cookie present
	// only for client-authorized services).
	secretData2 := blindedKey
	if cookie, err := decryptDescriptorCookie(middle, subcred, clientAuthKey); err != nil {
		return nil, err
	} else if cookie != nil {
		secretData2 = append(append([]byte(nil), blindedKey...), cookie...)
	}

	encBlob, err := extractMessage(middle, "encrypted")
	if err != nil {
		return nil, fmt.Errorf("onion: middle layer: %w", err)
	}
	inner, err := decryptLayer(encBlob, secretData2, subcred, revCounter, constEncrypted)
	if err != nil {
		return nil, fmt.Errorf("onion: second layer: %w", err)
	}

	intros, err := parseIntroPoints(inner)
	if err != nil {
		return nil, err
	}
	return &Descriptor{RevisionCounter: revCounter, IntroPoints: intros}, nil
}

// parseOuter extracts the revision counter and the superencrypted blob.
func parseOuter(raw []byte) (uint64, []byte, error) {
	var revCounter uint64
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "revision-counter ") {
			revCounter, _ = strconv.ParseUint(strings.TrimSpace(line[len("revision-counter "):]), 10, 64)
		}
	}
	blob, err := extractMessage(raw, "superencrypted")
	if err != nil {
		return 0, nil, fmt.Errorf("onion: outer layer: %w", err)
	}
	return revCounter, blob, nil
}

// extractMessage finds the "-----BEGIN MESSAGE-----" block that follows the
// given keyword line and returns its base64-decoded bytes. It does not use
// encoding/pem: a decrypted descriptor layer is NUL-padded, which the stdlib
// PEM reader does not tolerate around the block.
func extractMessage(raw []byte, keyword string) ([]byte, error) {
	kw := []byte("\n" + keyword + "\n")
	idx := bytes.Index(raw, kw)
	start := 0
	if idx < 0 {
		if bytes.HasPrefix(raw, []byte(keyword+"\n")) {
			start = len(keyword) + 1
		} else {
			return nil, fmt.Errorf("keyword %q not found", keyword)
		}
	} else {
		start = idx + len(kw)
	}

	seg := raw[start:]
	_, afterBegin, ok := bytes.Cut(seg, []byte("-----BEGIN MESSAGE-----"))
	if !ok {
		return nil, fmt.Errorf("no MESSAGE block after %q", keyword)
	}
	body, _, ok := bytes.Cut(afterBegin, []byte("-----END MESSAGE-----"))
	if !ok {
		return nil, fmt.Errorf("unterminated MESSAGE block after %q", keyword)
	}
	cleaned := stripBase64Whitespace(body)
	dec, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("MESSAGE block base64 after %q: %w", keyword, err)
	}
	return dec, nil
}

// stripBase64Whitespace removes newlines and spaces from a base64 blob.
func stripBase64Whitespace(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == '\n' || c == '\r' || c == ' ' || c == '\t' {
			continue
		}
		out = append(out, c)
	}
	return string(out)
}

// decryptLayer decrypts one descriptor layer: SALT(16) | ENCRYPTED | MAC(32).
// secretData is the layer's SECRET_DATA (the blinded key, plus the descriptor
// cookie for the authorized second layer).
func decryptLayer(blob, secretData, subcred []byte, revCounter uint64, stringConst string) ([]byte, error) {
	if len(blob) < descSaltLen+descMacLen {
		return nil, errors.New("layer blob too short")
	}
	salt := blob[:descSaltLen]
	enc := blob[descSaltLen : len(blob)-descMacLen]
	mac := blob[len(blob)-descMacLen:]

	// secret_input = SECRET_DATA | subcredential | INT_8(rev_counter)
	secretInput := concatBytes(secretData, subcred, int8be(revCounter))
	keys := torcrypto.SHAKE256(descKeyLen+descIVLen+descMacKeyLen, secretInput, salt, []byte(stringConst))
	secretKey := keys[:descKeyLen]
	secretIV := keys[descKeyLen : descKeyLen+descIVLen]
	macKey := keys[descKeyLen+descIVLen:]

	// D_MAC = SHA3-256(INT_8(len MAC_KEY) | MAC_KEY | INT_8(len SALT) | SALT | ENC)
	wantMac := torcrypto.SHA3_256(int8be(uint64(len(macKey))), macKey, int8be(uint64(len(salt))), salt, enc)
	if subtle.ConstantTimeCompare(wantMac, mac) != 1 {
		return nil, errors.New("descriptor MAC mismatch")
	}

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(enc))
	cipher.NewCTR(block, secretIV).XORKeyStream(out, enc)
	return out, nil
}

// parseIntroPoints parses the inner (second-layer) plaintext.
func parseIntroPoints(inner []byte) ([]IntroPoint, error) {
	lines := splitLines(inner)
	var intros []IntroPoint
	var cur *IntroPoint

	flush := func() {
		if cur != nil {
			intros = append(intros, *cur)
			cur = nil
		}
	}

	for i := 0; i < len(lines); i++ {
		f := strings.Fields(lines[i])
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "introduction-point":
			flush()
			cur = &IntroPoint{}
			if len(f) >= 2 {
				cur.LinkSpecifiers = decodeB64(f[1])
			}
		case "onion-key":
			if cur != nil && len(f) >= 3 && f[1] == "ntor" {
				cur.OnionKey = decodeB64(f[2])
			}
		case "auth-key":
			if cur != nil {
				cert, next := readCertBlock(lines, i+1)
				if cert != nil {
					cur.AuthKey = certifiedKey(cert)
				}
				i = next - 1 // resume after the block (loop's i++ steps to next)
			}
		case "enc-key":
			if cur != nil && len(f) >= 3 && f[1] == "ntor" {
				cur.EncKey = decodeB64(f[2])
			}
		}
	}
	flush()

	var valid []IntroPoint
	for _, ip := range intros {
		if len(ip.OnionKey) == 32 && len(ip.AuthKey) == 32 && len(ip.EncKey) == 32 && len(ip.LinkSpecifiers) > 0 {
			valid = append(valid, ip)
		}
	}
	if len(valid) == 0 {
		return nil, errors.New("onion: descriptor has no usable introduction points")
	}
	return valid, nil
}

// splitLines splits descriptor text into lines, normalizing CRLF, matching the
// behavior of bufio.Scanner's line splitting without its lookahead limitations.
func splitLines(b []byte) []string {
	return strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
}

// introKeywords are the second-layer keywords that begin a new field; a PEM
// cert block must not span across one (it would mean a missing END marker).
func isIntroKeyword(line string) bool {
	f := strings.Fields(line)
	if len(f) == 0 {
		return false
	}
	switch f[0] {
	case "introduction-point", "onion-key", "auth-key", "enc-key", "enc-key-cert", "legacy-key", "legacy-key-cert":
		return true
	}
	return false
}

// readCertBlock parses the PEM "ED25519 CERT" block that must begin at
// lines[start]. It returns the decoded bytes (nil if absent or malformed) and
// the index of the first line after the block. If the END marker is missing it
// stops at the next BEGIN/keyword line WITHOUT consuming it, so a corrupt block
// can never swallow the following introduction-point fields.
func readCertBlock(lines []string, start int) ([]byte, int) {
	if start >= len(lines) || !strings.HasPrefix(lines[start], "-----BEGIN") {
		return nil, start // no block here; consume nothing
	}
	for i := start + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "-----END") {
			block, _ := pem.Decode([]byte(strings.Join(lines[start:i+1], "\n") + "\n"))
			if block == nil {
				return nil, i + 1
			}
			return block.Bytes, i + 1
		}
		if strings.HasPrefix(lines[i], "-----BEGIN") || isIntroKeyword(lines[i]) {
			return nil, i // END missing; do not consume the following field
		}
	}
	return nil, len(lines)
}

// certifiedKey returns the 32-byte certified key from a Tor ed25519 cert:
// VER(1)|TYPE(1)|EXP(4)|KEYTYPE(1)|CERTIFIED_KEY(32)|...
func certifiedKey(cert []byte) []byte {
	const off = 1 + 1 + 4 + 1
	if len(cert) < off+32 {
		return nil
	}
	return append([]byte(nil), cert[off:off+32]...)
}

// LinkSpecAddr decodes a link-specifier list into a connectable RelayInfo-like
// triple. Returns the OR address, the 20-byte RSA identity, and 32-byte Ed25519
// identity if present.
type LinkSpecAddr struct {
	ORAddr string
	RSAID  []byte
	EdID   []byte
}

// ParseLinkSpecifiers decodes a NSPEC|specs link-specifier list.
func ParseLinkSpecifiers(raw []byte) (LinkSpecAddr, error) {
	var out LinkSpecAddr
	if len(raw) < 1 {
		return out, errors.New("onion: empty link specifiers")
	}
	n := int(raw[0])
	pos := 1
	for range n {
		if pos+2 > len(raw) {
			return out, errors.New("onion: truncated link specifier")
		}
		lstype := raw[pos]
		lslen := int(raw[pos+1])
		pos += 2
		if pos+lslen > len(raw) {
			return out, errors.New("onion: link specifier overflow")
		}
		val := raw[pos : pos+lslen]
		pos += lslen
		switch lstype {
		case 0x00: // IPv4 + port
			if lslen == 6 {
				ip := net.IPv4(val[0], val[1], val[2], val[3])
				port := binary.BigEndian.Uint16(val[4:6])
				out.ORAddr = net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
			}
		case 0x02: // legacy RSA identity
			if lslen == 20 {
				out.RSAID = append([]byte(nil), val...)
			}
		case 0x03: // ed25519 identity
			if lslen == 32 {
				out.EdID = append([]byte(nil), val...)
			}
		}
	}
	if out.ORAddr == "" || len(out.RSAID) != 20 {
		return out, errors.New("onion: link specifiers missing IPv4 or RSA identity")
	}
	return out, nil
}

func decodeB64(s string) []byte {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

func concatBytes(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
