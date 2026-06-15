package channel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/n0madic/go-tor-client/internal/byteutil"
)

// CERTS-cell certificate types (tor-spec §4.2). We only need the two Ed25519
// certs that authenticate a modern relay's link.
const (
	certTypeEd25519SigningCert = 4 // identity key certifies the signing key
	certTypeEd25519LinkCert    = 5 // signing key certifies SHA-256 of the TLS cert
)

// Ed25519 cert structure fields (cert-spec.txt).
const (
	edCertVersion           = 1
	edCertExtSignedWithKey  = 4 // extension carrying the signer's ed25519 key
	edCertMinLen            = 1 + 1 + 4 + 1 + 32 + 1 + 64
	edCertSignatureLen      = 64
	ed25519PublicKeyLen     = 32
	edCertInnerTypeSigning  = 4 // CERT_TYPE inside the signing cert
	edCertInnerTypeLinkAuth = 5 // CERT_TYPE inside the TLS-link cert
)

var (
	errBadCert     = errors.New("channel: malformed ed25519 certificate")
	errCertExpired = errors.New("channel: certificate expired")
)

type edExtension struct {
	typ   byte
	flags byte
	data  []byte
}

type ed25519Cert struct {
	certType     byte
	expiration   uint32 // hours since the Unix epoch
	keyType      byte
	certifiedKey []byte // 32 bytes
	extensions   []edExtension
	signature    []byte // 64 bytes
	signed       []byte // the cert bytes covered by the signature (all but the sig)
}

// parseEd25519Cert decodes a Tor ed25519 certificate (cert-spec.txt).
func parseEd25519Cert(b []byte) (*ed25519Cert, error) {
	if len(b) < edCertMinLen {
		return nil, errBadCert
	}
	r := byteutil.NewReader(b)
	if r.Byte() != edCertVersion {
		return nil, fmt.Errorf("%w: bad version", errBadCert)
	}
	c := &ed25519Cert{}
	c.certType = r.Byte()
	c.expiration = r.U32()
	c.keyType = r.Byte()
	c.certifiedKey = append([]byte(nil), r.Bytes(ed25519PublicKeyLen)...)

	nExt := int(r.Byte())
	for range nExt {
		extLen := int(r.U16())
		ext := edExtension{
			typ:   r.Byte(),
			flags: r.Byte(),
		}
		ext.data = append([]byte(nil), r.Bytes(extLen)...)
		c.extensions = append(c.extensions, ext)
	}
	c.signature = append([]byte(nil), r.Bytes(edCertSignatureLen)...)
	if r.Err() || r.Remaining() != 0 {
		return nil, errBadCert
	}
	c.signed = b[:len(b)-edCertSignatureLen]
	return c, nil
}

// signerKey returns the ed25519 key carried in the "signed-with-ed25519-key"
// extension, if present.
func (c *ed25519Cert) signerKey() ([]byte, bool) {
	for _, e := range c.extensions {
		if e.typ == edCertExtSignedWithKey && len(e.data) == ed25519PublicKeyLen {
			return e.data, true
		}
	}
	return nil, false
}

// verifySignature checks the cert signature against pub and its expiration.
func (c *ed25519Cert) verify(pub []byte, now time.Time) error {
	if len(pub) != ed25519PublicKeyLen {
		return errBadCert
	}
	expiry := time.Unix(int64(c.expiration)*3600, 0)
	if now.After(expiry) {
		return fmt.Errorf("%w: expired at %s", errCertExpired, expiry)
	}
	if !ed25519.Verify(pub, c.signed, c.signature) {
		return fmt.Errorf("%w: signature", errBadCert)
	}
	return nil
}

// verifyCerts validates the CERTS-cell payload for a relay and returns the
// relay's verified Ed25519 identity key (KP_relayid_ed).
//
// Chain (tor-spec §4.2):
//   - CertType 4: identity key signs the signing key. The identity key is in
//     the "signed-with-ed25519-key" extension.
//   - CertType 5: signing key signs SHA-256 of the relay's TLS link cert.
//
// tlsCertDER is the DER encoding of the leaf certificate presented in the TLS
// handshake; binding it prevents a man-in-the-middle from substituting certs.
func verifyCerts(payload, tlsCertDER []byte, now time.Time) (identity []byte, err error) {
	certs, err := parseCertsCell(payload)
	if err != nil {
		return nil, err
	}

	signingRaw, ok := certs[certTypeEd25519SigningCert]
	if !ok {
		return nil, errors.New("channel: CERTS missing Ed25519 signing cert (type 4)")
	}
	linkRaw, ok := certs[certTypeEd25519LinkCert]
	if !ok {
		return nil, errors.New("channel: CERTS missing Ed25519 link cert (type 5)")
	}

	signingCert, err := parseEd25519Cert(signingRaw)
	if err != nil {
		return nil, fmt.Errorf("channel: signing cert: %w", err)
	}
	if signingCert.certType != edCertInnerTypeSigning {
		return nil, fmt.Errorf("%w: signing cert wrong inner type %d", errBadCert, signingCert.certType)
	}
	identityKey, ok := signingCert.signerKey()
	if !ok {
		return nil, errors.New("channel: signing cert missing identity-key extension")
	}
	if err := signingCert.verify(identityKey, now); err != nil {
		return nil, fmt.Errorf("channel: signing cert: %w", err)
	}
	signingKey := signingCert.certifiedKey

	linkCert, err := parseEd25519Cert(linkRaw)
	if err != nil {
		return nil, fmt.Errorf("channel: link cert: %w", err)
	}
	if linkCert.certType != edCertInnerTypeLinkAuth {
		return nil, fmt.Errorf("%w: link cert wrong inner type %d", errBadCert, linkCert.certType)
	}
	if err := linkCert.verify(signingKey, now); err != nil {
		return nil, fmt.Errorf("channel: link cert: %w", err)
	}

	wantDigest := sha256.Sum256(tlsCertDER)
	if !bytes.Equal(linkCert.certifiedKey, wantDigest[:]) {
		return nil, errors.New("channel: link cert does not match TLS certificate (possible MITM)")
	}

	return identityKey, nil
}

// parseCertsCell decodes a CERTS cell payload into a map from cert type to the
// raw certificate body.
func parseCertsCell(payload []byte) (map[byte][]byte, error) {
	r := byteutil.NewReader(payload)
	n := int(r.Byte())
	out := make(map[byte][]byte, n)
	for range n {
		certType := r.Byte()
		certLen := int(r.U16())
		body := r.Bytes(certLen)
		if r.Err() {
			return nil, errors.New("channel: truncated CERTS cell")
		}
		out[certType] = append([]byte(nil), body...)
	}
	if r.Err() {
		return nil, errors.New("channel: malformed CERTS cell")
	}
	return out, nil
}
