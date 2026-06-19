package directory

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

var (
	errBadSig      = errors.New("directory: bad RSA signature padding")
	errCertExpired = errors.New("directory: authority certificate expired")
)

// authCert is a parsed and (after verify) trusted dir-key-certificate.
type authCert struct {
	identityFP   string // SHA-1 of the identity key DER (upper hex) == authority v3ident
	signingKeyFP string // SHA-1 of the signing key DER (upper hex)
	identityKey  *rsa.PublicKey
	signingKey   *rsa.PublicKey
	expires      time.Time
	signedBody   []byte // bytes covered by dir-key-certification
	certSig      []byte // the dir-key-certification signature
}

// certKey identifies a cert by (authority identity, signing key).
func (c *authCert) certKey() string { return c.identityFP + "-" + c.signingKeyFP }

// ParseAuthCert parses a dir-key-certificate document.
func ParseAuthCert(raw []byte) (*authCert, error) {
	cert := &authCert{}

	idDER, err := extractPEM(raw, "dir-identity-key", "RSA PUBLIC KEY")
	if err != nil {
		return nil, fmt.Errorf("directory: identity key: %w", err)
	}
	cert.identityKey, err = x509.ParsePKCS1PublicKey(idDER)
	if err != nil {
		return nil, fmt.Errorf("directory: parse identity key: %w", err)
	}
	idSum := sha1.Sum(idDER)
	cert.identityFP = strings.ToUpper(hex.EncodeToString(idSum[:]))

	skDER, err := extractPEM(raw, "dir-signing-key", "RSA PUBLIC KEY")
	if err != nil {
		return nil, fmt.Errorf("directory: signing key: %w", err)
	}
	cert.signingKey, err = x509.ParsePKCS1PublicKey(skDER)
	if err != nil {
		return nil, fmt.Errorf("directory: parse signing key: %w", err)
	}
	skSum := sha1.Sum(skDER)
	cert.signingKeyFP = strings.ToUpper(hex.EncodeToString(skSum[:]))

	exp := fieldValue(raw, "dir-key-expires")
	if exp == "" {
		return nil, errors.New("directory: cert missing dir-key-expires")
	}
	cert.expires, err = time.Parse("2006-01-02 15:04:05", exp)
	if err != nil {
		return nil, fmt.Errorf("directory: parse dir-key-expires %q: %w", exp, err)
	}

	// The dir-key-certification covers everything up to and including the
	// "dir-key-certification\n" line.
	marker := []byte("dir-key-certification\n")
	mi := bytes.Index(raw, marker)
	if mi < 0 {
		return nil, errors.New("directory: cert missing dir-key-certification")
	}
	cert.signedBody = raw[:mi+len(marker)]

	sigDER, err := extractPEMAfter(raw[mi:], "SIGNATURE")
	if err != nil {
		return nil, fmt.Errorf("directory: cert signature: %w", err)
	}
	cert.certSig = sigDER
	return cert, nil
}

// Verify checks the certificate's self-signature and that its identity matches
// the expected authority v3ident.
func (c *authCert) Verify(expectedV3Ident string, now time.Time) error {
	if c.identityFP != strings.ToUpper(expectedV3Ident) {
		return fmt.Errorf("directory: cert identity %s != authority %s", c.identityFP, expectedV3Ident)
	}
	// A missing/zero expiry is treated as invalid rather than never-expiring, so a
	// cert without a usable dir-key-expires can never bypass the temporal bound.
	if c.expires.IsZero() || now.After(c.expires) {
		return errCertExpired
	}
	recovered, err := rsaRecover(c.identityKey, c.certSig)
	if err != nil {
		return fmt.Errorf("directory: cert self-signature: %w", err)
	}
	want := sha1.Sum(c.signedBody)
	if !bytes.Equal(recovered, want[:]) {
		return errors.New("directory: cert self-signature mismatch")
	}
	return nil
}

// VerifyConsensus checks that at least MajorityThreshold distinct authorities
// signed the consensus and that it is currently valid. certs is keyed by
// certKey() (identityFP-signingKeyFP).
func VerifyConsensus(c *Consensus, certs map[string]*authCert, now time.Time) error {
	if now.Before(c.ValidAfter) {
		return fmt.Errorf("directory: consensus not yet valid (valid-after %s)", c.ValidAfter)
	}
	if now.After(c.ValidUntil) {
		return fmt.Errorf("directory: consensus expired (valid-until %s)", c.ValidUntil)
	}

	seen := make(map[string]bool)
	for _, sig := range c.signatures {
		cert := certs[sig.identityFP+"-"+sig.signingKeyFP]
		if cert == nil {
			continue
		}
		var digest []byte
		switch sig.alg {
		case "sha256":
			d := sha256.Sum256(c.signedBody)
			digest = d[:]
		case "sha1":
			d := sha1.Sum(c.signedBody)
			digest = d[:]
		default:
			continue
		}
		recovered, err := rsaRecover(cert.signingKey, sig.sig)
		if err != nil || !bytes.Equal(recovered, digest) {
			continue
		}
		seen[sig.identityFP] = true
	}
	if len(seen) < MajorityThreshold {
		return fmt.Errorf("directory: only %d/%d valid authority signatures", len(seen), MajorityThreshold)
	}
	return nil
}

// rsaRecover performs the raw RSA public-key operation and strips PKCS#1 v1.5
// type-1 padding, returning the embedded message. Tor directory signatures sign
// the bare digest (no ASN.1 DigestInfo), so this cannot use VerifyPKCS1v15.
func rsaRecover(pub *rsa.PublicKey, sig []byte) ([]byte, error) {
	m := new(big.Int).Exp(new(big.Int).SetBytes(sig), big.NewInt(int64(pub.E)), pub.N)
	k := (pub.N.BitLen() + 7) / 8
	eb := m.FillBytes(make([]byte, k))
	if len(eb) < 11 || eb[0] != 0x00 || eb[1] != 0x01 {
		return nil, errBadSig
	}
	i := 2
	for i < len(eb) && eb[i] == 0xFF {
		i++
	}
	if i == len(eb) || eb[i] != 0x00 {
		return nil, errBadSig
	}
	return eb[i+1:], nil
}

// extractPEM finds the PEM block of the given type that follows the given
// keyword line, returning its DER bytes.
func extractPEM(raw []byte, keyword, pemType string) ([]byte, error) {
	_, after, ok := bytes.Cut(raw, []byte(keyword+"\n"))
	if !ok {
		return nil, fmt.Errorf("keyword %q not found", keyword)
	}
	return extractPEMAfter(after, pemType)
}

func extractPEMAfter(raw []byte, pemType string) ([]byte, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if pemType != "" && block.Type != pemType {
		return nil, fmt.Errorf("unexpected PEM type %q", block.Type)
	}
	return block.Bytes, nil
}

func fieldValue(raw []byte, key string) string {
	kw := []byte("\n" + key + " ")
	i := bytes.Index(raw, kw)
	start := 0
	if i < 0 {
		if bytes.HasPrefix(raw, []byte(key+" ")) {
			start = len(key) + 1
		} else {
			return ""
		}
	} else {
		start = i + len(kw)
	}
	end := bytes.IndexByte(raw[start:], '\n')
	if end < 0 {
		return string(raw[start:])
	}
	return string(raw[start : start+end])
}
