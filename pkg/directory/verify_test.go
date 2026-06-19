package directory

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testAuthority is a synthetic directory authority signing key for tests.
type testAuthority struct {
	priv         *rsa.PrivateKey
	identityFP   string
	signingKeyFP string
}

func makeAuthority(t *testing.T, label string) testAuthority {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	skDER := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
	skSum := sha1.Sum(skDER)
	idSum := sha1.Sum([]byte(label)) // arbitrary but stable identity fingerprint
	return testAuthority{
		priv:         priv,
		identityFP:   strings.ToUpper(hex.EncodeToString(idSum[:])),
		signingKeyFP: strings.ToUpper(hex.EncodeToString(skSum[:])),
	}
}

// rawRSASign reproduces a Tor directory signature: PKCS#1 v1.5 type-1 padding of
// the bare digest (no ASN.1 DigestInfo) raised to the private exponent.
func rawRSASign(t *testing.T, priv *rsa.PrivateKey, digest []byte) []byte {
	t.Helper()
	k := (priv.N.BitLen() + 7) / 8
	em := make([]byte, k)
	em[1] = 0x01
	psLen := k - 3 - len(digest)
	if psLen < 8 {
		t.Fatalf("key too small for digest")
	}
	for i := range psLen {
		em[2+i] = 0xFF
	}
	copy(em[3+psLen:], digest)
	s := new(big.Int).Exp(new(big.Int).SetBytes(em), priv.D, priv.N)
	return s.FillBytes(make([]byte, k))
}

// buildSignedConsensus produces a consensus signed by the given authorities and
// the matching cert map. Each signature is over sha256 of the signed body.
func buildSignedConsensus(t *testing.T, auths []testAuthority, validAfter, validUntil time.Time) (*Consensus, map[string]*authCert) {
	t.Helper()
	body := []byte("network-status-version 3 microdesc\nvalid-after 2030\n")
	digest := sha256.Sum256(body)
	c := &Consensus{ValidAfter: validAfter, ValidUntil: validUntil, signedBody: body}
	certs := map[string]*authCert{}
	for _, a := range auths {
		c.signatures = append(c.signatures, consensusSig{
			alg:          "sha256",
			identityFP:   a.identityFP,
			signingKeyFP: a.signingKeyFP,
			sig:          rawRSASign(t, a.priv, digest[:]),
		})
		certs[a.identityFP+"-"+a.signingKeyFP] = &authCert{
			identityFP:   a.identityFP,
			signingKeyFP: a.signingKeyFP,
			signingKey:   &a.priv.PublicKey,
		}
	}
	return c, certs
}

func makeAuthorities(t *testing.T, n int) []testAuthority {
	t.Helper()
	auths := make([]testAuthority, n)
	for i := range auths {
		auths[i] = makeAuthority(t, "authority-"+string(rune('A'+i)))
	}
	return auths
}

func TestVerifyConsensusThreshold(t *testing.T) {
	t.Parallel()
	now := time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC)
	va, vu := now.Add(-time.Hour), now.Add(time.Hour)

	t.Run("exactly threshold passes", func(t *testing.T) {
		auths := makeAuthorities(t, MajorityThreshold)
		c, certs := buildSignedConsensus(t, auths, va, vu)
		if err := VerifyConsensus(c, certs, now); err != nil {
			t.Fatalf("VerifyConsensus with %d valid sigs: %v", MajorityThreshold, err)
		}
	})

	t.Run("one under threshold fails", func(t *testing.T) {
		auths := makeAuthorities(t, MajorityThreshold-1)
		c, certs := buildSignedConsensus(t, auths, va, vu)
		if err := VerifyConsensus(c, certs, now); err == nil {
			t.Fatal("VerifyConsensus accepted a sub-threshold consensus")
		}
	})

	t.Run("forged signature not counted", func(t *testing.T) {
		auths := makeAuthorities(t, MajorityThreshold)
		c, certs := buildSignedConsensus(t, auths, va, vu)
		// Corrupt one signature: it must not count, dropping below threshold.
		c.signatures[0].sig[10] ^= 0xff
		if err := VerifyConsensus(c, certs, now); err == nil {
			t.Fatal("VerifyConsensus counted a forged signature")
		}
	})

	t.Run("duplicate identity does not inflate count", func(t *testing.T) {
		auths := makeAuthorities(t, MajorityThreshold-1)
		c, certs := buildSignedConsensus(t, auths, va, vu)
		// Re-add the first authority's signature under a different alg: still one
		// distinct identity, so the count must not reach the threshold.
		dup := c.signatures[0]
		d := sha1.Sum(c.signedBody)
		dup.alg = "sha1"
		dup.sig = rawRSASign(t, auths[0].priv, d[:])
		c.signatures = append(c.signatures, dup)
		if err := VerifyConsensus(c, certs, now); err == nil {
			t.Fatal("VerifyConsensus let a duplicate identity inflate the count")
		}
	})

	t.Run("wrong cert signing key not counted", func(t *testing.T) {
		auths := makeAuthorities(t, MajorityThreshold)
		c, certs := buildSignedConsensus(t, auths, va, vu)
		// Swap one cert's signing key for an unrelated key: recovery mismatches.
		other := makeAuthority(t, "intruder")
		key := auths[0].identityFP + "-" + auths[0].signingKeyFP
		certs[key].signingKey = &other.priv.PublicKey
		if err := VerifyConsensus(c, certs, now); err == nil {
			t.Fatal("VerifyConsensus counted a signature verified with the wrong key")
		}
	})
}

func TestVerifyConsensusValidityWindow(t *testing.T) {
	t.Parallel()
	now := time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC)
	auths := makeAuthorities(t, MajorityThreshold)

	c, certs := buildSignedConsensus(t, auths, now.Add(time.Hour), now.Add(2*time.Hour))
	if err := VerifyConsensus(c, certs, now); err == nil {
		t.Error("accepted a not-yet-valid consensus")
	}

	c, certs = buildSignedConsensus(t, auths, now.Add(-2*time.Hour), now.Add(-time.Hour))
	if err := VerifyConsensus(c, certs, now); err == nil {
		t.Error("accepted an expired consensus")
	}
}

// TestAuthCertVerifyExpiry covers M2: a cert with a missing/zero expiry must be
// treated as expired rather than never-expiring, and a past expiry is rejected.
func TestAuthCertVerifyExpiry(t *testing.T) {
	t.Parallel()
	const id = "ABCDEF"

	zero := &authCert{identityFP: id, expires: time.Time{}}
	if err := zero.Verify(id, time.Now()); !errors.Is(err, errCertExpired) {
		t.Fatalf("zero-expiry cert: err = %v, want errCertExpired", err)
	}

	past := &authCert{identityFP: id, expires: time.Now().Add(-time.Hour)}
	if err := past.Verify(id, time.Now()); !errors.Is(err, errCertExpired) {
		t.Fatalf("expired cert: err = %v, want errCertExpired", err)
	}
}

// TestParseAuthCertRequiresExpiry covers M2 at the parse layer: a cert document
// without a dir-key-expires line is rejected outright.
func TestParseAuthCertRequiresExpiry(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyPEM := func() string {
		der := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
		return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der}))
	}
	sigPEM := string(pem.EncodeToMemory(&pem.Block{Type: "SIGNATURE", Bytes: []byte("x")}))

	doc := func(withExpires bool) []byte {
		var b strings.Builder
		b.WriteString("dir-identity-key\n")
		b.WriteString(keyPEM())
		b.WriteString("dir-signing-key\n")
		b.WriteString(keyPEM())
		if withExpires {
			b.WriteString("dir-key-expires 2030-01-01 00:00:00\n")
		}
		b.WriteString("dir-key-certification\n")
		b.WriteString(sigPEM)
		return []byte(b.String())
	}

	if _, err := ParseAuthCert(doc(false)); err == nil {
		t.Fatal("ParseAuthCert accepted a cert with no dir-key-expires")
	}
	cert, err := ParseAuthCert(doc(true))
	if err != nil {
		t.Fatalf("ParseAuthCert with expiry: %v", err)
	}
	if cert.expires.IsZero() {
		t.Fatal("parsed cert has a zero expiry despite a dir-key-expires line")
	}
}
