// Package directory bootstraps the Tor network view: it fetches and verifies
// the microdescriptor consensus, fetches the referenced microdescriptors, and
// validates consensus signatures against the hardcoded directory authorities.
package directory

// Authority is a hardcoded Tor directory authority. Values are taken verbatim
// from upstream Tor's src/app/config/auth_dirs.inc; the V3Ident is the trust
// anchor used to validate consensus signatures.
type Authority struct {
	Nickname string
	V3Ident  string // 40-hex SHA-1 of the authority's v3 identity key
	IP       string
	DirPort  int
	ORPort   int
}

// DirAddr returns the "ip:dirport" used for direct (cold-start) HTTP fetches.
func (a Authority) DirAddr() string {
	return a.IP + ":" + itoa(a.DirPort)
}

// DefaultAuthorities is the current set of nine v3 directory authorities. The
// bridge authority (Serge) is intentionally excluded: it does not sign the
// microdescriptor consensus.
var DefaultAuthorities = []Authority{
	{"moria1", "F533C81CEF0BC0267857C99B2F471ADF249FA232", "128.31.0.39", 9231, 9201},
	{"tor26", "2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C", "217.196.147.77", 80, 443},
	{"dizum", "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58", "45.66.35.11", 80, 443},
	{"gabelmoo", "ED03BB616EB2F60BEC80151114BB25CEF515B226", "131.188.40.189", 80, 443},
	{"dannenberg", "0232AF901C31A04EE9848595AF9BB7620D4C5B2E", "193.23.244.244", 80, 443},
	{"maatuska", "49015F787433103580E3B66A1707A00E60F2D15B", "171.25.193.9", 443, 80},
	{"longclaw", "23D15D965BC35114467363C165C4F724B64B4F66", "199.58.81.140", 80, 443},
	{"bastet", "27102BC123E7AF1D4741AE047E160C91ADC76B21", "204.13.164.118", 80, 443},
	{"faravahar", "70849B868D606BAECFB6128C5E3D782029AA394F", "216.218.219.41", 80, 443},
}

// MajorityThreshold is the minimum number of valid authority signatures for the
// consensus to be accepted (more than half of the nine authorities).
const MajorityThreshold = 5

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
