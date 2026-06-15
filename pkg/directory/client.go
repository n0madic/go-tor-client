package directory

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"
)

const (
	pathConsensusMicrodesc = "/tor/status-vote/current/consensus-microdesc"
	pathKeysFpSk           = "/tor/keys/fp-sk/"
	pathMicroD             = "/tor/micro/d/"

	maxMicrodescPerRequest = 92

	// maxDecompressedSize bounds the inflated size of a directory response so a
	// malicious relay/HSDir cannot send a small zlib/gzip "bomb" that expands to
	// gigabytes and exhausts client memory. The microdesc consensus and batched
	// microdescriptors are a few MB; 64 MiB is generous headroom.
	maxDecompressedSize = 64 << 20
)

// Client fetches directory documents over plain HTTP from directory
// authorities (used for cold-start bootstrap).
type Client struct {
	authorities []Authority
	http        *http.Client
	log         *slog.Logger
	now         func() time.Time
	cache       Cache
	tunnel      Tunnel
}

// Tunnel fetches a directory document over Tor via a BEGIN_DIR stream, used to
// anonymize directory requests (microdescriptors, consensus refreshes) once a
// circuit is available. The cold-start consensus fetch necessarily stays direct.
type Tunnel interface {
	DirGet(ctx context.Context, path string) ([]byte, error)
}

// UseCache attaches a persistent cache so subsequent runs can skip downloading
// the consensus, certificates, and already-seen microdescriptors. Pass nil to
// disable caching.
func (c *Client) UseCache(cache Cache) { c.cache = cache }

// UseTunnel routes subsequent directory fetches through Tor (BEGIN_DIR),
// falling back to direct HTTP if the tunnel fails. Pass nil to disable.
func (c *Client) UseTunnel(t Tunnel) { c.tunnel = t }

func (c *Client) cacheGet(key string) ([]byte, bool) {
	if c.cache == nil {
		return nil, false
	}
	return c.cache.Get(key)
}

func (c *Client) cachePut(key string, data []byte) {
	if c.cache != nil {
		c.cache.Put(key, data)
	}
}

// NewClient builds a directory client. If authorities is nil, the hardcoded
// DefaultAuthorities are used.
func NewClient(authorities []Authority, log *slog.Logger) *Client {
	if len(authorities) == 0 {
		authorities = DefaultAuthorities
	}
	if log == nil {
		log = slog.Default()
	}
	return &Client{
		authorities: authorities,
		http:        &http.Client{},
		log:         log,
		now:         time.Now,
	}
}

// Bootstrap fetches the microdescriptor consensus, fetches the signing
// certificates, verifies the consensus signatures, and returns the verified
// consensus.
func (c *Client) Bootstrap(ctx context.Context) (*Consensus, error) {
	// Try a cached consensus first: it must still be time-valid and must pass
	// full signature verification (the trust anchor is the hardcoded authority
	// identities, so a tampered cache cannot be accepted).
	if cons := c.cachedConsensus(ctx); cons != nil {
		c.log.Debug("using cached consensus", "routers", len(cons.Routers), "valid_until", cons.ValidUntil)
		return cons, nil
	}
	return c.fetchVerifyConsensus(ctx)
}

// Refresh fetches and verifies a brand-new consensus, bypassing the cache
// short-circuit so a long-running client whose consensus has expired can pick up
// fresh routing data. Like every other post-bootstrap fetch it prefers the Tor
// tunnel when one is set.
func (c *Client) Refresh(ctx context.Context) (*Consensus, error) {
	return c.fetchVerifyConsensus(ctx)
}

// fetchVerifyConsensus downloads, parses, verifies, and caches a fresh
// microdescriptor consensus. It is shared by Bootstrap (after a cache miss) and
// Refresh (which always fetches anew).
func (c *Client) fetchVerifyConsensus(ctx context.Context) (*Consensus, error) {
	raw, err := c.fetchFromAny(ctx, pathConsensusMicrodesc)
	if err != nil {
		return nil, fmt.Errorf("directory: fetch consensus: %w", err)
	}
	cons, err := ParseConsensus(raw)
	if err != nil {
		return nil, err
	}
	c.log.Debug("consensus parsed", "routers", len(cons.Routers), "valid_until", cons.ValidUntil)

	certs, err := c.fetchCerts(ctx, cons.signatures)
	if err != nil {
		return nil, fmt.Errorf("directory: fetch certs: %w", err)
	}
	if err := VerifyConsensus(cons, certs, c.now()); err != nil {
		return nil, err
	}
	c.log.Debug("consensus verified", "certs", len(certs))
	c.cachePut("consensus", raw)
	return cons, nil
}

// cachedConsensus returns a verified, still-valid consensus from the cache, or
// nil if there is none, it has expired, or it fails verification.
func (c *Client) cachedConsensus(ctx context.Context) *Consensus {
	raw, ok := c.cacheGet("consensus")
	if !ok {
		return nil
	}
	cons, err := ParseConsensus(raw)
	if err != nil {
		return nil
	}
	now := c.now()
	if now.Before(cons.ValidAfter) || now.After(cons.ValidUntil) {
		return nil // expired or not yet valid
	}
	certs, err := c.fetchCerts(ctx, cons.signatures)
	if err != nil {
		return nil
	}
	if err := VerifyConsensus(cons, certs, now); err != nil {
		return nil
	}
	return cons
}

// fetchCerts returns the authority certificates referenced by the consensus
// signatures, keyed by certKey(), using the cache when it covers every needed
// signing key and otherwise downloading and caching a fresh set.
func (c *Client) fetchCerts(ctx context.Context, sigs []consensusSig) (map[string]*authCert, error) {
	byIdent := make(map[string]Authority)
	for _, a := range c.authorities {
		byIdent[strings.ToUpper(a.V3Ident)] = a
	}

	var need []string
	for _, s := range sigs {
		if _, ok := byIdent[s.identityFP]; ok {
			need = append(need, s.identityFP+"-"+s.signingKeyFP)
		}
	}
	if len(need) == 0 {
		return nil, fmt.Errorf("no signatures from known authorities")
	}

	if raw, ok := c.cacheGet("certs"); ok {
		if certs := c.parseCerts(raw, byIdent); certsCoverAll(certs, need) {
			return certs, nil
		}
	}

	raw, err := c.fetchFromAny(ctx, pathKeysFpSk+strings.Join(need, "+"))
	if err != nil {
		return nil, err
	}
	certs := c.parseCerts(raw, byIdent)
	if !certsCoverAll(certs, need) {
		return nil, fmt.Errorf("directory: fetched certs miss some signing keys")
	}
	c.cachePut("certs", raw)
	return certs, nil
}

// parseCerts parses and verifies every authority cert in a (possibly
// concatenated) certs document, keyed by certKey().
func (c *Client) parseCerts(raw []byte, byIdent map[string]Authority) map[string]*authCert {
	out := make(map[string]*authCert)
	for _, segment := range splitCerts(raw) {
		cert, err := ParseAuthCert(segment)
		if err != nil {
			c.log.Debug("skip malformed cert", "err", err)
			continue
		}
		auth, ok := byIdent[cert.identityFP]
		if !ok {
			continue // not a known authority
		}
		if err := cert.Verify(auth.V3Ident, c.now()); err != nil {
			c.log.Debug("cert verify failed", "auth", auth.Nickname, "err", err)
			continue
		}
		out[cert.certKey()] = cert
	}
	return out
}

func certsCoverAll(certs map[string]*authCert, need []string) bool {
	for _, k := range need {
		if _, ok := certs[k]; !ok {
			return false
		}
	}
	return true
}

// FetchMicrodescriptors downloads microdescriptors for the given consensus "m"
// hashes, returning a map keyed by hash. Requests are batched.
func (c *Client) FetchMicrodescriptors(ctx context.Context, hashes []string) (map[string]Microdescriptor, error) {
	return c.fetchMicrodescriptors(ctx, hashes, c.fetchFromAny)
}

// FetchMicrodescriptorsDirect fetches microdescriptors via direct HTTP,
// bypassing any tunnel. It is used to fetch the microdescriptors of the
// tunnel's own circuit relays without creating a dependency cycle.
func (c *Client) FetchMicrodescriptorsDirect(ctx context.Context, hashes []string) (map[string]Microdescriptor, error) {
	return c.fetchMicrodescriptors(ctx, hashes, c.fetchDirect)
}

func (c *Client) fetchMicrodescriptors(ctx context.Context, hashes []string, fetch func(context.Context, string) ([]byte, error)) (map[string]Microdescriptor, error) {
	out := make(map[string]Microdescriptor, len(hashes))

	// Serve from cache where possible (microdescriptors are content-addressed
	// and immutable, so a hash hit is always valid).
	var missing []string
	for _, h := range hashes {
		if raw, ok := c.cacheGet("md/" + h); ok {
			if mds := ParseMicrodescriptors(raw); len(mds) == 1 && mds[0].Digest == h {
				out[h] = mds[0]
				continue
			}
		}
		missing = append(missing, h)
	}

	for start := 0; start < len(missing); start += maxMicrodescPerRequest {
		end := min(start+maxMicrodescPerRequest, len(missing))
		batch := missing[start:end]
		raw, err := fetch(ctx, pathMicroD+strings.Join(batch, "-"))
		if err != nil {
			return nil, fmt.Errorf("directory: fetch microdescs: %w", err)
		}
		for _, md := range ParseMicrodescriptors(raw) {
			out[md.Digest] = md
			c.cachePut("md/"+md.Digest, md.Raw)
		}
	}
	return out, nil
}

// fetchFromAny fetches a directory path, preferring the Tor tunnel (if set)
// and falling back to direct HTTP to the authorities.
func (c *Client) fetchFromAny(ctx context.Context, path string) ([]byte, error) {
	if c.tunnel != nil {
		if body, err := c.tunnel.DirGet(ctx, path); err == nil {
			return body, nil
		} else {
			c.log.Debug("tunneled dir fetch failed; using direct", "err", err)
		}
	}
	return c.fetchDirect(ctx, path)
}

// fetchDirect fetches a directory path via direct HTTP to the authorities,
// bypassing any tunnel. Used for cold-start bootstrap and to fetch the
// microdescriptors of the tunnel's own circuit relays (avoiding a cycle).
func (c *Client) fetchDirect(ctx context.Context, path string) ([]byte, error) {
	order := shuffledIndices(len(c.authorities))
	var lastErr error
	for _, i := range order {
		auth := c.authorities[i]
		body, err := c.get(ctx, auth.DirAddr(), path)
		if err != nil {
			lastErr = err
			c.log.Debug("dir fetch failed", "auth", auth.Nickname, "err", err)
			continue
		}
		return body, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no authorities available")
	}
	return nil, lastErr
}

func (c *Client) get(ctx context.Context, hostport, path string) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	url := "http://" + hostport + path
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// Set Accept-Encoding ourselves so the transport leaves decompression to us
	// (Tor dir servers commonly answer with zlib "deflate", which the stdlib
	// does not auto-decode).
	req.Header.Set("Accept-Encoding", "gzip, deflate, identity")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, hostport)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	return decompress(resp.Header.Get("Content-Encoding"), body)
}

// Decompress decodes a directory response body according to its
// Content-Encoding (gzip or zlib "deflate"). Exported for reuse by tunneled
// (BEGIN_DIR) directory fetches.
func Decompress(encoding string, body []byte) ([]byte, error) {
	return decompress(encoding, body)
}

// decompress decodes a directory response body according to its Content-Encoding.
// Tor's "deflate" is zlib-wrapped (RFC 1950); raw DEFLATE is tried as a fallback.
func decompress(encoding string, body []byte) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return body, nil
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer zr.Close()
		return readAllLimited(zr)
	case "deflate":
		if zr, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
			defer zr.Close()
			return readAllLimited(zr)
		}
		fr := flate.NewReader(bytes.NewReader(body))
		defer fr.Close()
		return readAllLimited(fr)
	default:
		return body, nil
	}
}

// readAllLimited reads up to maxDecompressedSize bytes, returning an error if
// the stream is larger — defending against decompression bombs.
func readAllLimited(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxDecompressedSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxDecompressedSize {
		return nil, fmt.Errorf("directory: decompressed body exceeds %d bytes", maxDecompressedSize)
	}
	return data, nil
}

// splitCerts splits a concatenated certs document on the version line.
func splitCerts(raw []byte) [][]byte {
	marker := []byte("dir-key-certificate-version")
	var starts []int
	for i := 0; i+len(marker) <= len(raw); i++ {
		if (i == 0 || raw[i-1] == '\n') && bytes.HasPrefix(raw[i:], marker) {
			starts = append(starts, i)
		}
	}
	var out [][]byte
	for idx, s := range starts {
		end := len(raw)
		if idx+1 < len(starts) {
			end = starts[idx+1]
		}
		out = append(out, raw[s:end])
	}
	return out
}

func shuffledIndices(n int) []int {
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	for i := n - 1; i > 0; i-- {
		jBig, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		j := int(jBig.Int64())
		idx[i], idx[j] = idx[j], idx[i]
	}
	return idx
}
