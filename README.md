# go-tor-client

A minimal but functional **Tor client in pure Go** — no CGO, no dependency on the C
`tor` daemon. It connects to the live Tor network and routes traffic both to the
clearnet (via exit relays) and to **v3 onion services**.

Only the modern protocol is implemented (no legacy):

- handshakes: **ntor v1** only (no TAP/RSA CREATE)
- onion services: **v3** only
- link protocol: **v4/v5** only (4-byte circuit IDs)
- directories: **microdescriptor** consensus

The single external dependency is `filippo.io/edwards25519` (pure Go, for
ed25519 key blinding). Everything else is the Go standard library
(`crypto/ecdh`, `crypto/sha3`, `crypto/hkdf`, `crypto/ed25519`, ...).

## Public API

```go
import tor "github.com/n0madic/go-tor-client"

ctx := context.Background()
client, err := tor.NewClient(ctx, &tor.Config{}) // bootstraps: consensus + guard
if err != nil { /* ... */ }
defer client.Close()

// DialContext is compatible with proxy.ContextDialer and *net.Dialer.DialContext,
// so it plugs straight into an http.Transport.
httpClient := &http.Client{Transport: &http.Transport{DialContext: client.DialContext}}

// clearnet through a 3-hop circuit + exit:
resp, _ := httpClient.Get("https://check.torproject.org/")

// v3 onion through intro + rendezvous:
resp, _ = httpClient.Get("http://<56-char-base32>.onion/")
```

`Config` fields (all optional): `DataDir` (persist the guard **and** an on-disk
directory cache between runs), `Logger` (`*slog.Logger`), `DirAuthorities`
(override the hardcoded set, for tests), `Cache` (plug a custom
`directory.Cache`), `MaxCircuitDirtiness` (how long a pooled circuit accepts new
streams; 0 → 10 min, like tor).

### Circuit pooling & lifecycle

Circuits are **pooled and reused**: many concurrent streams multiplex over one
circuit, and `DialContext` reuses a port-compatible (clearnet) or per-host
(onion) circuit instead of building a fresh one each call. A background janitor
reaps circuits that are dead, idle past `MaxCircuitDirtiness`, or retired, and
`Close` tears the whole pool down. Closing a returned `net.Conn` releases its
stream slot — no more circuit leaks.

Lifecycle controls:

```go
client.NewIdentity()        // NEWNYM: drop pooled circuits so new dials take fresh paths
client.RotateGuard(ctx)     // close the guard channel and connect a *different* entry guard
client.Stats()              // {ClearnetCircuits, OnionCircuits, Built, Reused}
```

`NewIdentity` performs no network I/O: idle circuits are torn down immediately,
in-use ones are retired and reaped once their last stream closes (so existing
streams keep working). The consensus is **refreshed lazily** on the first dial
after it expires; the swap is best-effort, so a failed refresh falls back to the
stale consensus rather than failing the dial.

### Caching for fast startup

Setting `DataDir` enables an on-disk cache of the consensus, authority
certificates, and microdescriptors, so subsequent starts skip the big
downloads — most importantly the ~5000-entry HSDir microdescriptor set used for
onion lookups. A cached consensus is still fully re-verified against the
hardcoded authority identities (a tampered cache cannot be accepted) and is
discarded once it expires.

The cache is an exported interface, so third-party applications can provide
their own backing store:

```go
type Cache interface {            // package directory
    Get(key string) ([]byte, bool)
    Put(key string, data []byte)
}

cache, _ := directory.NewDiskCache("/var/cache/tor") // bundled disk implementation
client, _ := tor.NewClient(ctx, &tor.Config{Cache: cache})
// or, at the directory layer directly:
dir := directory.NewClient(nil, logger)
dir.UseCache(cache)
```

## Command-line interface

The `cmd/go-tor-client` binary wraps the library with three subcommands. Logs go
to **stderr**, so a fetched body printed to stdout stays clean.

```bash
go build -o go-tor-client ./cmd/go-tor-client

# 1) SOCKS5 proxy — tunnel any TCP app through Tor
go-tor-client socks [-listen 127.0.0.1:1080] [-datadir DIR] [-log-level info]

curl --socks5-hostname 127.0.0.1:1080 https://check.torproject.org/   # clearnet
curl --socks5-hostname 127.0.0.1:1080 http://<56-char-base32>.onion/  # onion (remote DNS)

# 2) HTTP proxy — CONNECT tunnels + plain forwarding through Tor
go-tor-client http [-listen 127.0.0.1:8080] [-datadir DIR] [-log-level info]

curl -x http://127.0.0.1:8080 https://check.torproject.org/   # HTTPS via CONNECT
curl -x http://127.0.0.1:8080 http://api.ipify.org/           # plain HTTP forward
curl -x http://127.0.0.1:8080 https://<56-char-base32>.onion/ # onion via CONNECT

# 3) request — curl-like HTTP(S) fetch directly through Tor (no proxy)
go-tor-client request [-X METHOD] [-H 'K: V']... [-d DATA|@file] [-o FILE] [-i] \
                      [-timeout 60s] [-datadir DIR] [-log-level info]  URL

go-tor-client request -i https://check.torproject.org/
go-tor-client request -X POST -d @body.json -H 'Content-Type: application/json' https://...

# .onion is much slower to reach (HSDir ring + descriptor + rendezvous); a warm
# -datadir cache helps a lot, and .onion URLs get a 3m implicit timeout.
go-tor-client request -datadir ~/.go-tor-client http://<56-char-base32>.onion/
```

> **Onion timing.** Reaching a `.onion` costs more than a clearnet dial. The
> first, **cold** lookup must download the full ~5600-microdescriptor HSDir set to
> build the hash-ring (≈30s), then fetch the descriptor and run intro/rendezvous.
> A warm **`-datadir`** cache skips that download, so repeat runs are **~5–6s**.
> Because a rendezvous/intro circuit can land on a slow or dead relay, the client
> bounds each attempt and **retries on a fresh path** (like a full tor client).
> `request` also applies a **3-minute implicit timeout to `.onion` URLs** (unless
> you pass `-timeout`); clearnet keeps the 60s default.

The SOCKS5 server (`pkg/socks`, a dialer-agnostic RFC 1928 / RFC 1929
implementation that knows nothing about Tor) supports both no-auth and
username/password. The credentials are **not validated** — they are an isolation
token (like tor's `IsolateSOCKSAuth`): each distinct user/pass pair gets its own
`*tor.Client`, with a separate guard channel and circuit pool, so traffic under
different credentials rides **circuit-isolated** paths. Set `-datadir` to keep
the per-identity bootstrap cheap via the warm on-disk cache.

`DOMAINNAME` requests (including `.onion`) are passed to the dialer **verbatim**:
DNS is resolved at the exit, never locally, so the proxy does not leak lookups.

The HTTP proxy (`pkg/httpproxy`, also dialer-agnostic and Tor-unaware) handles
both forms a proxy-aware client uses: **`CONNECT`** tunnels (HTTPS, and `.onion`
over TLS) are dialed through Tor and relayed as raw bytes, while **plain
absolute-URI** requests (`GET http://host/path`) are forwarded and the response
streamed back. Target hostnames reach the dialer verbatim (remote DNS), hop-by-hop
headers are stripped, and no `X-Forwarded-For`/`Via` header is added, so the
proxy does not disclose the client. Like SOCKS, the **`Proxy-Authorization`**
username/password is an unvalidated **isolation token**: each distinct credential
pair gets its own `*tor.Client`, so traffic under different credentials rides
**circuit-isolated** paths (the token is stripped before forwarding, never
leaking to the origin). Requests without credentials share one default identity.

```sh
curl -x http://alice:work@127.0.0.1:8080  https://check.torproject.org/  # identity A
curl -x http://bob:play@127.0.0.1:8080    https://check.torproject.org/  # identity B (separate circuits)
```

The SOCKS and HTTP servers share this credential→dialer abstraction
(`pkg/proxyauth`), and the CLI backs both subcommands with one per-identity
`*tor.Client` pool.

Limitations: the SOCKS server is **CONNECT only** — no SOCKS4/4a, BIND, UDP
ASSOCIATE, or tor `RESOLVE`/`RESOLVE_PTR`. Both proxies relay without half-close
(the underlying Tor stream has no `CloseWrite`), so a `CONNECT`/SOCKS tunnel is
torn down when either direction ends; this is fine for request/response (HTTP)
traffic.

## Architecture

Strictly layered; each package is independently testable.

| Package | Responsibility |
|---------|----------------|
| `internal/byteutil` | big-endian read/write helpers, xor |
| `pkg/torcrypto` | ntor v1 & hs_ntor handshakes, AES-CTR keystream, running SHA-1/SHA3 digest, HKDF-SHA256, SHA3/SHAKE256, ed25519 key blinding, X25519 ECDH |
| `pkg/cell` | fixed (514B) and variable cell codec, relay-cell layout, command constants |
| `pkg/channel` | TLS link to a relay, VERSIONS/CERTS/NETINFO handshake, ed25519 identity verification, cell framing |
| `pkg/circuit` | CREATE2/EXTEND2 telescoping, per-hop onion AES-CTR + digest, RELAY_EARLY budget, circuit-level SENDME flow control |
| `pkg/stream` | stream multiplexing (BEGIN/DATA/END/CONNECTED), stream-level SENDME, `net.Conn` |
| `pkg/directory` | hardcoded authorities, fetch+verify microdesc consensus, fetch microdescriptors and certs |
| `pkg/pathsel` | flag filtering, bandwidth-weighted selection, /16 & same-relay exclusion, exit-policy matching |
| `pkg/onion` | v3 address/blinding, HSDir hash-ring, two-layer descriptor decrypt + signature, intro points, INTRODUCE1/rendezvous, e2e AES-256/SHA3 |
| `tor` (root) | public `Client`, `DialContext`, bootstrap orchestration |
| `internal/relay` | bidirectional full-close connection relay (shared by both proxies) |
| `pkg/proxyauth` | shared credential→dialer abstraction (`Dialer`, `DialerFactory`, isolation key) for both proxies |
| `pkg/socks` | dialer-agnostic SOCKS5 proxy server (RFC 1928 + RFC 1929), CONNECT only |
| `pkg/httpproxy` | dialer-agnostic HTTP forward proxy (CONNECT + plain forwarding), per-credential isolation |
| `cmd/go-tor-client` | CLI: `socks` + `http` proxies + `request` (curl-like direct fetch) |

## Testing

```bash
go test -short ./...        # offline unit tests (crypto vectors, codecs, round-trips)
go test ./...               # also runs the live network integration tests
```

Live, network-gated tests (skipped under `-short`):

- `TestBootstrapLive` — cold-start, verify a real consensus's signatures.
- `TestDialClearnetLive` — build a 3-hop circuit, fetch `check.torproject.org`,
  confirm Tor routing.
- `TestDialOnionLive` — full v3 onion flow to a public onion service.

Key cryptography is pinned to official test vectors: the hs_ntor handshake
(rend-spec-v3 Appendix G) and a real descriptor-signature fixture.

## Path & privacy hardening

- **Family exclusion** — path selection rejects relays that mutually declare
  each other in their `family` lines (in addition to the same-relay and same-/16
  rules), re-rolling on a conflict.
- **Tunneled directory fetches** — after bootstrap, microdescriptor and
  consensus-refresh requests are sent through Tor over a `BEGIN_DIR` circuit, so
  they are not made directly from your IP to the authorities. (The very first
  cold-start consensus is necessarily fetched directly — there is no circuit
  yet.) If the tunnel fails, the fetch **fails closed** by default rather than
  silently retrying over direct HTTP from your IP; set
  `Config.AllowDirectDirFallback` to opt in to the direct fallback (it is logged
  at `WARN` when it happens).
- **Consumption-based stream flow control** — stream SENDMEs are emitted as the
  application *reads* data, so a slow reader back-pressures the sender and
  buffering stays bounded by the window rather than growing unboundedly.
- **Onion client authorization** — restricted-discovery services are supported
  via `Config.OnionClientAuth` (onion address → 32-byte x25519 private key); the
  descriptor cookie is recovered and used to decrypt the inner layer.

## Out of scope

ntor-v3 and congestion control; full guard-spec (prop271); pluggable transports
(obfs4); hosting an onion service; ed25519 "Happy Families" family-id
certificates (prop321) — the classic mutual `family` rule is implemented.
