# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A minimal **pure-Go Tor client** (no CGO, no C `tor` daemon). It connects to the
live Tor network and routes traffic to the clearnet (via exit relays) and to v3
onion services. Public entry point is `tor.Client.DialContext`, compatible with
`proxy.ContextDialer` / `http.Transport.DialContext`. Only modern protocol is
implemented: **ntor handshakes, link v4/v5, microdescriptor consensus, v3 onion**
(no TAP/RSA-CREATE, no v2 onion). Module path is `github.com/n0madic/go-tor-client`.

## Commands

```bash
go build ./...                       # build everything
go vet ./...                         # vet
go test -short ./...                 # OFFLINE unit tests only (no network)
go test ./...                        # also runs live network integration tests

go test ./pkg/torcrypto/             # one package
go test ./pkg/onion/ -run TestHSNtor -v   # one test
go test . -run TestDialOnionLive -v -timeout 300s   # one live test (needs Tor network)
```

- **Live tests are gated by `testing.Short()`** and reach the real Tor network:
  `TestBootstrapLive`, `TestDialClearnetLive`, `TestDialExitIPLive` (root + `pkg/directory`),
  `TestDialOnionLive`, `TestCacheWarmStartLive`. They are slow (10s–60s) and can be
  flaky on network variance. Always run `-short` first; run the relevant live test
  to validate end-to-end protocol changes.
- LSP/gopls may report stale `BrokenImport` errors with the old `nomadic` path after
  edits — **`go build ./...` is the source of truth**, not the LSP.

## Architecture

Strictly layered; lower packages know nothing about higher ones. Dependency
direction is one-way up:

```
internal/byteutil  →  pkg/torcrypto, pkg/cell
pkg/cell + torcrypto  →  pkg/channel  →  pkg/circuit  →  pkg/stream
pkg/directory, pkg/pathsel, pkg/onion  →  (root) package tor
```

- **`pkg/torcrypto`** — the correctness-critical package. ntor v1 + hs_ntor handshakes,
  AES-CTR keystreams, running SHA-1/SHA-3 digest, HKDF/SHAKE, ed25519 blinding,
  X25519. Each construction mirrors tor-spec / rend-spec-v3 and is pinned to test
  vectors where they exist (`TestHSNtorVector`, blinding/digest KATs).
- **`pkg/cell`** — link cell codec (fixed 514B + variable) and the relay-cell layout.
- **`pkg/channel`** — one TLS link to a relay; VERSIONS/CERTS/NETINFO handshake;
  verifies the relay's Ed25519 identity via the CERTS chain (and binds it to the
  TLS leaf cert); runs a read pump that demuxes cells to circuits by CircID.
- **`pkg/circuit`** — CREATE2/EXTEND2 telescoping, per-hop onion crypto, RELAY_EARLY
  budget, circuit-level SENDME. Talks to the channel via the small `Link` interface.
- **`pkg/stream`** — multiplexes streams over a circuit (BEGIN/DATA/END/CONNECTED),
  exposes each as a `net.Conn`. Talks to the circuit via the `Carrier` interface.
- **`pkg/directory`** — hardcoded authorities, fetch+verify microdesc consensus,
  fetch microdescriptors/certs. Pluggable `Cache` (disk) and `Tunnel` (BEGIN_DIR).
- **`pkg/pathsel`** — flag/bandwidth-weighted relay selection + exclusions.
- **`pkg/onion`** — v3 address/blinding, HSDir hash-ring, 2-layer descriptor
  decrypt + signature, intro points, INTRODUCE1/rendezvous, client auth.
- **root `tor`** (`client.go`, `pool.go`, `onion_dial.go`, `dirtunnel.go`, `guard.go`) —
  orchestrates: bootstrap → connect guard → tunnel → `DialContext`.

### Request flow

`DialContext` first runs `ensureFreshConsensus` (lazy refresh if `valid-until`
passed), then splits on the `.onion` suffix. Clearnet: **reuse** a pooled
port-compatible circuit (`acquireClearnet`) or pick a family/subnet-safe
`guard → middle → exit` path (`buildExitCircuit` / `pickRelay`), build over the
persistent guard channel, send RELAY_BEGIN. Onion (`onion_dial.go`): reuse a
per-host pooled circuit (`acquireOnion`) or derive time-period + blinded key,
fetch+decrypt the descriptor, ESTABLISH_RENDEZVOUS on one circuit, INTRODUCE1
(hs_ntor) on another, await RENDEZVOUS2, add a virtual e2e hop
(`buildOnionCircuit`), then RELAY_BEGIN.

### Circuit lifecycle / pooling (`pool.go`)

One `circuit.Circuit` + one `stream.Manager` multiplexes many streams, so
`DialContext` returns a `trackedConn` that releases a pooled circuit's stream
slot on `Close` (fixing the old leak). `Client.sel` is an `atomic.Pointer` so the
consensus swaps lock-free (`selector()` accessor); `poolMu` guards the
`clearnetPool`/`onionPool`. Reuse predicate is the pure `circuitReusable`
(open + not retired + within `maxDirty` + match). A janitor (`maintain`/`reap`,
30 s ticker, stopped by `Close`) reaps dead/idle-expired/retired circuits.
`NewIdentity()` (no network) retires every pooled circuit — idle ones torn down
now, in-use ones when their last stream closes. `RotateGuard(ctx)` closes the
guard channel and `connectGuard(..., avoid)` picks a different guard.

### Two crypto regimes (do not mix)

- **Clearnet hops (ntor v1):** AES-128-CTR + running **SHA-1** digest; relay cells
  use the tor1 layout; circuit SENDME tag is 20 bytes.
- **Onion end-to-end hop (hs_ntor):** AES-256-CTR + running **SHA-3-256** digest,
  added via `circuit.AddRendezvousHop`. The SENDME tag is still truncated to 20
  bytes even here.

### Directory cache + tunnel

`Config.DataDir` enables `directory.DiskCache` (consensus/certs/microdescs by hash;
cached consensus is re-verified against hardcoded authority identities). After the
guard is up, the root `Client` registers itself as the `directory.Tunnel`, so
microdescriptor and consensus-refresh fetches go through a reusable BEGIN_DIR
circuit. The cold-start consensus is necessarily direct (no circuit yet). The dir
circuit's own relays are resolved with `FetchMicrodescriptorsDirect` to avoid a
build-needs-microdescs cycle.

## Protocol gotchas that span files (high-bug-risk)

- **CircID width:** 2 bytes only for the initial VERSIONS exchange, 4 bytes after.
  Wrong width parses everything downstream as garbage.
- **Persistent AES-CTR:** one cipher.Stream per hop per direction for the circuit's
  lifetime — the counter advances across cells. A fresh cipher per cell breaks it.
- **Relay digest:** zero the 4-byte digest field → hash the 509B payload → write the
  digest back → then layer AES-CTR. On receive, peel outward, checking `recognized==0`
  **and** the digest (recognized alone has 2^-16 false positives). Verifying without
  corrupting digest state uses `RunningDigest.VerifyAndCommit` (clones, commits on match).
- **RELAY_EARLY:** EXTEND2 must go in RELAY_EARLY cells; max 8 per circuit.
- **Onion descriptor URL uses base64** of the blinded key (NOT base32).
- **Descriptor MESSAGE blocks are extracted manually** (not `encoding/pem`): a
  decrypted layer is NUL-padded, which the stdlib PEM reader rejects.
- **Descriptor signature** covers bytes up to and including the `\n` before
  `signature` (keyword excluded), prefixed by `Tor onion service descriptor sig v3`.
- **Family exclusion is mutual:** two relays are same-family only if each lists the
  other (`directory.SameFamily`); path selection re-rolls on conflict (`pickRelay`).
- **Stream flow control is consumption-based:** stream SENDMEs are emitted as the app
  *reads* (chunk deque in `pkg/stream`), not on arrival — bounds buffering.
- Directory authorities answer with zlib **`deflate`** (not gzip); decode it manually.

## Verification conventions

Offline tests use crypto vectors (hs_ntor, blinding, digest), codec round-trips,
and relay onion-crypto round-trips modeling the relay side. The descriptor
signature path is regression-tested against a captured real descriptor in
`pkg/onion/testdata/`. End-to-end correctness is asserted by the live tests.
After any protocol change: `go build ./... && go vet ./... && go test -short ./...`,
then the relevant live test.
