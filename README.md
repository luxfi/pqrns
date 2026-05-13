# pqrns

> **PQ-RNS**: hybrid post-quantum profile for the
> [Reticulum Network Stack](https://github.com/markqvist/Reticulum).
> Paper: [luxfi/papers/pq-rns](https://github.com/luxfi/papers/tree/main/pq-rns).
> Spec: [LP-9701](https://github.com/luxfi/lps/blob/main/LPs/lp-9701-reticulum-network-stack.md).

Reticulum is the cryptography-based mesh-networking stack designed by
Mark Qvist for LoRa, packet radio, KISS modems, serial lines,
free-space optical links, and any other half-duplex carrier with at
least 5 bps and a 500-byte MTU. It provides initiator-anonymous,
coordination-less multi-hop transport with end-to-end encryption and
unforgeable delivery acknowledgements, completely without IP.

PQ-RNS extends RNS with a hybrid PQ identity and key-exchange layer
**without forking the reference protocol**:

| Purpose | Native RNS (classical) | PQ-RNS extension (hybrid) |
|---|---|---|
| Identity signing | Ed25519 | Ed25519 + ML-DSA-65 (FIPS 204) |
| Key exchange | X25519 | X25519 + ML-KEM-768 (FIPS 203) |
| Session encryption | AES-256-CBC + HMAC-SHA-256 | (unchanged) |
| KDF | HKDF-SHA-256 | HKDF-SHA-256 over hybrid secret |

A capability bit in the announce frame advertises hybrid-PQ support.
Two PQ-capable peers upgrade to hybrid automatically; a peer with
`requirePostQuantum: true` refuses classical-only counterparties.

## Forward secrecy

Both halves of the KEM are ephemeral per link: a fresh X25519 keypair
and a fresh ML-KEM-768 keypair are generated, used to derive the
session key, then zeroed. Retrospective decryption requires recovering
**both** ephemerals — the classical leg AND the lattice leg — for
every recorded link. Long-term identity keys (Ed25519 + ML-DSA-65)
authenticate the transcript only; they never directly wrap session
traffic.

## Wire-format cost

| Component | Classical | Hybrid | Δ |
|---|---|---|---|
| Public identity | 64 B | ~3.2 KiB | +3.1 KiB |
| Signature (one) | 64 B | ~2.5 KiB | +2.4 KiB |
| KEX ciphertext (one) | 32 B | ~1.2 KiB | +1.1 KiB |
| Handshake total (3 pkts) | ~192 B | ~9 KiB | +8.8 KiB |
| Steady-state per-packet | 0.44 bps | 0.44 bps | 0 |

For sub-1 Kbps carriers a `HYBRID_PSK_RESPONDER` mode is available
(long-term ML-KEM key pre-shared out-of-band, ephemeral only on the
initiator). Trades responder-side ephemeral PFS on the lattice leg
for ~3× bandwidth reduction.

## Layout

```
pqrns/
├── cmd/pqrnsd/        daemon: serve PQ-RNS over configured interfaces
├── pkg/identity/      hybrid identity (Ed25519 + X25519 + ML-DSA-65 + ML-KEM-768)
├── pkg/link/          hybrid link establishment + session key derivation
├── pkg/announce/      capability-bearing announce frames
├── pkg/cap/           capability negotiation (require / hybrid_full / hybrid_psk)
└── .github/workflows/ CI gates
```

## Configuration

```yaml
# ~/.lux/config.yaml — node-side
rns:
  enabled: true
  configPath: ~/.lux/reticulum
  announceInterval: 5m
  interfaces:
    - AutoInterface          # WiFi / Ethernet auto-discovery
    - TCPClientInterface     # explicit TCP carrier
    - LoRaInterface          # RNode LoRa transceiver
  linkTimeout: 30s
  postQuantum: true          # advertise PQ capability
  requirePostQuantum: false  # accept classical peers (default)
```

Setting `requirePostQuantum: true` makes the node a strict-PQ enclave;
classical-only peers cannot link and any attempt is rejected before
key material is exchanged.

## Composition

PQ-RNS sits where TCP/IP cannot: mesh / LoRa / packet radio /
free-space optical / disconnected networks / contested EW environments.
On TCP/IP the equivalent role is held by [luxfi/zwing](https://github.com/luxfi/zwing).
On top of both rides [luxfi/pqsafe](https://github.com/luxfi/pqsafe) for
file envelopes, with [luxfi/age](https://github.com/luxfi/age) handling
at-rest re-keying when E2E transfer isn't possible.

```
Application data (file, message, RPC)
     │
     ▼  PQSAFE envelope (ciphertext + signed manifest)
     │
     ▼  Z-Wing (TCP/IP)  OR  PQ-RNS (mesh / LoRa / packet radio)
     │
     ▼  TCP / WiFi / LoRa / packet radio / KISS / serial / optical
```

## Domain separation

```go
const (
    CtxLinkKDF      = "PQRNS-LINK-v1"
    CtxIdentitySig  = "PQRNS-IDENTITY-SIG-v1"
    CtxAnnounceSig  = "PQRNS-ANNOUNCE-SIG-v1"
    CtxRekey        = "PQRNS-LINK-REKEY-v1"
)
```

Every HKDF derivation and every signature carries an explicit context
string. No two layers ever derive a key from the same transcript.

## Status

Reference profile for LP-9701. The Lux node already ships PQ-RNS
under `network/dialer/` ([luxfi/node](https://github.com/luxfi/node));
this repo carries the standalone library + CLI for non-node consumers
(file utilities, embedded devices, mesh applications).

The authoritative Reticulum reference is
[markqvist/Reticulum](https://github.com/markqvist/Reticulum). PQ-RNS
is interoperable with native RNS: a PQ-RNS node looks like an ordinary
RNS peer to classical-only nodes.

## Paper

`luxfi/papers/pq-rns/pq-rns.tex` is the authoritative specification.
This implementation tracks the paper; any divergence is a bug in the
implementation.

## License

Apache-2.0 (see `LICENSE`). The native RNS protocol itself was
dedicated to the Public Domain by its author in 2016; PQ-RNS is an
Apache-2.0-licensed extension.
