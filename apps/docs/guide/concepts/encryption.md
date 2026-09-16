# Encryption & Secrets

Tunnet does not use WireGuard. All mesh traffic is encrypted using QUIC, powered by the [iroh](https://iroh.computer) networking library.

## Why QUIC instead of WireGuard?

WireGuard is excellent for point-to-point VPN tunnels, but mesh networking on top of it requires workarounds: userspace implementations for NAT traversal, separate relay protocols, and no native support for multiplexed streams.

iroh provides QUIC connections with built-in NAT traversal (STUN, relay fallback), multiplexed bidirectional streams (used for serve, tunnel, and file transfer), and datagram support (used for mesh packet forwarding). The encryption is TLS 1.3 under the hood.

## Connection establishment

When peer A wants to reach peer B, the iroh endpoint uses the peer's endpoint ID (derived from its Ed25519 public key) to establish a QUIC connection. iroh tries direct connectivity first (via known addresses and STUN), then falls back to relay-assisted connectivity if a direct path cannot be established.

## Direct mode transport auth

In Direct mode (no control plane), peers authenticate before accepting data-plane ALPNs. Joining uses an **invite bootstrap** proof (HMAC over the join secret from the invite code). After membership is established, peers present coordinator-signed **network grants** tied to the current **network epoch**. Coordinators bump the epoch and publish **revocations** when kicking a peer; revoked endpoints are rejected on reconnect.

## Secrets at rest

Sensitive material is stored separately from public config:

| File | Contents |
|------|----------|
| `state.json` | Public enrollment / network metadata (no secrets) |
| `tunnet.toml` | Public agent config (firewall, DNS, logging, …) |
| `state.enc` | AES-256-GCM ciphertext of identity seed, network PSKs, doc tickets, and login tokens |
| `state.enc.meta` | Seal tier and wrapped data-encryption key |

On write, Tunnet picks the best available seal tier:

1. **tpm** - Windows DPAPI (TPM-backed when present)
2. **keychain** - macOS Keychain
3. **derived** - key derived from stable machine identity and a random per-state salt (resists offline copy to another machine)
4. **plaintext** - only when forced

Force plaintext with `--no-encrypt-state` or `TUNNET_NO_ENCRYPT_STATE=1` on `enroll`, `create`, `join`, or `run`. Use this only for containers and CI.
