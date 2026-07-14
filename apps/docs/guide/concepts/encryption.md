# Encryption & Secrets

TunTun does not use WireGuard. All mesh traffic is encrypted using QUIC, powered by the [iroh](https://iroh.computer) networking library.

## Why QUIC instead of WireGuard?

WireGuard is excellent for point-to-point VPN tunnels, but mesh networking on top of it requires workarounds: userspace implementations for NAT traversal, separate relay protocols, and no native support for multiplexed streams.

iroh provides QUIC connections with built-in NAT traversal (STUN, relay fallback), multiplexed bidirectional streams (used for serve, tunnel, SSH, and file transfer), and datagram support (used for mesh packet forwarding). The encryption is TLS 1.3 under the hood.

## Connection establishment

When peer A wants to reach peer B, the iroh endpoint uses the peer's endpoint ID (derived from its Ed25519 public key) to establish a QUIC connection. iroh tries direct connectivity first (via known addresses and STUN), then falls back to relay-assisted connectivity if a direct path cannot be established.

## ALPN protocol negotiation

TunTun uses QUIC ALPN (Application-Layer Protocol Negotiation) to multiplex different protocols over the same iroh endpoint. Each protocol has its own ALPN identifier: `tuntun/tunnel/1` for mesh datagrams, `tuntun/relay/1` for relay reverse tunnels, `tuntun/ssh/1` for SSH sessions, `tuntun/send/1` for file transfers, and `tuntun/recording/1` for SSH session recordings.

## Direct mode transport auth

In Direct mode (no control plane), peers additionally perform a PSK handshake before accepting any application-level ALPN. This ensures that only peers who know the network secret can communicate, even without a central authority.

## Secrets at rest

Sensitive material is stored separately from public config:

| File | Contents |
|------|----------|
| `state.json` | Public enrollment / network metadata (no secrets) |
| `tuntun.toml` | Public agent config (firewall, DNS, logging, …) |
| `state.enc` | AES-256-GCM ciphertext of identity seed, network PSKs, doc tickets, and login tokens |
| `state.enc.meta` | Seal tier and wrapped data-encryption key |

On write, TunTun picks the best available seal tier:

1. **tpm** - Windows DPAPI (TPM-backed when present)
2. **keychain** - macOS Keychain
3. **derived** - key derived from machine-id + boot-id + salt (resists offline copy to another machine)
4. **plaintext** - only when forced

Force plaintext with `--no-encrypt-state` or `TUNTUN_NO_ENCRYPT_STATE=1` on `enroll`, `create`, `join`, or `run`. Use this only for containers and CI.
