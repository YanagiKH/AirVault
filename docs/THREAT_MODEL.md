# AirVault Threat Model

## Scope

The model covers the TypeScript protocol, Electron desktop client, Java Android client, C++ native core, WebSocket relay, release automation, and data exchanged between two AirVault endpoints.

## Assets

- device identity private keys;
- ephemeral X25519 private keys and derived session material;
- one-time PINs and QR secrets;
- plaintext file names, manifests, and contents;
- saved peer identities;
- release-signing keys and artifacts.

## Trust boundaries

| Boundary | Trust assumption |
|---|---|
| Sender endpoint | Trusted while selecting and encrypting files |
| Receiver endpoint | Trusted while approving, decrypting, scanning, and saving files |
| Relay | Untrusted for confidentiality and content integrity; trusted only for best-effort availability |
| Local network | Untrusted; discovery traffic can be observed, spoofed, replayed, or dropped |
| Out-of-band PIN/QR channel | Must be independent enough to detect or prevent an active relay attacker |
| Build and release system | Protected GitHub environment, reviewed workflow, least-privilege token, external Android signing secret |

## In-scope attackers

- a malicious or compromised relay;
- a network attacker who can observe, modify, inject, replay, or drop traffic;
- an unauthenticated internet client attacking the relay;
- a local-network attacker sending forged discovery packets;
- a malicious sender attempting path traversal, disk exhaustion, executable delivery, replay, or chunk reordering;
- a supply-chain attacker modifying dependencies or release automation.

## Out of scope

- an endpoint compromised before encryption or after decryption;
- a user intentionally approving and opening a malicious file;
- traffic-analysis resistance against a global observer;
- denial of service that consists solely of blocking all network connectivity;
- recovery of an identity key deleted with application data.

## Primary attack paths and controls

| Attack path | Control |
|---|---|
| Relay substitutes an identity or ephemeral key | Ed25519 signatures, device-ID fingerprint binding, pinned peer key, out-of-band proof |
| Relay guesses a PIN | Five attempts per offer, ten-minute expiry, PIN never sent to relay, QR alternative with 256-bit secret |
| Replay of an old offer or registration | Timestamp window, expiry, random challenges, one-time nonce cache, transfer-specific keys |
| Ciphertext modification or reordering | AES-GCM tag, purpose/index AAD, deterministic unique nonce, exact chunk sequence |
| Malicious destination path | Cross-platform normalization, absolute/traversal/reserved-name rejection, SAF on Android |
| Disk exhaustion | 256-file and 100 GiB transfer caps, receiver manifest approval, declared-size enforcement |
| Partial-file confusion | Temporary suffix, integrity verification before final rename, unique final name |
| Discovery spoofing | Signed beacon, public-key fingerprint verification, freshness, nonce replay cache, no automatic trust |
| WebSocket compression attack | Compression disabled and payload size capped |
| Dependency or workflow compromise | Locked dependencies, Dependabot, dependency review, CodeQL, least-privilege workflow permissions, artifact attestations |

## Residual risk

Six-digit PIN authorization has limited entropy and depends on attempt limits at the receiving endpoint. QR authorization is strongly preferred for hostile networks. Endpoint malware scanners can miss new threats. Device IDs use a truncated fingerprint for usability, so the full pinned public key remains the authoritative identity after first verification.
