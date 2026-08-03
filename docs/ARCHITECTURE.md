# AirVault Architecture

AirVault separates cryptographic policy, endpoint user interfaces, native defensive primitives, and ciphertext routing.

## Components

| Component | Responsibility |
|---|---|
| TypeScript protocol package | Canonical serialization, identity fingerprints, signed handshake, key derivation, AEAD, manifest rules |
| Electron main process | Private-key access, filesystem access, local discovery, relay connection, transfer state machine |
| Electron renderer | Sandboxed user interface with a narrow context-bridge API and strict Content Security Policy |
| Java Android client | Android 7+ Keystore-protected identity, signed nearby discovery, Scandit QR-only scanning with credential-free fallback, Storage Access Framework I/O, E2EE transfer state machine |
| C++ native core | OpenSSL hashing, secure zeroing, constant-time comparison, bounded binary frame parsing, C API |
| Relay | Authenticated device registry and content-blind routing with no transfer persistence |

## Endpoint flow

The renderer never receives identity private keys, ephemeral private keys, or session keys. Desktop filesystem and network operations live in the Electron main process. The Android app delegates document access to Android's picker and uses content URIs rather than broad filesystem paths.

## Relay flow

The relay maintains only an in-memory map from authenticated device IDs to current WebSocket connections. Messages are forwarded in order to a named destination. Offline messages are not queued, and transfer payloads are not stored.

## Failure behavior

Cryptographic verification failures, identity changes, stale messages, invalid paths, out-of-order chunks, size mismatches, and digest mismatches stop the transfer. AirVault does not downgrade security algorithms or continue with unauthenticated data.
