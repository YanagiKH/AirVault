# AirVault Protocol v1

## Primitive suite

- Identity signature: Ed25519
- Ephemeral key agreement: X25519
- Key derivation: HKDF-SHA-256
- Content AEAD: AES-256-GCM with 128-bit tag
- File commitment: SHA-256
- Serialization: canonical UTF-8 JSON with recursively sorted object keys

All protocol numbers are JSON safe integers. Binary values are unpadded base64url unless identified as PEM.

## Device identifier

The Ed25519 public key is exported as SubjectPublicKeyInfo DER. AirVault hashes the DER with SHA-256, base32-encodes the digest, takes the first 20 characters, and renders:

```text
AV-XXXXX-XXXXX-XXXXX-XXXXX
```

The human-readable ID is checked whenever a public key is presented. The complete public key is pinned after authorization.

## Offer

The signed offer contains:

- protocol version and random transfer ID;
- sender and intended receiver IDs;
- sender Ed25519 public key;
- fresh sender X25519 public key;
- 192-bit random challenge;
- SHA-256 digest of the canonical plaintext manifest;
- creation and expiry times;
- HMAC-SHA-256 commitments to the PIN and QR secret.

The signature covers every field except `signature`.

## Acceptance

The receiver verifies the offer and authorization commitment, creates a fresh X25519 key, and returns a signed acceptance. The acceptance binds the receiver identity, receiver ephemeral key, transfer ID, authorization method, timestamp, and HMAC proof over both ephemeral-key transcripts.

## Session derivation

```text
shared = X25519(local_ephemeral_private, remote_ephemeral_public)
salt   = SHA-256("AirVault/v1/session\0" || unsigned_offer || "\0" || authorization_secret)
keys   = HKDF-SHA-256(shared, salt, info=transfer_id, length=64)
Kenc   = keys[0..31]
Kconf  = keys[32..63]
```

Implementations erase the raw shared secret and intermediate material when their runtime exposes a reliable primitive.

## Packet encryption

For a packet purpose and monotonically increasing index:

```text
aad   = canonical_json({version, transferId, purpose, index})
nonce = HMAC-SHA-256(Kconf, aad)[0..11]
packet = AES-256-GCM(Kenc, nonce, aad, plaintext)
```

Purposes are separate namespaces such as `manifest`, `control`, and `file:0`. An index must never repeat within a purpose. Receivers reject unexpected purposes, indexes, and nonces before releasing plaintext.

## Transfer order

1. Signed offer
2. Signed and authorized acceptance
3. Encrypted manifest
4. Receiver safety scan and explicit approval
5. Encrypted `ready` control
6. Encrypted ordered file chunks
7. Encrypted `complete` control
8. File-size and SHA-256 verification
9. Optional local malware scan and final rename

## Relay envelope

Relay messages expose only `from`, `to`, `transferId`, and an opaque protocol payload. Registrations are signed and expire after five minutes. Binary WebSocket frames and compressed messages are not used.

## Versioning

Implementations reject unknown major protocol versions. Cryptographic-suite changes require a new major protocol version and new test vectors; silent algorithm fallback is prohibited.
