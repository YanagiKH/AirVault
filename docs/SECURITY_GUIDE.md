# AirVault Security Guide

This manual explains AirVault's security controls, operational requirements, and limits. Administrators and users should read it before transferring sensitive material.

## Security objectives

AirVault is designed to:

- keep file names, manifest details, and file contents confidential from the relay;
- authenticate permanent device identities;
- provide fresh session keys for every transfer;
- require an explicit, short-lived out-of-band authorization;
- detect modification, replay, truncation, reordering, and identity-key substitution;
- prevent unsafe destination paths and silent executable delivery;
- preserve partial files outside their final names until integrity verification succeeds.

AirVault does not attempt to hide all traffic metadata. A relay or network observer can infer connections, timing, IP addresses, device IDs used for routing, and approximate ciphertext volume. AirVault also cannot protect plaintext after a trusted endpoint displays or saves it.

## Cryptographic protocol

1. Each installation creates an Ed25519 identity key pair. The device ID is a truncated, human-readable base32 encoding of the SHA-256 public-key fingerprint.
2. The sender creates a fresh X25519 key pair, challenge, transfer ID, six-digit PIN, and independent 256-bit QR secret.
3. The signed offer commits to the receiver ID, ephemeral public key, manifest digest, creation time, expiry, and PIN/QR HMAC commitments.
4. The receiver verifies the sender signature, device-ID fingerprint, target ID, time window, and authorization commitment.
5. The receiver creates its own fresh X25519 key pair and signs an acceptance containing an authorization proof.
6. Both devices derive 64 bytes with HKDF-SHA-256. The input binds the X25519 shared secret, signed offer transcript, transfer ID, and chosen PIN/QR secret.
7. The first 32 bytes are the AES-256-GCM content key. The remaining 32 bytes derive unique 96-bit nonces from the transfer ID, packet purpose, and monotonic packet index.
8. The manifest is encrypted before the relay sees it. Files are then encrypted in independent authenticated chunks after receiver approval.

PINs contain about 20 bits of entropy. The signed offer contains a PIN verifier, so a relay that records an offer can enumerate the six-digit PIN offline. This does not reveal the X25519 shared secret or let the relay sign as the destination device, but it means the PIN must be treated as a short-lived consent check rather than the sole cryptographic authentication factor. AirVault also limits a receiver to five failed attempts per offer and expires offers after ten minutes. Prefer the QR path for high-risk transfers because it carries an independent 256-bit secret. Never transmit the PIN through the same potentially compromised channel used to coordinate the transfer.

## Identity pinning

Adding a device ID creates an unverified saved peer. The first successful transfer authorized by PIN or QR verifies that the presented public key hashes to the saved ID and then pins the full public key. Every later transfer requires the exact same key.

If AirVault reports that an identity key changed:

1. Stop the transfer.
2. Contact the peer through an independent trusted channel.
3. Confirm whether AirVault was reinstalled or the device was intentionally reset.
4. Remove and re-add the peer only after comparing the full new ID.

There is no automatic key replacement.

## Secure local discovery

Desktop and Android clients send small signed multicast beacons on the local network. A beacon includes only the device ID, public identity key, timestamp, and random nonce. AirVault verifies the signature, fingerprint, timestamp, and replay nonce before displaying or processing it.

Discovery never creates trust automatically and never bypasses PIN/QR authorization. Desktop marks an already-saved ID online only after validation. Android may list a validated nearby ID, but the user must explicitly select “Save”; only then is the advertised full identity key pinned. A conflicting key for an already-pinned ID is rejected.

Local discovery exposes the device ID and public key to systems on the local subnet. Block UDP port 53545 or disable multicast at the network layer when this presence metadata is unacceptable.

## File safety pipeline

Before sending:

- only regular, non-symbolic-link files are accepted on desktop;
- each file is read to calculate SHA-256;
- the file count, total byte count, names, and destination paths are validated;
- dangerous executable extensions are marked for receiver review.

Before receiving bytes:

- the encrypted manifest is authenticated and compared with the signed manifest digest;
- absolute paths, path traversal, reserved Windows names, duplicate paths, invalid sizes, and malformed hashes are blocked;
- the receiver sees the file list, aggregate size, and executable warnings and must explicitly approve.

During and after receipt:

- chunks must arrive in exact sequence and are authenticated with AES-GCM;
- received bytes cannot exceed the declared file size;
- output uses temporary `.airvault-part` names;
- every completed file must match the committed size and SHA-256 digest;
- desktop clients call Microsoft Defender or ClamAV when a supported local scanner is available;
- only verified files are renamed to their final unique names.

Malware scanning is defense in depth, not a guarantee that a file is harmless. Keep endpoint protection and operating systems updated, and do not open an unexpected executable merely because it passed a scanner.

## Relay requirements

Production clients must use `wss://`. The Android client rejects user-info and local hostnames, then rechecks every DNS answer at connection time and blocks loopback, private, link-local, multicast, documentation, carrier-grade NAT, and IPv6 ULA addresses. Self-hosted Android relays therefore need a publicly routable TLS endpoint. Terminate TLS 1.2 or newer at a maintained reverse proxy, prefer TLS 1.3, enable HSTS on related HTTPS endpoints, and do not log WebSocket payloads.

Run the relay:

- as a non-root user;
- without host filesystem mounts;
- with a read-only root filesystem and dropped Linux capabilities;
- behind connection, bandwidth, and IP-level abuse controls;
- with logs restricted to operational events and short retention;
- on a dedicated origin not shared with untrusted applications.

The relay authenticates registrations with Ed25519 signatures, rejects stale or replayed nonces, limits message size, disables WebSocket compression, and rate-limits messages. It does not persist file data.

## Device security

- Enable full-disk encryption and a screen lock.
- Keep the AirVault application, operating system, and endpoint scanner updated.
- Do not copy AirVault's private application-data directory between devices.
- Back up files separately; AirVault is a transfer tool, not archival storage.
- Remove saved devices that are lost, sold, or no longer trusted.
- Treat QR authorization images and PINs as temporary secrets.
- Verify release checksums, attestations, and Android signing certificates.
- Do not install builds from untrusted mirrors.

Desktop private identity material is protected with Electron `safeStorage` where the operating system provides it and stored with owner-only file permissions. Android private identity material is encrypted by a non-exportable AES-256 key in Android Keystore.

## Incident response

For a suspected compromised endpoint:

1. Disconnect it from the network.
2. Stop using its AirVault ID.
3. Remove that ID from all peers.
4. Preserve relevant operating-system and relay logs.
5. Reinstall AirVault on a known-clean system to create a new identity.
6. Re-add the new ID through a verified channel.
7. Assume files already decrypted on the compromised endpoint may be exposed.

For a suspected relay compromise, rotate TLS and infrastructure credentials, redeploy from a verified image, inspect metadata logs, and notify users. Previously transferred file contents remain protected unless an endpoint, authorization secret, or session key was also compromised.

## Verification checklist

- [ ] The application came from the official release and its checksum matches.
- [ ] The relay URL uses `wss://` and a valid certificate.
- [ ] The destination device ID was exchanged over a trusted channel.
- [ ] Identity-key change warnings are treated as blocking.
- [ ] PINs or QR codes are shared out of band.
- [ ] The receiver reviews names, sizes, and executable warnings.
- [ ] Endpoint malware protection is active.
- [ ] Sensitive plaintext is protected after download.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Follow [SECURITY.md](../SECURITY.md).
