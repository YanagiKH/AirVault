# Contributing to AirVault

Thank you for improving AirVault. File transfer and cryptographic code requires unusually careful review.

## Before opening a change

1. Search existing issues and pull requests.
2. Open an issue for protocol, cryptographic-suite, persistent-format, or architecture changes.
3. Keep unrelated changes in separate pull requests.
4. Never include real credentials, private keys, signing files, or personal test data.

Security vulnerabilities must follow [SECURITY.md](SECURITY.md), not the public issue tracker.

## Local verification

```bash
npm ci
npm run typecheck
npm test
npm run build

cmake -S native/core -B native/core/build -DCMAKE_BUILD_TYPE=Debug
cmake --build native/core/build --parallel
ctest --test-dir native/core/build --output-on-failure

gradle -p apps/android lintDebug testDebugUnitTest assembleDebug
```

## Security requirements

- Use established platform cryptography; do not introduce custom cryptographic primitives.
- Bind every protocol field that affects identity, authorization, routing, or decryption to a signature, KDF transcript, or AEAD AAD.
- Never reuse an AEAD nonce with the same key.
- Treat relay, discovery, filenames, file metadata, and incoming packets as untrusted.
- Keep Electron renderers sandboxed with context isolation and a narrow IPC allowlist.
- Use constant-time comparisons for secrets and authentication values.
- Add negative tests for malformed, replayed, stale, oversized, and out-of-order input.
- Keep external GitHub Actions pinned to full commit SHAs.
- Update the threat model and protocol document when a trust boundary changes.

## Pull requests

Describe the problem, security impact, implementation, compatibility impact, and exact validation commands. Protocol changes need cross-platform test vectors. User-facing changes need screenshots or accessible visual descriptions.

By contributing, you agree that your contribution is licensed under Apache License 2.0.
