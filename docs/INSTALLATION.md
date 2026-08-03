# Installation and Release Signing

## Release downloads

Official installers are attached to GitHub Releases:

- Windows x64 NSIS installer
- Linux x86_64 AppImage
- Linux amd64 Debian package
- Android APK
- Native core archives for Windows and Linux
- `SHA256SUMS.txt`

Verify both the checksum file and GitHub artifact attestation before installation.

The root `package.json` version is the repository release version. A release-relevant push to `main` performs the full cross-platform packaging matrix and creates the matching immutable `v<version>` tag and GitHub Release when it does not already exist. A direct semantic-version tag push is also supported. Existing releases are never replaced or retagged.

## Source prerequisites

| Target | Requirements |
|---|---|
| TypeScript packages | Node.js 22+, npm 10+ |
| Windows desktop | Windows runner, Electron/electron-builder prerequisites |
| Linux desktop | Ubuntu 24.04+, FUSE for AppImage execution |
| Android | Android 13+ device; JDK 17, Android SDK/Build Tools 36, Gradle 9.5 for source builds |
| Native core | CMake 3.22+, C++20 compiler, OpenSSL 3 development package |

## Android release signing

Never commit an Android keystore or passwords. Configure a protected GitHub `release` environment with:

- `AIRVAULT_ANDROID_KEYSTORE_BASE64`
- `AIRVAULT_ANDROID_KEYSTORE_PASSWORD`
- `AIRVAULT_ANDROID_KEY_ALIAS`
- `AIRVAULT_ANDROID_KEY_PASSWORD`

For a local build, pass:

```bash
gradle -p apps/android assembleRelease \
  -PAIRVAULT_KEYSTORE_FILE=/absolute/path/airvault-release.jks \
  -PAIRVAULT_KEYSTORE_PASSWORD='...' \
  -PAIRVAULT_KEY_ALIAS='airvault' \
  -PAIRVAULT_KEY_PASSWORD='...'
```

Back up the keystore offline. Losing it prevents users from installing updates over an existing APK. A changed certificate must be treated as a security event.

The workflow accepts either all four Android signing secrets or none. A partial configuration is rejected. When none are configured, CI produces an installable `-android-debug.apk` validation artifact instead of pretending that the APK is production-signed. Debug-signed APKs are for testing only, use the `.debug` application ID, and must not be distributed as production updates.

## Windows code signing

electron-builder supports a protected code-signing certificate through its standard `CSC_LINK` and `CSC_KEY_PASSWORD` environment variables. Configure both in the GitHub `release` environment. A partial configuration is rejected. When neither secret is configured, CI disables certificate auto-discovery and labels the resulting validation installer with `-unsigned.exe`.

Only Android assets without the `-debug` suffix and Windows assets without the `-unsigned` suffix are production-signing candidates. Always inspect `ARTIFACT_SECURITY.md`, verify `SHA256SUMS.txt`, and verify the published artifact attestation before distribution.

## Linux verification

The release workflow generates checksums and GitHub artifact attestations. Distributions may additionally repackage AirVault under their own signing policy.
