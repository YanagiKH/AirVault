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

## Source prerequisites

| Target | Requirements |
|---|---|
| TypeScript packages | Node.js 22+, npm 10+ |
| Windows desktop | Windows runner, Electron/electron-builder prerequisites |
| Linux desktop | Ubuntu 24.04+, FUSE for AppImage execution |
| Android | Android 13+ device; JDK 17, Android SDK/Build Tools 35, Gradle 8.13 for source builds |
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

## Windows code signing

electron-builder supports a protected code-signing certificate through its standard `CSC_LINK` and `CSC_KEY_PASSWORD` environment variables. Configure them in the GitHub `release` environment. Unsigned pull-request builds are validation artifacts only.

## Linux verification

The release workflow generates checksums and GitHub artifact attestations. Distributions may additionally repackage AirVault under their own signing policy.
