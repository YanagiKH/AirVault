# Security Policy

## Supported versions

Security updates are provided for the latest release and the current `main` branch.

| Version | Supported |
|---|---|
| Latest release | Yes |
| `main` | Yes |
| Older releases | No |

## Report a vulnerability

Please use [GitHub private vulnerability reporting](https://github.com/YanagiKH/AirVault/security/advisories/new). Do not open a public issue, discussion, or pull request containing exploit details.

Include:

- affected version and component;
- concise impact and attacker prerequisites;
- reproduction steps or proof of concept;
- affected file and line when known;
- suggested mitigation, if available;
- whether the issue is already public.

Never include real private keys, access tokens, personal files, or third-party data. Use synthetic test material.

## Response targets

- Initial acknowledgement: within 3 business days
- Triage decision: within 7 business days
- Status update: at least every 14 days while remediation is active

Timelines may change with severity and complexity. Coordinated disclosure dates are agreed with the reporter after a fix is validated and release users have a reasonable update window.

## Scope

In scope:

- protocol and cryptographic implementation errors;
- authentication, identity pinning, and authorization bypass;
- plaintext disclosure to a relay or unauthorized peer;
- unsafe file write, path traversal, or integrity-check bypass;
- relay denial of service caused by bounded unauthenticated input;
- Electron renderer-to-main privilege escalation;
- Android storage or Keystore protection failures;
- release workflow and dependency supply-chain vulnerabilities.

Generally out of scope:

- social engineering without a product vulnerability;
- physical access to an already-unlocked endpoint;
- denial of service consisting only of blocking network access;
- scanner detection gaps without a bypass in AirVault's own controls;
- reports generated only by an automated scanner without a reproducible vulnerable path.

## Safe harbor

Good-faith research that respects privacy, avoids destructive testing, uses accounts and devices you control, and reports findings privately is welcomed. Stop testing if you encounter other people's data or risk service disruption.
