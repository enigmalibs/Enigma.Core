# Security Policy

Enigma.Core is a cryptography library, so the correctness and confidentiality of its implementations
matter directly to the security of the applications that depend on it. Vulnerability reports are
taken seriously and handled with priority.

## Supported versions

Security fixes are provided for the latest released version. Enigma.Core follows
[Semantic Versioning](https://semver.org/), and users are encouraged to stay current with the newest
release.

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | :white_check_mark: |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull
requests.** Public disclosure before a fix is available puts every user at risk.

Instead, use **GitHub's private vulnerability reporting**:

1. Go to the repository's **Security** tab.
2. Select **Report a vulnerability** to open a private advisory.
3. Include as much detail as you can — the affected version, the algorithm or component involved, a
   description of the issue, and, where possible, a minimal reproduction and its impact.

This keeps the report private between you and the maintainers while it is triaged and fixed.

## What to expect

- Your report will be acknowledged and triaged as promptly as possible.
- The issue will be investigated and, once confirmed, a fix prepared and released.
- Coordinated disclosure is preferred: please allow a reasonable period for a fix to ship before any
  public discussion of the vulnerability.
- Your contribution will be credited in the resulting advisory unless you ask to remain anonymous.

## Scope

Reports concerning the cryptographic implementations, key handling, or the public API surface of
Enigma.Core are in scope. Because Enigma.Core builds on BouncyCastle, issues rooted in the
underlying BouncyCastle library should also be reported upstream to the BouncyCastle project.
