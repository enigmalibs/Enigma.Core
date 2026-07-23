# FEATURE-4620 — NuGet release preparation (v1.0.0)

**Status:** DONE (multi-phase)
**Type:** FEATURE (multi-phase)
**Branch (per phase, at build time):** `feature/feature-4620-phaseNN-<slug>` — one branch per phase, cut from current `HEAD`.

## Objective

Prepare **Enigma.Core** for its first public NuGet release, version **1.0.0**: complete package
metadata / build config, run a license check, produce a summary-style README backed by
per-category documentation/samples, write initial release notes, add community files
(`SECURITY.md`, `CLAUDE.md`), and produce (print, never run) the release runbook. This is the
final feature before publishing; the base roadmap is otherwise `DONE`.

## Context & constraints

- **Evolution of an existing codebase.** Enigma.Core is a re-architected .NET cryptography library
  (service + factory + DI, BouncyCastle-backed) at `https://github.com/enigmalibs/Enigma.Core`
  (org `enigmalibs`, distinct from Enigma.Cryptography's `josueclement`).
- Library multi-targets `netstandard2.0;net8.0;net10.0` — **already the correct LTS + netstandard
  set; no TFM change this release** (nothing to log in a Compatibility note).
- **Positioning: brand-new library.** README and release notes make **no reference** to
  Enigma.Cryptography. First release notes describe the 1.0.0 feature set, not a migration.
- Central Package Management (`Directory.Packages.props`); shared build defaults in
  `Directory.Build.props` (`Authors=Josué Clément`, `Copyright © 2026`, `LangVersion=14`,
  `Nullable=enable`, `TreatWarningsAsErrors=true`, `EnforceCodeStyleInBuild=true`).
- Tests are MTP-native (`xunit.v3` + `coverlet.collector`, no `Microsoft.NET.Test.Sdk`).
- Tag format: **bare `X.Y.Z`** (matches Enigma.Cryptography's existing tags; Enigma.Core has none).
- Published/default branch for the runbook: **`main`**.

## Parity audit — completed during planning, accepted as-is (audit trail)

A full category-by-category audit of Enigma.Cryptography (OLD library) vs. Enigma.Core (NEW)
confirmed **essentially complete functional/algorithmic parity**; Certificates is a **superset**.
No cipher, mode, hash, KDF, encoding, OTP, RSA, PQC, padding scheme, or certificate operation is
missing. Verdicts: Block ciphers (12 engines, ECB/CBC/CTR/GCM+AAD) = PARITY; Stream ciphers
(ChaCha20, ChaCha20-RFC7539, Salsa20) = PARITY; Padding = PARITY; Hashing (MD5/SHA-1/256/512/SHA-3)
= PARITY; HMAC (SHA1/256/512) = PARITY; KDF (PBKDF2 4 PRFs, Argon2 d/i/id ×2 versions) = PARITY;
Encoding (Base64/Base32/Hex) = PARITY; OTP (HOTP/TOTP/provisioning) = PARITY; RSA (PKCS#1v1.5 +
OAEP encrypt, PKCS#1v1.5 sign, PEM) = PARITY; PQC (ML-KEM 512/768/1024, ML-DSA 44/65/87) = PARITY;
Certificates = PARITY+ (adds Thumbprint, DER import/export, `IsRevoked`); Extensions/Utils = PARITY.

**Three minor, non-functional API-shape deltas — reviewed and ACCEPTED as intentional
re-architecture choices (no work to do):**

1. `CertificateInfo.IsValidNow` dropped — derivable from `NotBefore`/`NotAfter`.
2. Public general-purpose `PemUtils` / `PemPasswordFinder` (arbitrary-key stream PEM I/O) is now
   internal — RSA key PEM round-trip (incl. AES-256-CBC-encrypted private keys) remains available
   via the RSA service.
3. Public `X509Utils` and the public `SignatureAlgorithms` string constants are now internal —
   replaced on the public surface by `IX509CertificateService` and the `RsaSignatureAlgorithm` enum.

→ **No gap-fill work items.** Release proceeds on the current public surface.

## Design decisions (from the interview)

| Decision | Choice |
|----------|--------|
| First version | `1.0.0` |
| Positioning | Brand-new library; no reference to Enigma.Cryptography |
| Parity deltas | Accept all three as intentional; release as-is |
| README → docs linking | **Prose mention only** — no per-sample links, no absolute GitHub URLs, no nuget-breaking relative links |
| Docs content | Guide + copy-pasteable code samples per category |
| Packaging extras | `docs/RELEASE.md` runbook **only** (SourceLink/symbols, PackageIcon, GitHub Actions CI **excluded**) |
| Community files | `SECURITY.md` + `CLAUDE.md` (CONTRIBUTING.md / CHANGELOG.md excluded) |
| License metadata | `PackageLicenseFile` (reworded MIT `LICENSE.md`), not the SPDX expression |
| Badges | NuGet version + Downloads + License (MIT) |
| SECURITY.md channel | GitHub private vulnerability reporting (no email exposed) |

## Definition of Done (applies to every phase)

Per the dev-workflow skill: (1) zero-warning build; (2) full test suite green; (3) phase
acceptance criteria met; (4) roadmap + this plan's phase status updated; (5) `docs/done/<ID>.md`
written. For doc-only phases, criteria 1–2 are met by well-formedness + inspection (state that
there was nothing to build/test), except where a phase edits the csproj — those keep the full
Release build green across all three TFMs. Run the doc-freshness sweep at build time. Never
auto-commit; print a suggested commit message per phase. Runbook commands are **printed, never run**;
the NuGet API key is never stored or echoed.

---

## PHASE01 — Package metadata & build config + license check

**Status:** DONE

**Goal:** make `src/Enigma.Core/Enigma.Core.csproj` a complete, valid NuGet package definition and
verify licensing.

**Steps**

1. Edit `Enigma.Core.csproj` `<PropertyGroup>`, adding/setting:
   - `<Version>` `0.1.0` → **`1.0.0`**
   - `<Title>Enigma.Core — .NET Cryptography Library</Title>`
   - `<Description>` — a fresh one-paragraph summary of the feature set (block & stream ciphers,
     RSA, PQC (ML-DSA/ML-KEM), X.509 certificates, hashing, HMAC, OTP, KDF (PBKDF2/Argon2), padding,
     data encoding), built on BouncyCastle. **No mention of Enigma.Cryptography.**
   - `<PackageTags>` — e.g. `enigma cryptography bouncycastle aes chacha20 salsa20 rsa pqc ml-dsa
     ml-kem x509 certificate csr pfx sha hash hmac otp hotp totp base32 pbkdf2 argon2 encryption
     signing dotnet`
   - `<PackageReadmeFile>README.md</PackageReadmeFile>`
   - `<PackageLicenseFile>LICENSE.md</PackageLicenseFile>`
   - `<RepositoryUrl>https://github.com/enigmalibs/Enigma.Core</RepositoryUrl>`
   - `<RepositoryType>git</RepositoryType>`
   - `<PackageProjectUrl>https://github.com/enigmalibs/Enigma.Core</PackageProjectUrl>`
   - `<PackageReleaseNotes>` — populated in PHASE03 (mirror RELEASENOTES top); may be a placeholder
     here and finalized in PHASE03, or left for PHASE03 entirely.
   - keep `<GenerateDocumentationFile>true`; **do not** add `GeneratePackageOnBuild` (stays off).
2. Add the packaging `<ItemGroup>` (paths relative to the csproj at `src/Enigma.Core/`):
   ```xml
   <ItemGroup>
     <None Include="..\..\README.md" Pack="true" PackagePath="\" />
     <None Include="..\..\LICENSE.md" Pack="true" PackagePath="\" />
   </ItemGroup>
   ```
3. **License check** (record findings in the completion doc):
   - Confirm `LICENSE.md` is present, is MIT-equivalent text, dated 2026, and is now packed.
   - Audit third-party **runtime** dependency licenses for redistribution compatibility:
     `BouncyCastle.Cryptography` 2.6.2 = MIT; `PolySharp` = MIT (compile-only, `PrivateAssets=all`,
     not redistributed); `System.Buffers` = MIT (netstandard2.0 only). Confirm all MIT-compatible.
     (`xunit.v3`, `coverlet.collector` are test-only — not shipped.)
   - Confirm the README license badge target (`LICENSE.md`) is consistent.
4. Dependency freshness: run `dotnet list package --outdated`; apply only straightforward
   **non-coupled** bumps (BouncyCastle/PolySharp/System.Buffers) if any, recording every
   `old → new` transition; hold if uncertain. Likely no change.

**Acceptance criteria**

- `dotnet pack src/Enigma.Core/Enigma.Core.csproj -c Release` produces `Enigma.Core.1.0.0.nupkg`
  with README.md and LICENSE.md embedded (verify by inspecting the nupkg).
- Zero-warning Release build across `netstandard2.0`, `net8.0`, `net10.0`; full test suite green.
- License-check findings recorded in `docs/done/FEATURE-4620-PHASE01.md`.

---

## PHASE02 — Per-category documentation & samples

**Status:** DONE

**Goal:** one markdown guide per library category under `docs/guides/`, plus an index, each with
supported algorithms/modes, the key public classes/factories, and copy-pasteable C# usage samples.
Samples must match the **actual public API** (service + factory + DI pattern) — verify against the
source, not from memory.

**Files (13 guides + index) under `docs/guides/`:**

- `README.md` — the documentation/samples **index**: short intro + a categorized list linking each
  guide below via **relative** URLs (correct when browsing on GitHub).
- `block-ciphers.md` — 12 engines (AES, DES, 3DES, Blowfish, Twofish, Serpent, Camellia, CAST5,
  IDEA, SEED, ARIA, SM4); modes Ecb/Cbc/Ctr/Gcm; GCM AAD + `GcmMacSize`; padding integration.
- `stream-ciphers.md` — ChaCha20, ChaCha20-RFC7539, Salsa20.
- `padding.md` — None, Pkcs7, Iso7816, Iso10126, X923.
- `hashing.md` — MD5, SHA-1, SHA-256, SHA-512, SHA-3; streaming + progress/cancellation.
- `hmac.md` — HMAC-SHA1/256/512.
- `key-derivation.md` — PBKDF2 (4 PRFs), Argon2 (variants + versions).
- `encoding.md` — Base64, Base32 (RFC 4648), Hex.
- `otp.md` — HOTP (RFC 4226), TOTP (RFC 6238), `otpauth://` provisioning.
- `public-key.md` — RSA: keygen (PEM, optional encrypted private key), PKCS#1 v1.5 & OAEP
  encrypt/decrypt, sign/verify.
- `pqc.md` — ML-KEM 512/768/1024 (encapsulate/decapsulate), ML-DSA 44/65/87 (sign/verify).
- `certificates.md` — self-signed generation, CSR + validation, issuance, chain validation,
  `IsRevoked`/CRL, PKCS#12 import/export, DER import/export, `GetCertificateInfo` (incl. Thumbprint).
- `extensions.md` — `StreamExtensions.*` and `EncodingExtensions`.
- `utils.md` — `RandomUtils`, `CryptoDefaults.StreamBufferSize`.

Each guide follows a consistent shape: **Supported algorithms/schemes → Key classes/factories →
Usage example(s)**. Note the async/`IProgress<int>`/`CancellationToken` pattern where it applies
(block/stream ciphers, hashing, HMAC).

**Delegation note (build flow):** the 13 guides are independent and split cleanly — `/build` may
delegate them to parallel sub-agents (each given the target path + the relevant public API surface),
then the owner re-verifies all snippets against the source before declaring the phase done.

**Acceptance criteria**

- All 13 guides + `docs/guides/README.md` exist and are well-formed markdown.
- Every code sample compiles against the real public API (verified by inspection against source).
- Index relative links resolve on GitHub; no absolute URLs.
- Nothing to build/test (doc-only) — state so in the completion doc.

---

## PHASE03 — Summary README + release notes + community files

**Status:** DONE

**Goal:** the summary-style `README.md`, initial `RELEASENOTES.md`, finalized `<PackageReleaseNotes>`,
`SECURITY.md`, and `CLAUDE.md`.

**Steps**

1. `README.md` (root; packed into the nupkg):
   - Title `# Enigma.Core`.
   - Badges: NuGet version, Downloads, License (MIT → `LICENSE.md`).
   - One-paragraph intro (brand-new library; built on BouncyCastle). No Enigma.Cryptography mention.
   - `> **What's new in 1.0** — …` callout → `RELEASENOTES.md`.
   - **Features** — bulleted summary grouped by category (block ciphers, stream ciphers, public-key,
     PQC, X.509, hashing, HMAC, OTP, KDF, padding, encoding).
   - Async / progress / cancellation note.
   - Installation (`dotnet add package Enigma.Core`) + supported TFMs line
     (`netstandard2.0`, `net8.0`, `net10.0`; BouncyCastle 2.6.2).
   - **Documentation** section — **prose-only** mention: per-category guides & samples live under
     `docs/guides/` in the repository, indexed by `docs/guides/README.md`. **No clickable
     per-sample links, no absolute GitHub URLs, no nuget-breaking relative links.**
2. `RELEASENOTES.md` — `# Enigma.Core v1.0.0 Release Notes`: initial release; feature overview by
   category; Compatibility (targets `netstandard2.0`/`net8.0`/`net10.0`; BouncyCastle 2.6.2);
   Version (initial `1.0.0`). No migration guide (brand-new library).
3. `<PackageReleaseNotes>` in the csproj — short prose mirroring the RELEASENOTES top, ending with
   `See RELEASENOTES.md for the full details.`
4. `SECURITY.md` — supported versions + responsible disclosure via **GitHub private vulnerability
   reporting** (Security tab → Report a vulnerability); note the crypto-library sensitivity.
5. `CLAUDE.md` — repo guide adapted from Enigma.Cryptography's: architecture (service + factory + DI,
   BouncyCastle-backed, public surface free of BouncyCastle types), layout, target frameworks,
   build/test commands (`dotnet build`/`dotnet test`, MTP + xunit.v3), and the dev-workflow
   conventions. Describes Enigma.Core specifically.

**Acceptance criteria**

- `README.md`, `RELEASENOTES.md`, `SECURITY.md`, `CLAUDE.md` present and well-formed.
- README contains no absolute URLs and no nuget-breaking relative links; badges resolve.
- `<PackageReleaseNotes>` mirrors the RELEASENOTES top.
- csproj still packs clean (README now non-empty); Release build zero-warning; tests green.

---

## PHASE04 — Release runbook & final cut prep

**Status:** DONE

**Goal:** the committed release checklist and a verified, printed publish runbook.

**Steps**

1. Create `docs/RELEASE.md` from the house `dotnet-release` template (create only if missing),
   filling placeholders: `PackageId=Enigma.Core`, solution `Enigma.Core.slnx`, lib csproj
   `src/Enigma.Core/Enigma.Core.csproj`, lib dir `src/Enigma.Core`, default branch `main`,
   tag format bare `X.Y.Z`.
2. Release-config pre-flight: `dotnet build Enigma.Core.slnx -c Release` and
   `dotnet test Enigma.Core.slnx -c Release` — both clean.
3. Verify `dotnet pack src/Enigma.Core/Enigma.Core.csproj -c Release -o ./artifacts` produces
   `Enigma.Core.1.0.0.nupkg` with README.md + LICENSE.md embedded and correct metadata.
4. **Print (do not run)** the pack/tag/push runbook for the user:
   - `dotnet build`/`dotnet test -c Release`
   - merge release branch → `main`; `git switch main && git pull`
   - `git tag 1.0.0` / `git push origin 1.0.0`
   - `dotnet pack … -o ./artifacts`
   - `dotnet nuget push ./artifacts/Enigma.Core.1.0.0.nupkg --api-key <NUGET_API_KEY> --source https://api.nuget.org/v3/index.json`
   - post-publish verification (package page shows 1.0.0; badge resolves; `dotnet add package
     Enigma.Core --version 1.0.0` restores; tag exists).

**Acceptance criteria**

- `docs/RELEASE.md` complete and accurate for this repo.
- Release build + test green; pack verified to embed README+LICENSE.
- Runbook printed to the console (never executed); no API key stored/echoed.

---

## Out of scope / suggestions recorded (not planned here)

- **`AddEnigmaCore` DI-registration helper** (Microsoft.Extensions.DependencyInjection.Abstractions)
  — a natural fit for this DI-first factory library, but a functional feature, not release prep.
  Candidate future `FEATURE-*`, not release-blocking.
- SourceLink + symbol package (`snupkg`) + deterministic build — declined this release.
- `PackageIcon` / nuget.org logo — declined this release.
- GitHub Actions CI/publish workflow — declined this release.
- CONTRIBUTING.md / CHANGELOG.md — declined (RELEASENOTES.md is the single notes source).
- CRLF/line-endings — recommendation-only; `.gitattributes` present. Note any churn in the
  relevant completion doc; never a code change.
