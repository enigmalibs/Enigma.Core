# CLAUDE.md

Guidance for Claude Code (and other AI agents) working in this repository.

## What this is

**Enigma.Core** is a modern .NET cryptography library built on [BouncyCastle](https://www.bouncycastle.org/).
It provides block & stream ciphers, RSA, post-quantum cryptography (ML-DSA / ML-KEM), X.509
certificates, hashing, HMAC, one-time passwords, key derivation, padding, and data encoding — all
behind a small, consistent, dependency-injection-friendly public surface.

## Architecture

The whole library follows one pattern: **service + factory + DI**.

- A **service** (`IHashService`, `IBlockCipherService`, `IRsaService`, …) performs one kind of
  cryptographic operation.
- A **factory** (`IHashServiceFactory`, `IBlockCipherServiceFactory`, …) creates configured service
  instances — the factory selects the algorithm/mode; the service does the work.
- Factories are plain classes: construct them with `new HashServiceFactory()`. Their `I…Factory`
  interfaces are designed to register cleanly in any `Microsoft.Extensions.DependencyInjection`
  container. Most factories are parameterless; a few compose others via constructor injection
  (`HotpServiceFactory(IHmacServiceFactory)`, `TotpServiceFactory(IHotpServiceFactory)`,
  `OtpProvisioningServiceFactory(IEncodingServiceFactory)`).
- There is deliberately **no** `AddEnigmaCore` DI-registration helper.

**Load-bearing invariant — BouncyCastle never leaks onto the public surface.** BouncyCastle backs
every implementation, but no `Org.BouncyCastle.*` type may appear on any exported type or member.
This is enforced by a reflection guard test,
`tests/Enigma.Core.UnitTests/Api/BouncyCastleIsolationTests.cs`, which walks every exported type and
fails the build if a BouncyCastle type is exposed. Keep this test green.

**Async / progress / cancellation.** Streaming operations (block & stream ciphers, hashing, HMAC)
expose `async` APIs that take an optional `IProgress<int>` (bytes processed) and a
`CancellationToken`.

## Project layout

```
Enigma.Core.slnx                     Solution (SLNX format)
Directory.Build.props                Shared build defaults (Authors, Copyright, LangVersion 14, Nullable, TreatWarningsAsErrors)
Directory.Packages.props             Central Package Management (all package versions pinned here)
.editorconfig                        Code style + analyzer severities
global.json                          SDK 10.0.100 (latestFeature); test runner = Microsoft.Testing.Platform
src/Enigma.Core/                     The library
  Symmetric/BlockCiphers/            AES, DES, 3DES, Blowfish, Twofish, Serpent, Camellia, CAST5, IDEA, SEED, ARIA, SM4
  Symmetric/StreamCiphers/           ChaCha20, ChaCha20-RFC7539, Salsa20
  Padding/                           None, PKCS#7, ISO 7816-4, ISO 10126-2, ANSI X9.23
  Hashing/Hash/                      MD5, SHA-1, SHA-256, SHA-512, SHA-3
  Hashing/Hmac/                      HMAC-SHA1/256/512
  KeyDerivation/                     PBKDF2, Argon2
  Encoding/                          Base64, Base32, Hex
  Otp/                               HOTP, TOTP, otpauth:// provisioning
  Asymmetric/PublicKey/              RSA (encryption, signing, PEM)
  Asymmetric/Pqc/                    ML-KEM, ML-DSA (+ PEM serialization per family)
  Certificates/                      X.509 generation, CSR, issuance, chain validation, CRL, PKCS#12/DER, info
  Extensions/                        EncodingExtensions, StreamExtensions (typed sync/async stream I/O)
  Internal/                          Cross-category internals (PemEnvelope: the one PEM/PBES2 implementation)
  Utils/                             RandomUtils, CryptoDefaults
tests/Enigma.Core.UnitTests/         xUnit v3 test suite (mirrors the src category layout)
  Api/                               Public-surface guard tests (incl. BouncyCastleIsolationTests)
  Infrastructure/                    Shared test helpers
docs/                                Guides, samples, and the dev-workflow tracking artifacts
```

## Target frameworks & dependencies

- Multi-targets **`netstandard2.0;net8.0;net10.0`**.
- Runtime dependency: **BouncyCastle.Cryptography 2.7.0** (all TFMs).
- `System.Buffers` (Span/Memory support) and **PolySharp** (compile-only C# polyfills,
  `PrivateAssets=all`) are referenced on **netstandard2.0 only**; both are framework-provided or
  unnecessary on net8.0+.
- All versions are managed centrally in `Directory.Packages.props` (do not put `Version=` on
  `<PackageReference>` items).

## Build & test

Zero-warning builds are enforced (`TreatWarningsAsErrors=true`, `EnforceCodeStyleInBuild=true`), so
warnings fail the build.

```bash
# Build the whole solution (Release)
dotnet build Enigma.Core.slnx -c Release

# Run the full test suite (Microsoft.Testing.Platform runner, per global.json)
dotnet test --solution Enigma.Core.slnx -c Release

# Produce the NuGet package
dotnet pack src/Enigma.Core/Enigma.Core.csproj -c Release -o ./artifacts
```

Tests are **MTP-native**: `xunit.v3` + `coverlet.collector`, with **no** `Microsoft.NET.Test.Sdk`.

## Conventions

- **Language/style.** C# 14, `Nullable=enable`, `ImplicitUsings=disable` (declare `using`s
  explicitly). Follow `.editorconfig`; do not introduce warnings.
- **Public surface.** Never expose a BouncyCastle type publicly (see the isolation test above).
  Prefer the enum/service abstractions already in place over leaking primitive/library types.
- **Documentation.** Public APIs carry XML doc comments (`GenerateDocumentationFile=true`).
  Per-category usage guides live under `docs/guides/` (indexed by `docs/guides/README.md`).

## Dev workflow (tracked work)

This repo plans and tracks work through a house workflow:

- `docs/roadmap.md` — the single registry of every work item (`FEATURE-HHHH`, `BUG-HHHH`,
  `CODE-REVIEW-HHHH`; large items are split into `-PHASENN` phases).
- `docs/plan/<ID>.md` — the full plan for each item (the contract a build implements).
- `docs/done/<ID>.md` — a completion record per finished item/phase.

Each unit of work gets its own branch (`feature/…`, `bugfix/…`, `review/…`), cut from the current
`HEAD`. A unit is **done** only when the build is warning-free, the whole test suite passes, the
plan's acceptance criteria are met, the roadmap/plan statuses are updated, and the completion doc is
written. Commits are left to the maintainer.
