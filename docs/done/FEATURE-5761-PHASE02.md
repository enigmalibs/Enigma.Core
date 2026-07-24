# FEATURE-5761 PHASE02 — Provisioning (un-defer as DI service)

- **Status:** DONE (final phase — FEATURE-5761 now complete)
- **Type:** FEATURE phase (2 of 2)
- **Branch:** `feature/feature-5761-phase02-otp` (cut from `feature/feature-5761-phase01-otp` @ `456e9e8`)
- **Scope:** `Otp` module
  (`OtpProvisioning`, `OtpAuthParameters`).

## Summary
Un-deferred the TOTP provisioning surface that FEATURE-4442 left out of the frozen skeleton, delivering it
as an injectable DI service rather than the old `static class OtpProvisioning`. Ported the otpauth
Key-URI-Format logic (secret generation, `BuildUri`, `ParseUri`) at maximum fidelity over Core's Base32
encoder (FEATURE-0399) and `Utils/RandomUtils` (FEATURE-61D1). BouncyCastle (`SecureRandom`, reached only
through `RandomUtils.GenerateRandomBytes`) stays strictly internal — no BC type on the public surface.

**Key adaptation — static helper → DI service.** The old library exposed static
`OtpProvisioning.{GenerateSecret,BuildUri,ParseUri}` with a private `new Base32Service()`. Per the settled
redesign this becomes `IOtpProvisioningService` + `OtpProvisioningService` + a factory, consuming Base32
through `IEncodingServiceFactory.CreateBase32Service()` (created once at construction; the service is
stateless and reusable), consistent with the rest of Core's factory/DI shape.

**Signature reshape — `BuildUri(OtpAuthParameters)`.** The old `BuildUri(issuer, accountName, secret,
digits, periodSeconds, algorithm)` with per-parameter defaults collapses into the single frozen
`BuildUri(OtpAuthParameters parameters)`. The validation the old method performed (null secret, blank
account name, digits 4-9, positive period) moves into `BuildUri` operating on the DTO's fields, plus a
null-`parameters` guard. `OtpAuthParameters` itself is ported verbatim (sealed class, positional ctor,
get-only props, nullable `Issuer`) — no validation in the DTO, preserving the round-trip test.

### Members implemented
- **`OtpAuthParameters`** — sealed result DTO `(string? Issuer, string AccountName, byte[] Secret, int
  Digits, int PeriodSeconds, OtpHashAlgorithm Algorithm)`, verbatim port.
- **`IOtpProvisioningService` / `OtpProvisioningService`** —
  - `string BuildUri(OtpAuthParameters parameters)` — unpadded Base32 secret, URI-escaped label/issuer,
    canonical `secret/issuer/algorithm/digits/period` ordering; full parameter validation.
  - `OtpAuthParameters ParseUri(string uri)` — scheme/type checks, issuer precedence (query param over
    label prefix), default fallbacks (SHA1/6/30), tolerant Base32 decode, `FormatException` on malformed
    input.
  - `byte[] GenerateSecret(int sizeBytes = 20)` — 16-byte minimum enforced, backed by
    `RandomUtils.GenerateRandomBytes`.
  - Internal ctor `(IEncodingServiceFactory)` — only the factory constructs; throws `ArgumentNullException`
    on a null factory.
- **`IOtpProvisioningServiceFactory` / `OtpProvisioningServiceFactory`** — `CreateOtpProvisioningService()`;
  public ctor injects `IEncodingServiceFactory`, throws `ArgumentNullException` on null.

## Files / modules touched

### Created — library (`src/Enigma.Core/Otp/`)
- `OtpAuthParameters.cs` — sealed DTO (verbatim port; doc-refs retargeted to `IOtpProvisioningService`).
- `IOtpProvisioningService.cs` — service contract with XML docs.
- `OtpProvisioningService.cs` — implementation; internal `(IEncodingServiceFactory)` ctor; Base32 created
  once; `BuildUri`/`ParseUri`/`GenerateSecret`; private `ParseQuery`/`SplitLabel`/`ParseIntParam`/
  `AlgorithmToString`/`AlgorithmFromString` helpers.
- `IOtpProvisioningServiceFactory.cs` — factory contract.
- `OtpProvisioningServiceFactory.cs` — implementation; injects `IEncodingServiceFactory`.

### Created — tests (`tests/Enigma.Core.UnitTests/Otp/`)
- `OtpProvisioningTests.cs` — 20 test methods / 24 cases, all driving the service through the factory:
  known-answer `BuildUri` vector, label/issuer escaping, no-issuer omission, build→parse round-trip,
  minimal-URI defaults, issuer precedence (query vs label), invalid/format throws (Theory ×4), non-numeric
  digits, null URI, `GenerateSecret` default/custom size + 16-byte minimum, null-parameters / null-secret /
  blank-account guards, invalid-digits (Theory ×2) / non-positive-period guards, null-encoding-factory
  guard, and the **Base32 seam test** pinning `12345678901234567890` →
  `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ` (canonical encode, case-tolerant decode).

The reflection BC-leak guard (`OtpBouncyCastleIsolationTests`) already scans the entire `Enigma.Core.Otp`
namespace, so the new public provisioning types are covered automatically — no test change needed.

## Deviations & follow-ups
- **`BuildUri` validation relocated into the method (design, not defect).** Because the six loose
  parameters became one `OtpAuthParameters` argument, the guards now validate the DTO's fields; the
  null-secret guard throws `ArgumentNullException` (paramName `parameters`) and blank-account throws
  `ArgumentException`, preserving the old tests' exception types. A new null-`parameters` guard was added.
- **Validation coverage extended.** Added `BuildUri` invalid-digits / non-positive-period throw tests
  (the old suite only exercised these paths implicitly through defaults); they cover the restored
  validation now living in `BuildUri`.
- **Un-deferred types introduced complete (no stub-first history).** The plan asks each amendment to land
  first as a throwing stub. These types were *deferred* (never stubbed) by the skeleton, and under this
  workflow the dev is a single user-owned commit, so interface-then-implementation collapses into one
  commit — same handling recorded for PHASE01. Signatures and behaviour are correct and tested.
- **`GenerateSecret` parameter renamed** `size` → `sizeBytes` per the frozen contract; behaviour
  (default 20, 16-byte minimum) unchanged.
- **`record` modernization of `OtpAuthParameters`** left open for PR per the plan; kept as the ported
  sealed class to preserve property names and the round-trip test.
- **Line endings:** no CRLF/line-ending anomalies observed in the touched files; no action taken
  (recommendation-only per workflow).

## Build / test evidence
- **Build:** `dotnet build -c Release` → **Build succeeded, 0 Warning(s), 0 Error(s)** across all three
  library TFMs (`netstandard2.0;net8.0;net10.0`) under `TreatWarningsAsErrors` +
  `GenerateDocumentationFile`. All provisioning code is netstandard2.0-safe (`Uri.EscapeDataString`/
  `UnescapeDataString`, `int.TryParse` with `CultureInfo.InvariantCulture`, `StringBuilder`,
  `string.Split`).
- **Tests:** `dotnet test -c Release` → **834 passed, 0 failed, 0 skipped** across both test TFMs
  (`net8.0`, `net10.0`); +48 over the prior 786 (24 new provisioning/seam cases × 2 TFMs), which exactly
  accounts for the delta and confirms the new file executed. (Note: the Microsoft.Testing.Platform
  treenode `--filter` form has shifted since PHASE01 and no longer isolates by class name here; the
  full-suite delta is the load-bearing evidence.)
- **Acceptance criteria (PHASE02):** all met — `BuildUri` produces the exact known-answer otpauth URI;
  `ParseUri` round-trips it (including 8-digit/60s/SHA256 and issuer precedence); `GenerateSecret` honors
  size and enforces the 16-byte minimum; all format/null/blank/range guards throw; no BC type on any
  public `Enigma.Core.Otp` signature (namespace-scoped + assembly-wide reflection guards green);
  zero-warning build + green suite on all three TFMs. FEATURE-5761 is complete.
