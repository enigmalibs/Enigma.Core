# FEATURE-4442-PHASE06 — Certificates (X.509) (DONE)

## Summary
Sixth and **final** phase of the abstraction skeleton: scaffolded the **Certificates** module
(`Enigma.Core.Certificates`) — an X.509 certificate service covering **self-signed generation**,
**CSR / PKCS#10 generation**, **issuance** (signing a CSR with a CA), **chain validation**, and **CRL
(revocation) validation** — as a redesigned, BouncyCastle-free public contract with empty
(`throw new NotImplementedException()`) implementations. The BouncyCastle-coupled `CertificateInfo`
support type is **redesigned**: its `Org.BouncyCastle.Math.BigInteger SerialNumber` becomes
`System.Numerics.BigInteger`. All operations are in-memory (certificates/CSRs/CRLs are small structured
blobs), so the API is **sync** with **no `bufferSize`**, and all data crosses the boundary as PEM
`string`. Completing this phase flips the base **FEATURE-4442** item to `DONE`.

## Files/modules touched

### Created — `Enigma.Core.Certificates` (`src/Enigma.Core/Certificates/`)
- `CertificateInfo.cs` — **redesigned** `public sealed record` with `required` init-only properties:
  `Subject`, `Issuer`, `SerialNumber` (**`System.Numerics.BigInteger`**, replacing BouncyCastle's
  `BigInteger`), `NotBefore`, `NotAfter`, `SignatureAlgorithm` (read-back `string`), `Version` (`int`),
  `Thumbprint` (`string`). Referenced by `IX509CertificateService.GetCertificateInfo` (so it is in-scope
  for the skeleton, unlike the deferred support types).
- `IX509CertificateService.cs` — interface (6 members): `GenerateSelfSignedCertificate`,
  `GenerateCertificateSigningRequest`, `IssueCertificate`, `ValidateChain`, `IsRevoked`,
  `GetCertificateInfo`. All PEM `string` I/O; signing takes the root `RsaSignatureAlgorithm`
  (default `Sha256WithRsa`); validity via explicit `DateTimeOffset`; encrypted private-key PEMs via
  `char[]? password = null`.
- `X509CertificateService.cs` — sealed stub (all 6 methods throw).
- `IX509CertificateServiceFactory.cs` — interface: `CreateX509CertificateService()` (single, parameterless).
- `X509CertificateServiceFactory.cs` — sealed stub (method throws).

### Modified — workflow tracking
- `docs/roadmap.md` — PHASE06 `TODO` → `IN PROGRESS` → `DONE`; base **FEATURE-4442** `IN PROGRESS` →
  `DONE` (final phase completes the item).
- `docs/plan/FEATURE-4442.md` — PHASE06 status flips; item top-level status → `DONE`; recorded the full
  build-time signature design in the PHASE06 section (per principle 8), including the source-parity note.

## Design decisions (recorded per principle 8)
- **In-memory ⇒ sync + no `bufferSize`.** X.509 certificates, CSRs and CRLs are small structured blobs,
  not streams — so (like the KDF/OTP/Asymmetric phases) the API is sync and the factory carries no
  `bufferSize`. Principle 4's async-Stream split applies only where the source streamed, which X.509 does
  not.
- **All PEM `string` I/O** (satisfies the flag). No BouncyCastle `X509Certificate` /
  `Pkcs10CertificationRequest` / `X509Crl` type appears in any signature. DER `byte[]` overloads were
  **not** added (kept lean, as PHASE05 kept RSA to PEM `string`); flagged for PR.
- **Selecting vs reading back a signature algorithm.** Generation/issuance/CSR *select* the algorithm via
  the PHASE01 root `RsaSignatureAlgorithm` enum (default `Sha256WithRsa`) — exactly the consumer PHASE01
  fixed the shared vocabulary for. `CertificateInfo.SignatureAlgorithm` is a plain `string` because a
  parsed certificate may carry any algorithm (ECDSA, …), not only the four RSA variants — the exact
  read-back distinction PHASE01 anticipated ("`X509Utils` only ever reads back `SigAlgName`").
- **Deterministic validity via explicit `DateTimeOffset`** (not an ambient clock), mirroring PHASE04's
  TOTP decision — keeps the contract testable.
- **`char[]? password` for encrypted private-key PEMs**, reusing PHASE05's `PemPasswordFinder`-redesign
  convention (`null` = unencrypted).
- **Single parameterless factory method** `CreateX509CertificateService()` — X.509 is the only format;
  signature algorithm / validity / trust inputs are per-call parameters (as PHASE05's
  `CreatePublicKeyService()`). Named for the service type the plan mandates.
- **All members throw `NotImplementedException`** (including the factory `Create*`) — no concrete stub
  needs constructor parameters, avoiding unused-field errors under `TreatWarningsAsErrors`.
- **`CertificateInfo` as a `record` with `required` members.** `required` exempts the non-nullable
  properties from CS8618 (no constructor assigns them), and every property carries its own `<summary>`
  (CS1591). Both compile clean on `netstandard2.0` — PolySharp polyfills `IsExternalInit`,
  `RequiredMemberAttribute`, and `CompilerFeatureRequiredAttribute` (verified by the multi-TFM build).

## Deviations & follow-ups
- **Source-parity (no source library in the repo).** As in PHASE01–05, the original library isn't present,
  so signatures were designed at build time per principle 8. To verify against source at PR: (1) the exact
  `CertificateInfo` member set (whether `Version`/`Thumbprint` were present; whether `SignatureAlgorithm`
  was a `string` or an enum); (2) whether the source also took/returned DER `byte[]` overloads or exposed
  key-pair generation on this service (kept to PEM `string` per the mapping's scope); (3) exact method
  names/signatures for generation, issuance, chain and CRL validation (whether chain validation took
  explicit trusted-root/intermediate collections as here, and whether revocation was a separate `IsRevoked`
  vs folded into chain validation); (4) passphrase type (`char[]` vs `string`). All adjustable later without
  disturbing the skeleton (stubs throw).
- **Root `RsaSignatureAlgorithm` resolved without a `using`** — `Enigma.Core.Certificates` is nested within
  `Enigma.Core`, so the root enum resolves through the enclosing namespace (same as PHASE05's PublicKey).
  Confirmed by the clean build.
- **`IReadOnlyList<string>` for chain inputs** — first collection-typed parameter in the skeleton; fully
  BouncyCastle-free and available on all three TFMs.
- **Line endings (CRLF):** none observed — all new files are LF, consistent with the repo convention. No
  action taken (recommendation-only per `dev-workflow`).
- **No new unit tests** (acceptance criterion 5): stubs throw, nothing meaningful to assert; real tests
  arrive with the certificate implementation feature.

## Build/test evidence
- **Build:** `dotnet build Enigma.Core.slnx -warnaserror` → `Build succeeded. 0 Warning(s) 0 Error(s)`,
  producing `Enigma.Core.dll` for `netstandard2.0`, `net8.0`, and `net10.0` under `TreatWarningsAsErrors`
  + `GenerateDocumentationFile` (so all-public-members XML docs, CS1591, are enforced as errors).
- **Test:** `dotnet test --solution Enigma.Core.slnx` (MTP) → `Passed! total: 1, failed: 0, succeeded: 1,
  skipped: 0`. Definition-of-Done criterion 2 satisfied by the existing smoke test staying green (no new
  tests this phase, per acceptance criterion 5).
- **No BouncyCastle exposure:** `grep -rniE "bouncy|org\.bouncycastle|ICipherParameters|IPasswordFinder|
  IDigest|SecureRandom|AsymmetricKeyParameter|Pkcs10CertificationRequest|X509Crl"` over
  `src/Enigma.Core/Certificates` matches only the doc sentence stating no BouncyCastle types are exposed;
  `BouncyCastle.Cryptography` remains unreferenced by the project, so the clean build proves zero coupling.

## Acceptance criteria (per-phase list) — all met
1. ✅ Build clean (zero warnings) across `netstandard2.0`, `net8.0`, `net10.0` under `TreatWarningsAsErrors`.
2. ✅ No BouncyCastle types in any public signature, base type, or support-type member.
3. ✅ Every service/factory is a `sealed` class implementing its interface with `throw new
   NotImplementedException()` bodies (2 stub classes, 7 members).
4. ✅ XML docs on all public types/members (enforced by CS1591-as-error).
5. ✅ No new unit tests; existing smoke test passes green.
6. ✅ Roadmap + plan PHASE06 status updated (and base FEATURE-4442 → DONE); this completion doc written.
