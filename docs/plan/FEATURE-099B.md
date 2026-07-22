# FEATURE-099B — Certificates implementation (X.509)

- **Status:** IN PROGRESS (PHASE01 DONE; PHASE02 DONE; PHASE03 next)
- **Type:** FEATURE (multi-phase — 3 phases)
- **Depends on:** FEATURE-2E3E (publickey — RSA keygen + PEM); transitively FEATURE-61D1
- **Suggested branch (at build):** `feature/feature-099b-phaseNN-certificates-x509` (one branch per phase)
- **Basis:** ported from Enigma.Cryptography v5.0.0 (`/home/jo/Dev/Enigma.Cryptography`); redesign decisions validated by user 2026-07-21.

## Objective
Implement the X.509 certificate service behind the BouncyCastle-free contract in `Enigma.Core.Certificates`, porting behaviour and tests from Enigma.Cryptography v5.0.0 at **maximum fidelity**: self-signed generation, CSR (PKCS#10) generation, issuance from a CSR, chain validation against trusted roots, CRL-based revocation checking, certificate parsing into `CertificateInfo`, **plus the capabilities the FEATURE-4442 skeleton dropped that the user validated for restoration** — X.509 extension controls (CA / KeyUsage / SAN) on generation and issuance and read-back on `CertificateInfo`, PFX / PKCS#12 import & export, CSR signature verification, and DER load/save. All certificate/CSR/CRL/key I/O crosses the API as PEM strings (PKCS#12 and DER as `byte[]`, the one documented binary exception), with explicit `DateTimeOffset` validity and the `RsaSignatureAlgorithm` enum. Every BouncyCastle type stays internal (principle 1).

## Basis — port from Enigma.Cryptography v5.0.0
Exact old source files (from the spec `oldToNewMapping`):
- `src/Enigma.Cryptography/X509/IX509CertificateService.cs`
- `src/Enigma.Cryptography/X509/X509CertificateService.cs`
- `src/Enigma.Cryptography/X509/IX509CertificateServiceFactory.cs`
- `src/Enigma.Cryptography/X509/X509CertificateServiceFactory.cs`
- `src/Enigma.Cryptography/X509/CertificateInfo.cs`
- `src/Enigma.Cryptography/Utils/X509Utils.cs` (un-defer → internal)
- `src/Enigma.Cryptography/Utils/PemUtils.cs` (un-defer → internal, shared with publickey)
- `src/Enigma.Cryptography/Utils/RandomUtils.cs` (optional internal RNG, or `SecureRandom` directly as the old service does)
- `src/Enigma.Cryptography/SignatureAlgorithms.cs` (JCA-name mapping → internal)
- Tests: `src/UnitTests/X509/{SelfSignedCertificate,Csr,IssueCertificate,ChainValidation,CertificateInfo,CertificateFormat,Pfx}Tests.cs`

## Scope & mapping
| Old | New home | Note |
|-----|----------|------|
| `X509/IX509CertificateService.cs` | `Certificates/IX509CertificateService.cs` | FROZEN six members implemented as-is + **AMENDED** (extension options param, `IsCertificateSigningRequestValid`, `ExportPkcs12`/`ImportPkcs12`, DER overloads) |
| `X509/X509CertificateService.cs` | `Certificates/X509CertificateService.cs` | Implement all members behind PEM contract; BC generator/PKIX/PKCS#12 logic ported verbatim, internal; random 128-bit serial via `BigIntegers.CreateRandomBigInteger` |
| `X509/IX509CertificateServiceFactory.cs` + impl | `Certificates/IX509CertificateServiceFactory.cs` + impl | FROZEN parameterless `CreateX509CertificateService()` implemented as-is |
| `X509/CertificateInfo.cs` | `Certificates/CertificateInfo.cs` | FROZEN record + **AMENDED** (re-add `IsCertificateAuthority`, `KeyUsage`, `SubjectAlternativeNames`); `IsValidNow` stays DROPPED |
| `Utils/X509Utils.cs` | **un-defer → INTERNAL** under Certificates | Cert load/parse/info-extraction + DER + PFX helpers; old public static surface DROPPED |
| `Utils/PemUtils.cs` | **un-defer → INTERNAL** (shared with publickey) | PEM read/write + `char[]` password (`PemPasswordFinder`-equivalent adapter); old Stream API DROPPED |
| `Utils/RandomUtils.cs` | **INTERNAL if needed** | serial RNG, or `SecureRandom` directly |
| `SignatureAlgorithms.cs` | **INTERNAL** JCA mapping | superseded by root `RsaSignatureAlgorithm` (PHASE01); must emit identical JCA strings (`SHA256withRSA`, …) the old `Asn1SignatureFactory` consumed |
| `UnitTests/X509/*.cs` (7 files) | `tests/Enigma.Core.UnitTests/Certificates/*` | Rewrite to PEM-string API + `GetCertificateInfo` assertions |

## Contract amendments to the frozen skeleton (FEATURE-4442)
**Approved by user 2026-07-21.** Every amendment below is added FIRST as a throwing stub (`throw new NotImplementedException()` / new type with documented members) so the solution stays green, then implemented in its phase. Each keeps **principle 1** — no `Org.BouncyCastle.*` type appears in any signature, return, base type, or public support member; the extension controls are expressed by two new BC-free types.

| Member | Signature (BC-free) | Restores (old member / test) | Notes |
|--------|---------------------|------------------------------|-------|
| `X509KeyUsage` (new `[Flags]` enum) | `DigitalSignature, NonRepudiation, KeyEncipherment, DataEncipherment, KeyAgreement, KeyCertSign, CrlSign, EncipherOnly, DecipherOnly` | old `int? keyUsage` bitmask → `KeyUsage` extension | BC-free flags; internally maps to `Org.BouncyCastle.Asn1.X509.KeyUsage` bits |
| `X509CertificateOptions` (new sealed record) | `{ bool? IsCertificateAuthority; X509KeyUsage? KeyUsage; IReadOnlyList<string>? SubjectAlternativeNames }` | old `bool? basicConstraintsCa`, `int? keyUsage`, `GeneralNames? subjectAlternativeNames` | maps to `BasicConstraints` / `KeyUsage` / `SubjectAlternativeName` extensions internally |
| `GenerateSelfSignedCertificate` (amend) | add trailing `X509CertificateOptions? options = null` | old extension params on generation | required so a self-signed root can be marked `cA=true` for PKIX (Phase 2) |
| `IssueCertificate` (amend) | add trailing `X509CertificateOptions? options = null` | old extension params on issuance | required to build CA-capable intermediates for the 3-level chain |
| `CertificateInfo` (amend) | add `IsCertificateAuthority` (`bool`, required init), `KeyUsage` (`X509KeyUsage?` init, `null` when absent), `SubjectAlternativeNames` (`IReadOnlyList<string>` init, empty when none) | old `bool IsCa`, `bool[]? KeyUsage`, `IReadOnlyList<string> SubjectAlternativeNames`; `CertificateInfoTests` CA/KeyUsage/SAN + malformed-SAN guard | `bool IsValidNow` stays DROPPED (ambient clock; determinism) |
| `IsCertificateSigningRequestValid` (new) | `bool IsCertificateSigningRequestValid(string csrPem)` | old `bool VerifyCsr(Pkcs10CertificationRequest)`; `CsrTests.GenerateCsr_SignatureIsValid` | CSR also verified internally inside `IssueCertificate` (throws on invalid) |
| `ExportPkcs12` (new) | `byte[] ExportPkcs12(string certificatePem, string privateKeyPem, char[] password, IReadOnlyList<string>? chainPems = null)` | old `ExportToPfx`; `PfxTests` | PKCS#12 is binary → `byte[]` is the documented exception to all-PEM |
| `ImportPkcs12` (new) | `(string certificatePem, string privateKeyPem) ImportPkcs12(byte[] pkcs12, char[] password)` | old `LoadFromPfx`; `PfxTests` | tuple of PEM strings; wrong password → `CryptographicException` |
| `ExportCertificateToDer` (new) | `byte[] ExportCertificateToDer(string certificatePem)` | old `X509Utils.SaveCertificate`; `CertificateFormatTests` DER round-trip | binary `byte[]` exception |
| `ImportCertificateFromDer` (new) | `string ImportCertificateFromDer(byte[] derEncodedCertificate)` | old `X509Utils.LoadCertificate(byte[])`; `CertificateFormatTests` PEM/DER equivalence | returns PEM |

## BouncyCastle usage (internal only)
Confined to internal helpers (`PemUtils`, `X509Utils`, the service impl); no BC package reference is added by this feature — `BouncyCastle.Cryptography` + `System.Buffers` are referenced by `Enigma.Core` from the **foundation** feature (per settled orchestrator choice). BC auth/parse/validation failures (e.g. `InvalidCipherTextException`, PEM/DER parse errors, `Pkcs12` password failures) are wrapped in `System.Security.Cryptography.CryptographicException` (or `ArgumentException` for malformed input) at the service boundary — no BC exception escapes.

Types used behind the contract: `X509V3CertificateGenerator`, `Asn1SignatureFactory`, `Pkcs10CertificationRequest`, `X509Certificate` / `X509CertificateParser`, `X509Crl` / `X509CrlParser`, `PkixCertPathValidator`, `PkixParameters`, `PkixCertPath`, `TrustAnchor`, `CollectionUtilities`, `X509Name`, `GeneralNames` / `GeneralName`, `KeyUsage`, `BasicConstraints`, `X509Extensions`, `X509ExtensionUtilities`, `SecureRandom`, `BigIntegers`, `Org.BouncyCastle.Math.BigInteger`, `AsymmetricKeyParameter` / `AsymmetricCipherKeyPair`, `PemReader` / `PemWriter` / `IPasswordFinder`, `Pkcs12StoreBuilder` / `X509CertificateEntry` / `AsymmetricKeyEntry` (PFX), `CertificateExpiredException` / `CertificateNotYetValidException`. `X509V2CrlGenerator` is used **only test-side** (CRL fixtures), not in product code.

## Redesign decisions
### Already frozen (FEATURE-4442 PHASE06)
- No BouncyCastle types in any signature — certs/CSRs/CRLs/keys cross as PEM strings.
- `CertificateInfo` sealed record; `System.Numerics.BigInteger` serial (was `Org.BouncyCastle.Math.BigInteger`); `NotBefore`/`NotAfter` `DateTimeOffset` (was `DateTime`); `Thumbprint` added; read-back `SignatureAlgorithm` string.
- Explicit `DateTimeOffset notBefore`/`notAfter` validity (no ambient clock).
- `RsaSignatureAlgorithm` chosen per call (default `Sha256WithRsa`); JCA mapping internal.
- Parameterless factory `CreateX509CertificateService()`.
- Revocation as a distinct `IsRevoked(cert, crl, issuer)`; `ValidateChain` takes explicit `trustedRootPems` + optional `intermediatePems` (old single auto-classified collection replaced) — preserve old empty-anchor→`false` and `PkixCertPathValidatorException`→`false` semantics.
- Encrypted private-key PEMs unlocked with `char[]? password`.
- `GetCertificateInfo` is a service member (was static `X509Utils.GetCertificateInfo`).
- `DateTimeOffset` → BC `DateTime` conversion via `.UtcDateTime` at the generator boundary.

### Restored per user validation (2026-07-21)
- **Extension controls (`X509CertificateOptions` + `X509KeyUsage`)** — restores CA / KeyUsage / SAN on generation and issuance; **functionally required** because PKIX (`PkixCertPathValidator`) demands `BasicConstraints cA=true` on CA certs, without which the multi-level chain tests cannot produce a validatable hierarchy. Kept BC-free via the two new types.
- **`CertificateInfo` read-back of `IsCertificateAuthority` / `KeyUsage` / `SubjectAlternativeNames`** — it is inconsistent to set extensions but not read them; restores the ~10 `CertificateInfoTests` assertions and the malformed-SAN regression guard (re-targeted at the internal extractor's narrowed catch).
- **PFX / PKCS#12** (`ExportPkcs12` / `ImportPkcs12`) — restores the dropped `ExportToPfx`/`LoadFromPfx`; `byte[]` is the documented binary exception to the all-PEM rule. Ports `PfxTests` (round-trip, extracted-key-can-sign, with-chain, wrong-password-throws, empty-password).
- **CSR verification** (`IsCertificateSigningRequestValid`) — restores old `VerifyCsr`; issuance also verifies internally and throws on a tampered CSR.
- **CSR/issuance/self-signed against ambient clock** — kept deterministic (`IsValidNow` stays dropped).
- **DER load/save** (`ExportCertificateToDer` / `ImportCertificateFromDer`) — restores old `X509Utils` DER byte round-trip and PEM/DER-equivalence coverage.
- **Thumbprint = uppercase-hex SHA-256 of the DER-encoded certificate** (settled) — documented + covered by an independent KAT.
- **CRL generation stays out of the product API** (settled) — revocation is tested with a **test-side BouncyCastle CRL helper** (`X509V2CrlGenerator` + `Asn1SignatureFactory`), matching the old approach; product surface stays lean.

### Open for PR
- `IsCertificateSigningRequestValid` and the DER overloads (`ExportCertificateToDer` / `ImportCertificateFromDer`) come from the `cert_extra_parity_implied` decision, which flags them for PR confirmation. **Recommended default: keep them implemented and tested** (they restore real old capability at negligible cost); a reviewer may drop either if judged out of v6 scope, in which case delete the corresponding stub + tests in the same reviewed change.

## Test plan
No RFC/NIST/FIPS KAT vectors or CSV resources exist for X.509 — all old tests are self-generated round-trip/interop tests. Port every old file to `tests/Enigma.Core.UnitTests/Certificates/` against the PEM API, replacing BouncyCastle-object assertions with `GetCertificateInfo(pem)` assertions.
- **Keys**: obtained from the publickey feature's new `GenerateRsaKeyPair(int keySizeBits = 2048)` (PEM) — the dependency that replaces old `IPublicKeyService.GenerateKeyPair(2048)`; static RSA PEM fixtures (analogous to `PublicKey/pk_key1.pem`) as fallback. Rebuild `CryptoKeyPairFixture` BC-free (keys/certs as PEM/byte[]).
- **SelfSignedCertificateTests**: `GetCertificateInfo` reports `Subject==Issuer`, requested DN, `Version==3`, RSA `SignatureAlgorithm`, positive `System.Numerics.BigInteger` serial, matching `DateTimeOffset` validity; self-signed CA root validates via `ValidateChain(selfSignedPem, [selfSignedPem])`.
- **CsrTests**: `GenerateCertificateSigningRequest` round-trips to a CSR that `IssueCertificate` accepts; `IsCertificateSigningRequestValid` true for a well-formed CSR, false/throws for a tampered CSR PEM (restores `VerifyCsr`).
- **IssueCertificateTests**: issued leaf `Issuer==CA subject`, `Subject==CSR subject`; validates via `ValidateChain(leaf, [issuerSelfSigned])`; 3-level hierarchy built with CA `X509CertificateOptions` (`IsCertificateAuthority=true`, `KeyUsage=KeyCertSign|CrlSign`).
- **ChainValidationTests**: split old single trusted collection into `trustedRootPems` + `intermediatePems`; port FullChain succeeds, LeafAgainstRootOnly (missing intermediate) fails, UntrustedRoot fails, ExpiredLeaf fails, NotYetValidLeaf fails, EmptyTrustAnchors fails.
- **Revocation**: port `RevokedLeaf_WithCrl` / `UnrevokedLeaf_WithCrl` to `IsRevoked(leafPem, crlPem, issuerPem)`; `crlPem` from the **test-side BouncyCastle CRL helper** (BC referenced in the test project only); `RevokedLeaf_NoCrlSupplied_Succeeds` becomes "`ValidateChain` performs no revocation check; `IsRevoked` is the explicit check".
- **CertificateInfoTests**: port all field assertions including restored `IsCertificateAuthority` (true/false), `KeyUsage` (set / `null` when absent), `SubjectAlternativeNames` (populated / empty / malformed→empty guard against the internal extractor).
- **CertificateFormatTests**: PEM round-trip + invalid-PEM-throws; **plus** DER round-trip and PEM/DER-equivalence against `ExportCertificateToDer` / `ImportCertificateFromDer`.
- **PfxTests**: port round-trip, extracted-key-can-sign, with-chain, wrong-password-throws (asserts `CryptographicException`), empty-password against `ExportPkcs12` / `ImportPkcs12`.
- **New tests warranted by the redesign**:
  - **Reflection test** proving no `Org.BouncyCastle.*` type is reachable from any public member/parameter/return/base type in `Enigma.Core.Certificates` (proves principle 1).
  - Encrypted-private-key-PEM coverage exercising `char[]? password` on generation/CSR/issuance (unencrypted-null / correct-password / wrong-password-throws).
  - `System.Numerics.BigInteger` serial round-trip.
  - **Thumbprint KAT** vs an independently computed uppercase-hex SHA-256 of the DER cert.
  - `DateTimeOffset` validity boundary assertions.
  - BC-exception-wrapping test: malformed PEM / wrong PFX password surface `CryptographicException`/`ArgumentException`, never a BC type.
- Rebuild `ArgumentValidationTests` per-feature BC-free; add `coverlet.collector` for coverage (matches old suite). No vectors to regenerate for this feature (self-generated only).

## Dependencies
- **FEATURE-2E3E (publickey)** must land first: (1) `IPublicKeyService.GenerateRsaKeyPair(int keySizeBits = 2048, char[]? password = null)` returning `(string publicKeyPem, string privateKeyPem)` — the only in-library way to obtain the `privateKeyPem` every cert operation and every ported test needs; (2) the internal `PemUtils` (PEM read/write + `char[]` password / `PemPasswordFinder` replacement) is first built and shared there; (3) the `RsaSignatureAlgorithm` → JCA-name mapping is shared internal logic (reuse to avoid casing drift).
- **FEATURE-61D1 (foundation)** must land first: adds the `BouncyCastle.Cryptography` + `System.Buffers` package references to `Enigma.Core`, and provides the ported test harness (`CsvData`, `SyncProgress<T>`, `EncodingExtensions`) and `coverlet.collector`.

## Phases
### Phase 1 — Generation, CSR & issuance (+ restored extension controls & CSR verification)
**Status: DONE** (see `docs/done/FEATURE-099B-PHASE01.md`). Read-back decision: `GetCertificateInfo`'s
core fields were implemented in this phase (user-approved 2026-07-22) so generation could be asserted through
the public PEM API; the restored `CertificateInfo` extension fields, PFX and DER remain in Phase 3.

Un-defer `Utils/PemUtils` + `Utils/X509Utils` as internal helpers. Add the amendments as throwing stubs first: `X509KeyUsage` enum, `X509CertificateOptions` record, the trailing `options` param on `GenerateSelfSignedCertificate` / `IssueCertificate`, and `IsCertificateSigningRequestValid`. Then implement `GenerateSelfSignedCertificate`, `GenerateCertificateSigningRequest`, `IssueCertificate` and the parameterless factory, with the internal `RsaSignatureAlgorithm`→JCA mapping, `char[]?` password PEM decryption, extension emission (CA `BasicConstraints` / `KeyUsage` / SAN), and internal CSR verification. This phase gates CA-capable certs needed by Phase 2. Port `SelfSignedCertificateTests`, `CsrTests`, `IssueCertificateTests`, the no-BouncyCastle-leak reflection test, and encrypted-PEM tests.
Acceptance: self-signed/CSR/issuance behaviours pass; CA extensions produce validatable anchors; `IsCertificateSigningRequestValid` true/false correct; reflection test green.

### Phase 2 — Chain validation & CRL revocation
**Status: DONE** (see `docs/done/FEATURE-099B-PHASE02.md`). `ValidateChain` uses a PKIX **path builder**
(not a validator) so intermediate ordering is irrelevant — corrected after an adversarial review found the
validator-based version rejected valid multi-intermediate chains supplied out of leaf→root order.

Implement `ValidateChain` (PKIX path validation over `trustedRootPems` + `intermediatePems`; empty-anchor and `PkixCertPathValidatorException` → `false`) and `IsRevoked` (CRL parse + issuer-signature verification + revoked-serial lookup). Requires Phase 1's CA-capable generation to build the hierarchy. Port `ChainValidationTests` with split trust inputs; obtain signed CRL PEMs from the test-side BouncyCastle CRL helper.
Acceptance: 3-level chain validates; missing-intermediate / untrusted-root / expired / not-yet-valid / empty-anchor all `false`; `IsRevoked` true for a revoked leaf and false for an unrevoked leaf; `ValidateChain` performs no revocation on its own.

### Phase 3 — CertificateInfo parsing, PFX & DER (restored)
Add remaining amendments as throwing stubs first: `CertificateInfo`'s `IsCertificateAuthority` / `KeyUsage` / `SubjectAlternativeNames`, `ExportPkcs12` / `ImportPkcs12`, `ExportCertificateToDer` / `ImportCertificateFromDer`. Implement `GetCertificateInfo` (`System.Numerics.BigInteger` serial, `DateTimeOffset` dates, uppercase-hex SHA-256 `Thumbprint`, read-back `SignatureAlgorithm`, restored CA/KeyUsage/SAN read-back), PFX round-trip, and DER load/save. Port `CertificateInfoTests`, the full `CertificateFormatTests` (PEM + DER), and `PfxTests`; add the Thumbprint KAT.
Acceptance: `GetCertificateInfo` returns all fields correctly incl. restored extensions and a digest-verified `Thumbprint`; PFX round-trips (wrong password → `CryptographicException`); DER round-trip and PEM/DER equivalence hold.

## Acceptance criteria
- `Enigma.Core` builds clean with **ZERO warnings** across `netstandard2.0`, `net8.0`, `net10.0` under `TreatWarningsAsErrors` + `GenerateDocumentationFile` (CS1591 as error); XML docs on all public types/members including the new `X509KeyUsage`, `X509CertificateOptions`, and amended members.
- **No `Org.BouncyCastle.*` type** appears in any public signature, base type, return, or public support-type member of `Enigma.Core.Certificates` — proven by the reflection test — despite the internal BC package reference inherited from foundation.
- `GenerateSelfSignedCertificate` produces a PEM cert whose `GetCertificateInfo` reports `Subject==Issuer`, the requested DN, `Version 3`, an RSA `SignatureAlgorithm`, a positive `System.Numerics.BigInteger` serial, and `DateTimeOffset` validity matching inputs; validates via `ValidateChain` against itself.
- Extension controls work: an options record with `IsCertificateAuthority=true` and `KeyUsage=KeyCertSign|CrlSign` yields a cert whose `GetCertificateInfo` reads those back, and which functions as a PKIX anchor/intermediate.
- `GenerateCertificateSigningRequest` produces a CSR that `IssueCertificate` accepts; `IsCertificateSigningRequestValid` is true for it and a tampered CSR is rejected.
- `IssueCertificate` yields a leaf whose `Issuer==issuer subject` and `Subject==CSR subject`, chaining to the issuer.
- A 3-level root→intermediate→leaf hierarchy validates: `ValidateChain(leaf, [rootPem], [intermediatePem])` true; missing intermediate false; unrelated root false; expired and not-yet-valid leaves false; empty `trustedRootPems` false.
- `IsRevoked` true for a leaf in a valid issuer-signed CRL, false for an unrevoked leaf against a valid CRL; `ValidateChain` performs no revocation check.
- `GetCertificateInfo` round-trips a `System.Numerics.BigInteger` serial, returns `DateTimeOffset` dates, `int` Version, read-back `SignatureAlgorithm`, restored `IsCertificateAuthority`/`KeyUsage`/`SubjectAlternativeNames`, and a `Thumbprint` matching an independently computed uppercase-hex SHA-256 of the DER cert.
- `ExportPkcs12`/`ImportPkcs12` round-trip (extracted key can sign; with-chain works; wrong/empty password behaviour asserts `CryptographicException` for wrong); `ExportCertificateToDer`/`ImportCertificateFromDer` round-trip and equal the PEM form.
- Encrypted-PEM password handling works across generation/CSR/issuance (correct / null-for-unencrypted / wrong-throws); no BouncyCastle exception escapes any member.
- Every restored member is implemented and tested; every api-changing amendment was added as a throwing stub first and lands in one reviewed contract change; all ported X.509 tests pass; the existing smoke test stays green.
- Roadmap + plan status updated; completion docs `docs/done/FEATURE-099B-PHASE01.md`, `-PHASE02.md`, `-PHASE03.md` written.
