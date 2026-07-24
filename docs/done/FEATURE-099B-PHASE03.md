# FEATURE-099B PHASE03 — CertificateInfo parsing, PFX & DER (restored)

- **Status:** DONE
- **Type:** FEATURE phase (3 of 3 — final phase; the FEATURE-099B item is now DONE)
- **Branch:** `feature/feature-099b-phase03-info-pfx-der` (cut from `feature/feature-099b-phase02-chain-validation` @ `f5d5a30`)
- **Scope:** `Utils/X509Utils`
  (`ExportToPfx`/`LoadFromPfx`/`GetCertificateInfo`/`SaveCertificate`/`LoadCertificate`), `X509/CertificateInfo`, and
  `UnitTests/X509/{CertificateInfoTests,CertificateFormatTests,PfxTests}`.

## Summary
Restored the last of the FEATURE-4442-dropped X.509 capabilities behind the PEM contract, keeping every BouncyCastle
type internal (principle 1):

- **`CertificateInfo` read-back** — added `IsCertificateAuthority` (`bool`, required), `KeyUsage` (`X509KeyUsage?`,
  `null` when the extension is absent) and `SubjectAlternativeNames` (`IReadOnlyList<string>`, empty when absent).
  `X509CertUtils.ExtractInfo` now reads the `BasicConstraints`, `KeyUsage` and `SubjectAlternativeName` extensions;
  the KeyUsage bit array is mapped back to the BC-free flags enum, and a structurally invalid SAN is swallowed to an
  empty list (narrowed catch), matching the old regression guard.
- **PKCS#12 (PFX)** — `ExportPkcs12(certificatePem, privateKeyPem, password, chainPems?)` bundles the certificate +
  (unencrypted) private key + optional chain into a password-protected archive; `ImportPkcs12(pkcs12, password)`
  extracts them back as `(certificatePem, privateKeyPem)`. PKCS#12 is binary → `byte[]` is the documented exception to
  the all-PEM contract. A read failure (wrong password / corrupt / non-PFX) surfaces as `CryptographicException`.
- **DER** — `ExportCertificateToDer(certificatePem)` / `ImportCertificateFromDer(der)` round-trip a certificate through
  its raw DER encoding; malformed/empty bytes surface as `ArgumentException`.

The `bool IsValidNow` field of the old `CertificateInfo` stays **dropped** (ambient-clock; determinism), per the plan.

## Adversarial review & fixes
An independent multi-lens re-review (5 dimensions — read-back / PKCS#12 / DER+isolation / test-adequacy / port-fidelity,
every finding refute-verified) surfaced **3 real issues of 9 raw findings (6 refuted)**, each fixed before DONE and
locked with a regression test:

1. **`ImportPkcs12` leaked a raw BouncyCastle `ArgumentException` on valid-DER-but-non-PFX input (contract, medium).**
   The catch around `store.Load` handled only `IOException` (MAC mismatch / wrong password). For input that is
   well-formed DER of the wrong ASN.1 shape — realistically, a DER **certificate** handed to `ImportPkcs12` by mistake —
   BouncyCastle's `Pfx.GetInstance` throws `System.ArgumentException` ("illegal object in GetInstance: …DLSequence",
   `ParamName` `obj`/`seq`), which escaped uncaught: a wrong/misleading exception whose message leaks a BouncyCastle
   type, contradicting the documented "corrupt archive → `CryptographicException`" contract. **Fix:** broadened the
   catch to `IOException or ArgumentException or InvalidCastException` → `CryptographicException` (the try wraps only
   `store.Load`, so the method's own empty/no-key-entry `ArgumentException`s, thrown outside it, are unaffected).
   **Regression test:** `ImportPkcs12_ValidDerButNotArchive_ThrowsCryptographicException` (passes a DER certificate);
   confirmed it fails against the pre-fix code (raw `ArgumentException` at `X509CertificateService.cs:198`).
2. **"With chain" PFX test proved nothing about the chain (test adequacy, low).** `ExportPkcs12_WithChain_RoundTrips`
   asserted only the leaf thumbprint; since `ImportPkcs12` does not surface the chain, a regression dropping `chainPems`
   would still pass. **Fix:** the test now cracks the archive open with a test-side `TestPkcs12Builder.ReadKeyEntryChainSubjects`
   and asserts both the leaf and `CN=Root CA` are present (chain length 2).
3. **`ImportPkcs12` "valid archive but no key entry" path was untested (test adequacy, low).** The documented
   `ArgumentException` for a structurally valid, MAC-correct archive that carries no key entry (e.g. a cert-only PFX,
   which the product API cannot itself produce) was unexercised. **Fix / new test:**
   `ImportPkcs12_ValidArchiveWithNoKeyEntry_Throws`, backed by `TestPkcs12Builder.CreateCertificateOnlyArchive`.

The 6 refuted findings were dismissed on verification: the KeyUsage read-back is correct for all 9 bits by construction
(refuted; also independently cross-checked below); DER behaviour is identical for issued vs self-signed certs (same
encoder); the Thumbprint KAT is as independent as a random-serial cert allows (recomputes SHA-256 with
`System.Security.Cryptography`, not the impl); and the encrypted-input-key case is a documented precondition that
already yields a clean `CryptographicException`.

## Independent cross-checks (beyond the test suite)
- **KeyUsage on-wire bits.** Generated a cert with `KeyUsage = DigitalSignature | KeyEncipherment` and parsed it with
  .NET's own `System.Security.Cryptography.X509Certificates` stack (a non-BouncyCastle oracle): it reported *exactly*
  `DigitalSignature | KeyEncipherment`. This proves the write-mapping (`ToBcKeyUsage`) and read-mapping
  (`FromBcKeyUsage`) are not "mirror-bugged" — both are anchored to correct X.509 semantics.

## Deviations & follow-ups
- **Stub-first process step skipped.** The plan called for adding the amendments as throwing stubs first; because the
  whole phase lands in a single commit, the members were implemented directly. The final artefact is identical.
- **`ExportPkcs12` input key is unencrypted by design.** The single `password` parameter protects the produced archive;
  the input `privateKeyPem` is parsed unencrypted (an encrypted PEM yields a clear `CryptographicException`). This
  matches the plan's amendment table (one password parameter).
- **No CRLF/line-ending issues observed** in the touched files.
- The PHASE02 follow-up (`SecurityUtilityException`) landed on the parent branch as `f5d5a30`; this phase branches from it.

## Files / modules touched

### Modified — library (`src/Enigma.Core/Certificates/`)
- `IX509CertificateService.cs` — added `ExportPkcs12`, `ImportPkcs12`, `ExportCertificateToDer`,
  `ImportCertificateFromDer` (with XML docs + exception contract).
- `CertificateInfo.cs` — added `IsCertificateAuthority`, `KeyUsage`, `SubjectAlternativeNames`.
- `X509CertUtils.cs` — `ExtractInfo` read-back of CA/KeyUsage/SAN; new `FromBcKeyUsage`, `ExtractSubjectAlternativeNames`,
  `ToDer`, `ReadCertificateFromDer`, `ExportPkcs12`, `ImportPkcs12` (catch broadened per review issue 1). Added the
  `Security.Certificates` / `X509.Extension` usings.
- `X509CertificateService.cs` — the four new members (parse PEM inputs, delegate to `X509CertUtils`/`PemUtils`;
  null-password guard on the PKCS#12 members; DER as one-liners).

### Added — tests (`tests/Enigma.Core.UnitTests/Certificates/`)
- `CertificateInfoTests.cs` — 11 tests: issued issuer≠subject, serial/validity/algorithm/version, `IsCertificateAuthority`
  true / explicit-false / absent, `KeyUsage` read-back (leaf flags & CA flags) / null-when-absent, SANs populated / empty /
  malformed→empty (builds a broken SAN via BouncyCastle test-side).
- `CertificateFormatTests.cs` — 6 tests: DER round-trip, PEM/DER equivalence, malformed-PEM / invalid-DER / empty-DER
  throw, Thumbprint KAT vs an independently computed uppercase-hex SHA-256 of the DER.
- `Pkcs12Tests.cs` — 10 tests: round-trip, extracted-key-can-sign, with-chain (chain observed via `TestPkcs12Builder`),
  wrong-password → `CryptographicException`, empty-password round-trip, malformed-archive / valid-DER-not-archive →
  `CryptographicException`, empty-archive / no-key-entry → `ArgumentException`, null-password → `ArgumentNullException`.
- `TestPkcs12Builder.cs` — test-only helper (cert-only archive builder; chain-subject reader) for fixtures the product
  API cannot produce.

## Build / test evidence
- **Build:** `dotnet build -c Release` — **0 warnings / 0 errors** across `netstandard2.0`, `net8.0`, `net10.0`
  (`TreatWarningsAsErrors` + `GenerateDocumentationFile`, CS1591 as error).
- **Tests:** full suite green on both TFMs — **3254 passed, 0 failed, 0 skipped** (net8.0 + net10.0). PHASE03 adds
  **27 test methods** (11 `CertificateInfoTests` + 6 `CertificateFormatTests` + 10 `Pkcs12Tests`), incl. the 3
  review-driven regressions. The `CertificatesBouncyCastleIsolationTests` reflection guard still passes with the new
  members (all BC-free: `byte[]`, `char[]`, `string`, `ValueTuple<string,string>`, `IReadOnlyList<string>`, `X509KeyUsage?`).

## Acceptance criteria (Phase 3)
- `GetCertificateInfo` returns `System.Numerics.BigInteger` serial, `DateTimeOffset` dates, `int` Version, read-back
  `SignatureAlgorithm`, restored `IsCertificateAuthority`/`KeyUsage`/`SubjectAlternativeNames`, and a `Thumbprint`
  matching an independently computed uppercase-hex SHA-256 of the DER. ✅
- `ExportPkcs12`/`ImportPkcs12` round-trip (extracted key can sign; with-chain verified; wrong/empty password behaviour
  — wrong → `CryptographicException`). ✅
- `ExportCertificateToDer`/`ImportCertificateFromDer` round-trip and denote the same certificate as the PEM form. ✅
- No `Org.BouncyCastle.*` type or exception escapes any member (incl. the non-PFX DER input path fixed by review). ✅
