# FEATURE-57A9 — Certificates on the `RsaKey` handle (BREAKING)

**Status:** DONE
**Branch:** `feature/feature-57a9-certificates-rsakey`
**Plan:** `docs/plan/FEATURE-57A9.md`

## Summary

`IX509CertificateService` now takes key material as `RsaKey` handles and nothing else. The five
signatures the plan specifies were migrated in place — no `[Obsolete]` shim, no retained PEM-string
overload — and the `char[]? password` parameter is gone from every key-taking method. A passphrase is
supplied once, at `RsaKey.ImportPrivateKeyPem`, and never reaches the certificate API again. The
`char[] password` on `ExportPkcs12`/`ImportPkcs12` is untouched: it protects the PKCS#12 archive, not a
key PEM.

`ImportPkcs12` changed in both directions: it now returns `(string certificatePem, RsaKey privateKey)`
and constructs that handle around the extracted BouncyCastle key directly. **No private-key PEM is
written or re-parsed on that path any more** — the ~23-38 ms reconstruction cost FEATURE-6852 exists to
remove is gone from the PKCS#12 import too.

With its last caller gone, `src/Enigma.Core/Asymmetric/PublicKey/PemUtils.cs` was **deleted**. It was
already pure delegation over `Enigma.Core.Internal.PemEnvelope` (FEATURE-6852-PHASE01), so deleting it
removed a redirect, not an implementation. `PemEnvelope` remains `internal` and remains the single
implementation of the PBES2 scheme, the 600 000-iteration constant and the PEM exception mapping.

RSA is now represented one way across the whole library: `RsaKey`. The internal inconsistency
FEATURE-6852 left behind — RSA operations on handles, certificate operations on PEM strings plus a
passphrase — is closed.

## Files/modules touched

### Product code (modified)

- `src/Enigma.Core/Certificates/IX509CertificateService.cs` — the five signatures migrated to `RsaKey`;
  `char[]? password` removed from `GenerateSelfSignedCertificate`, `GenerateCertificateSigningRequest`
  and `IssueCertificate`; `ImportPkcs12`'s return type changed. XML docs rewritten: the interface
  `<remarks>` now states that key material crosses as `RsaKey` and that any passphrase is supplied once
  at import (explicitly excepting the PKCS#12 archive password), and `ImportPkcs12`'s `<returns>` drops
  "unencrypted private key (PEM-encoded)" for the handle, noting `ExportPrivateKeyPem` as the way back
  to a file. Added the `<exception>` docs the new argument contract implies.
- `src/Enigma.Core/Certificates/X509CertificateService.cs` — all five `PemUtils` call sites rewritten
  against `RsaKey`. Added a private `RequirePrivate(RsaKey, string paramName)` helper carrying the
  public-only guard, mirroring `PublicKeyService.RequirePrivate`; null-handle guards added on the four
  key-taking methods. `ImportPkcs12` builds the handle via the internal `RsaKey.FromBcKey`. Class
  `<remarks>` updated. `X509CertUtils` untouched, as the plan requires.

### Product code (deleted)

- `src/Enigma.Core/Asymmetric/PublicKey/PemUtils.cs` — **deleted** (51 lines of delegation).

### Tests (modified)

- `CertificateKeyFixture.cs` — exposes `RootPrivateKey`, `IntermediatePrivateKey`, `LeafPrivateKey`,
  `UnrelatedRootPrivateKey` as `RsaKey`; keeps `EncryptedPrivateKeyPem` + `EncryptedKeyPassword` so the
  encrypted path stays meaningful. The stale "the certificate API still takes private keys as PEM text"
  comment is replaced.
- `EncryptedKeyPemTests.cs` — six `[Fact]`s before, six after; see *Deviations* for the one swap.
- `SelfSignedCertificateTests.cs` — call sites updated; `GenerateSelfSigned_MalformedPrivateKeyPem_Throws`
  replaced by null-handle and public-only-handle tests (see *Deviations*).
- `Pkcs12Tests.cs` — call sites updated; the two round-trip tests now assert against the returned
  handle instead of a returned PEM, plus three new tests (certificate-binding, non-RSA key entry,
  public-only key).
- `CertificateSigningRequestTests.cs`, `IssueCertificateTests.cs` — call sites updated, plus
  null/public-only handle guards for their own key parameters.
- `ChainValidationTests.cs` — call sites updated; the `RootCa` / `Issue` helpers retyped from
  `string keyPem` to `RsaKey`.
- `RevocationTests.cs` — call sites updated; two `RootKeyPem` / `UnrelatedRootKeyPem` properties added
  because `TestCrlBuilder` signs with BouncyCastle directly and the test project cannot see `RsaKey`'s
  internal BouncyCastle key.
- `CertificateInfoTests.cs`, `CertificateFormatTests.cs` — call sites updated only where the compiler
  required it. `CertificateInfoTests` exports a PEM for its test-only BC certificate builder, same
  reason as above.
- `TestPkcs12Builder.cs` — two helpers added: `ReadCertificatePublicKeyPem` (reads a certificate's
  certified public key so a test can check a handle against the *certificate*, not another copy of the
  handle) and `CreateNonRsaKeyArchive` (an Ed25519-keyed PKCS#12 for the new guard).

Not touched, as expected: `TestCrlBuilder.cs` (its PEM-based signatures still fit),
`X509CertificateServiceFactoryTests.cs`, `CertificatesBouncyCastleIsolationTests.cs` — the isolation
guard needed no change because `RsaKey` is not a BouncyCastle type.

### Docs

- `docs/guides/certificates.md` — **rewritten** for the new API, with a `Migrating from the PEM-string
  API` section: a before/after table for the five members, a worked example replacing three
  `password:`-per-call sites with one `RsaKey.ImportPrivateKeyPem`, an explicit warning that positional
  arguments shift, and an `ImportPkcs12`-returns-a-handle before/after.
- `docs/guides/public-key.md` — a `The certificate service moved too` subsection added to its migration
  section, linking to the certificates guide (the certificates guide links back).

## Deviations & follow-ups

1. **`ImportPkcs12` gained a non-RSA guard the plan did not specify.**
   `X509CertUtils.ImportPkcs12` returns a BouncyCastle `AsymmetricKeyParameter`, which the 1.x code path
   simply wrote out as a PEM whatever its algorithm. With an `RsaKey` return there is no representable
   result for a non-RSA key entry, so the archive is now rejected with `ArgumentException` naming
   `pkcs12` — the same mapping the existing "contains no key entry with a certificate" case uses. A test
   (`ImportPkcs12_NonRsaKeyEntry_Throws`, over a new Ed25519-keyed archive fixture) and an
   `<exception>` doc line cover it. This is new behaviour, but the alternative was an
   `InvalidCastException` leak.

2. **Plan step 6 — the malformed-PEM test was deleted, not relocated.** The plan offered either choice.
   `RsaKeyTests.ImportPrivateKeyPem_EmptyOrMalformedPem_ThrowsArgumentExceptionNamingThePem` (`:311-315`)
   already asserts exactly `RsaKey.ImportPrivateKeyPem("not a pem at all")` → `ArgumentException` with
   `ParamName == "pem"`, so relocating `GenerateSelfSigned_MalformedPrivateKeyPem_Throws` would have
   duplicated an existing test verbatim. It was deleted and **replaced by two stronger tests** at the
   boundary that actually changed: `GenerateSelfSigned_NullPrivateKey_Throws` and
   `GenerateSelfSigned_PublicOnlyKey_ThrowsArgumentExceptionNamingTheKey`. Net certificate-test count
   is up, not down.

3. **Plan step 5 — one of the two wrong-password tests was retired, as the plan anticipated.** With the
   passphrase gone from the certificate API, `GenerateSelfSigned_EncryptedKey_WrongPassword` and
   `IssueCertificate_EncryptedIssuerKey_WrongPassword` collapsed onto the identical assertion —
   `RsaKey.ImportPrivateKeyPem(pem, wrongPassword)` throws `CryptographicException` — with no
   certificate operation left in either. The three success tests keep their certificate assertions
   verbatim, now operating on an imported handle. The three failure tests became:
   `ImportEncryptedKey_WrongPassword_ThrowsCryptographicException`,
   `ImportEncryptedKey_NoPassword_ThrowsCryptographicException`, and — in place of the duplicate —
   `EncryptedKey_ImportedOnce_ServesEveryCertificateOperation`, which asserts that one imported
   handle drives generation, CSR and issuance. The class is still six `[Fact]`s; no assertion was
   weakened, and the issuance-under-encrypted-key coverage the retired test contributed is preserved by
   `IssueCertificate_EncryptedIssuerKey_CorrectPassword_Succeeds` and the new test.

4. **No third un-relocatable call site appeared.** Plan step 7's contingency was not needed: every other
   certificate test was a mechanical call-site update, and every behavioural assertion survived
   unchanged.

5. **`ExportPkcs12` argument-check order.** The `privateKey` null check runs before the `password` null
   check. The pre-existing `ExportPkcs12_NullPassword_Throws` passes a valid key, so it is unaffected.

6. **Line endings.** No CRLF/LF churn was observed in this dev's diff; no action taken (recommendation-only
   per the workflow).

**Follow-ups (not done here, not blocking):**

- `docs/guides/certificates.md`'s note that a PKCS#12's stored private key is unencrypted is a property
  of `X509CertUtils.ExportPkcs12` (`Pkcs12StoreBuilder` defaults), unchanged by this item — worth a look
  if archive-key encryption ever becomes configurable.
- PQC certificates (ML-DSA-signed X.509) remain out of scope, as does a key-material abstraction
  spanning RSA and PQC for the certificate module — both recorded in the plan.

## Build/test evidence

- **Build:** `dotnet build Enigma.Core.slnx -c Release` → **Build succeeded, 0 Warning(s), 0 Error(s)**,
  across all three TFMs (`netstandard2.0`, `net8.0`, `net10.0`). `TreatWarningsAsErrors=true` and
  `EnforceCodeStyleInBuild=true` are in force, so this is a genuine zero-warning build.
- **Tests:** `dotnet test --solution Enigma.Core.slnx -c Release` → **total 3644, failed 0, succeeded
  3644, skipped 0**, green on both `net8.0` and `net10.0`.
- **Test count: 3626 → 3644** (+18 = **9 net-new test cases × 2 test TFMs**), all in `Certificates`.
  Ten added, one deleted, one replaced in place:
  - *added (10)* — `GenerateSelfSigned_NullPrivateKey_Throws`,
    `GenerateSelfSigned_PublicOnlyKey_ThrowsArgumentExceptionNamingTheKey`, `GenerateCsr_NullPrivateKey_Throws`,
    `GenerateCsr_PublicOnlyKey_ThrowsArgumentExceptionNamingTheKey`, `IssueCertificate_NullIssuerPrivateKey_Throws`,
    `IssueCertificate_PublicOnlyIssuerKey_ThrowsArgumentExceptionNamingTheKey`, `ExportPkcs12_NullPrivateKey_Throws`,
    `ExportPkcs12_PublicOnlyKey_ThrowsArgumentExceptionNamingTheKey`,
    `ImportPkcs12_ExtractedKeySignatureVerifiesAgainstReturnedCertificate`, `ImportPkcs12_NonRsaKeyEntry_Throws`;
  - *deleted (1)* — `GenerateSelfSigned_MalformedPrivateKeyPem_Throws` (*Deviations* 2);
  - *replaced (1)* — `IssueCertificate_EncryptedIssuerKey_WrongPassword_ThrowsCryptographicException` →
    `EncryptedKey_ImportedOnce_ServesEveryCertificateOperation` (*Deviations* 3).
- **`PemUtils` deletion verified:** `grep -rn "PemUtils" src/ tests/` returns **no hits**.
- **`PemEnvelope` verified unchanged:** still `internal static class PemEnvelope`
  (`src/Enigma.Core/Internal/PemEnvelope.cs:45`), still the only site of `Pbkdf2IterationCount = 600_000`,
  `IdAes256Cbc` and the PEM exception mapping.
- **Guide snippets verified by compilation, not by eye:** every C# snippet in the rewritten
  `docs/guides/certificates.md` (including both migration "after" blocks) was assembled into a throwaway
  library project referencing `Enigma.Core` and compiled against `net10.0` — **Build succeeded**, no
  errors or warnings. The scratch project was discarded.

## Acceptance criteria

| # | Criterion | Evidence |
|---|---|---|
| 1 | Signatures match the plan's "after" exactly; no `char[]? password` on any key-taking method; PKCS#12 archive password kept | `IX509CertificateService.cs` — the five members match verbatim; `ExportPkcs12`/`ImportPkcs12` keep `char[] password` |
| 2 | No `[Obsolete]`; no PEM-string overload retained | no `[Obsolete]` in the diff; each signature migrated in place, none duplicated |
| 3 | `PemUtils.cs` deleted; repo-wide search clean in `src/` and `tests/` | file deleted; `grep -rn "PemUtils" src/ tests/` → no hits |
| 4 | `PemEnvelope` still `internal`, still the sole PBES2 / iteration / mapping implementation | `internal static class PemEnvelope`; single-site greps for the constant and cipher OID |
| 5 | `ImportPkcs12` produces a working `RsaKey` with no intermediate PEM; it signs data verifying against the returned certificate's public key | `ImportPkcs12_ExtractedKeySignatureVerifiesAgainstReturnedCertificate` verifies against the public key read back from the *returned certificate*; implementation calls `RsaKey.FromBcKey` with no PEM round-trip |
| 6 | Round trip `GenerateRsaKey` → `ExportPkcs12` → `ImportPkcs12` preserves key and certificate | `ExportImportPkcs12_RoundTrip_PreservesCertificate` asserts thumbprint, subject and serial on the certificate, and `HasPrivateKey`, `KeySizeBits` and public-PEM equality on the handle |
| 7 | `null` handle → `ArgumentNullException`; public-only handle → `ArgumentException` with the right `paramName`, on all four key-taking methods | eight tests, two per method, each asserting the exact `ParamName` (`privateKey` / `issuerPrivateKey`) |
| 8 | Encrypted PEM works end-to-end for self-signed, CSR and issuance; wrong and missing password → `CryptographicException` at the import | `EncryptedKeyPemTests` — three success tests plus `EncryptedKey_ImportedOnce_ServesEveryCertificateOperation`; `ImportEncryptedKey_WrongPassword…` / `…_NoPassword…` |
| 9 | Every pre-existing behavioural assertion still present and passing, with the two relocations accounted for | 3644/3644 green; relocations recorded in *Deviations* 2 and 3; no assertion weakened to make a test compile |
| 10 | The three BouncyCastle isolation guards green with `RsaKey` on the certificate surface | all pass unmodified — `RsaKey` is not a BouncyCastle type, so no guard needed changing |
| 11 | Release build clean, zero warnings on three TFMs; suite green on net8.0 and net10.0 | see *Build/test evidence* |
| 12 | `docs/guides/certificates.md` rewritten with its migration section; every snippet compiles | rewritten; snippets compiled against `net10.0` — Build succeeded |
| 13 | This document written, including release-note copy and deviations | this file |

## Release-note copy for FEATURE-19C7

### Certificates take RSA key handles (breaking)

`IX509CertificateService` no longer accepts private keys as PEM text. Every method that takes key
material now takes an `RsaKey` handle — the same type `IPublicKeyService` adopted in this release — and
the per-call `char[]? password` parameter is gone.

| Before (1.x) | After (2.0.0) |
|---|---|
| `GenerateSelfSignedCertificate(string, string privateKeyPem, DateTimeOffset, DateTimeOffset, RsaSignatureAlgorithm, char[]? password, X509CertificateOptions?)` | `GenerateSelfSignedCertificate(string, RsaKey privateKey, DateTimeOffset, DateTimeOffset, RsaSignatureAlgorithm, X509CertificateOptions?)` |
| `GenerateCertificateSigningRequest(string, string privateKeyPem, RsaSignatureAlgorithm, char[]? password)` | `GenerateCertificateSigningRequest(string, RsaKey privateKey, RsaSignatureAlgorithm)` |
| `IssueCertificate(string, string, string issuerPrivateKeyPem, DateTimeOffset, DateTimeOffset, RsaSignatureAlgorithm, char[]? password, X509CertificateOptions?)` | `IssueCertificate(string, string, RsaKey issuerPrivateKey, DateTimeOffset, DateTimeOffset, RsaSignatureAlgorithm, X509CertificateOptions?)` |
| `ExportPkcs12(string, string privateKeyPem, char[] password, IReadOnlyList<string>?)` | `ExportPkcs12(string, RsaKey privateKey, char[] password, IReadOnlyList<string>?)` |
| `(string certificatePem, string privateKeyPem) ImportPkcs12(byte[], char[])` | `(string certificatePem, RsaKey privateKey) ImportPkcs12(byte[], char[])` |

Unchanged: `IsCertificateSigningRequestValid`, `ValidateChain`, `IsRevoked`, `GetCertificateInfo`,
`ExportCertificateToDer`, `ImportCertificateFromDer`, `CertificateInfo`, `X509CertificateOptions`,
`X509KeyUsage` and `IX509CertificateServiceFactory`.

#### The passphrase is supplied once, at the import

An encrypted key file used to mean repeating the passphrase at every call site:

```csharp
// 1.x
string caCertPem = certificates.GenerateSelfSignedCertificate(
    "CN=Example Root CA", caPrivateKeyPem, notBefore, notAfter,
    RsaSignatureAlgorithm.Sha256WithRsa, password, caOptions);

string csrPem = certificates.GenerateCertificateSigningRequest(
    "CN=service.example.com", caPrivateKeyPem,
    RsaSignatureAlgorithm.Sha256WithRsa, password);

string leafPem = certificates.IssueCertificate(
    csrPem, caCertPem, caPrivateKeyPem, notBefore, notAfter,
    RsaSignatureAlgorithm.Sha256WithRsa, password, leafOptions);
```

Now it is supplied where the key is parsed, and the handle does the rest:

```csharp
// 2.0.0
RsaKey caKey = RsaKey.ImportPrivateKeyPem(caPrivateKeyPem, password);

string caCertPem = certificates.GenerateSelfSignedCertificate(
    "CN=Example Root CA", caKey, notBefore, notAfter,
    RsaSignatureAlgorithm.Sha256WithRsa, caOptions);

string csrPem = certificates.GenerateCertificateSigningRequest(
    "CN=service.example.com", caKey);

string leafPem = certificates.IssueCertificate(
    csrPem, caCertPem, caKey, notBefore, notAfter,
    RsaSignatureAlgorithm.Sha256WithRsa, leafOptions);
```

Each 1.x call re-parsed the PEM and re-derived the decryption key from the passphrase before it could
sign anything. Import once, keep the handle.

A wrong or missing passphrase now surfaces as `CryptographicException` from `RsaKey.ImportPrivateKeyPem`
rather than from the certificate call that used to consume it.

#### `ImportPkcs12` returns a handle

```csharp
// 1.x — the returned PEM had to be re-imported before it could be used
(string certPem, string keyPem) = certificates.ImportPkcs12(pfx, pfxPassword);
RsaKey key = RsaKey.ImportPrivateKeyPem(keyPem);

// 2.0.0 — the handle is the return value
(string certPem, RsaKey key) = certificates.ImportPkcs12(pfx, pfxPassword);
```

No private-key PEM is written or re-parsed on this path any more. If you want a file, call
`key.ExportPrivateKeyPem()` — and note the 1.x return was always *unencrypted*, so passing a password to
the export is usually the better choice. A PKCS#12 whose key entry is not an RSA key now raises
`ArgumentException`, since there is no `RsaKey` to return.

#### Watch for shifted positional arguments

`char[]? password` sat between `signatureAlgorithm` and `options`. With it removed, an `options`
argument that was passed positionally now binds to the wrong parameter — usually a compile error, but
check any call site that did not use `options:`.

#### Migration guide

The certificates guide carries the full before/after:
[docs/guides/certificates.md](../guides/certificates.md#migrating-from-the-pem-string-api).
