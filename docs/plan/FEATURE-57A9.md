# FEATURE-57A9 — Certificates on the `RsaKey` handle (BREAKING)

**Status:** DONE (single-phase)
**Type:** FEATURE
**Branch (at build time):** `feature/feature-57a9-certificates-rsakey` — cut from current `HEAD`.

## Objective

Finish what FEATURE-6852 starts: make `RsaKey` the **single** representation of RSA key material
across the whole library. `IX509CertificateService` stops taking `string privateKeyPem` +
`char[]? password` and stops returning a private-key PEM string; `PemUtils` loses its last caller and
is **deleted**.

Deliberate breaking change, shipping in the same MAJOR version. **Nothing is marked `[Obsolete]`.**

**Depends on FEATURE-6852-PHASE02.** Build that first — this item consumes `RsaKey` and the
`PublicKeyService` rewrite.

## Why

After FEATURE-6852 alone the library is internally inconsistent: RSA operations take an `RsaKey`
while certificate operations still take a PEM string plus a passphrase on four methods, and
`ImportPkcs12` hands back a PEM string the caller must re-import — paying exactly the ~23-38 ms
reconstruction cost FEATURE-6852 exists to remove. A major version is the only cheap moment to fix
it, and the certificate **tests** must be touched in FEATURE-6852-PHASE02 regardless (their fixture
builds key material through the deleted `GenerateRsaKeyPair`).

## Context & constraints

- Ships in **2.0.0** with FEATURE-5413 and FEATURE-6852 (release: FEATURE-19C7).
- All shared constraints apply: BouncyCastle isolation, three TFMs, zero warnings, CPM, xUnit v3 /
  MTP, `.gitattributes` `eol=lf`.
- `Enigma.Core.Certificates` already depends on `Enigma.Core.Asymmetric.PublicKey` (it calls
  `PemUtils`, which lives there), so taking `RsaKey` introduces **no new** namespace coupling.
- Certificates, CSRs and CRLs stay **PEM strings**. Only *key material* changes representation.
  PKCS#12 (`byte[]`) and DER (`byte[]`) stay as they are — the two documented exceptions to the
  all-PEM contract.

## Design decisions (from the interview)

1. **Full migration, both directions.** Inputs *and* `ImportPkcs12`'s return value. A half-migration
   would leave the same inconsistency one layer down and need a second breaking change to finish.
2. **`PemUtils` is deleted.** After this item nothing calls it; its four members are already thin
   delegates over `Enigma.Core.Internal.PemEnvelope` (FEATURE-6852-PHASE01), so deleting the file
   removes a redirect, not an implementation. `PemEnvelope` stays `internal`; it is never made public.
3. **The passphrase disappears from the certificate API entirely.** It is supplied once, at
   `RsaKey.ImportPrivateKeyPem`. Do not reintroduce a `char[]? password` on any key-taking certificate
   method. (`ExportPkcs12`/`ImportPkcs12` keep their `char[] password` — that one protects the
   **PKCS#12 archive**, not a key PEM, and is unrelated.)
4. **Parameter order is preserved.** `RsaKey privateKey` takes the exact position of the removed
   `string privateKeyPem`; the removed `char[]? password` simply disappears, which shifts the trailing
   optional parameters. Callers using positional arguments break — acceptable and expected in a major
   version, and called out in the migration guide.

## Public surface changes

```csharp
// before -> after

string GenerateSelfSignedCertificate(
    string subjectDistinguishedName, string privateKeyPem,
    DateTimeOffset notBefore, DateTimeOffset notAfter,
    RsaSignatureAlgorithm signatureAlgorithm = RsaSignatureAlgorithm.Sha256WithRsa,
    char[]? password = null, X509CertificateOptions? options = null);
// ->
string GenerateSelfSignedCertificate(
    string subjectDistinguishedName, RsaKey privateKey,
    DateTimeOffset notBefore, DateTimeOffset notAfter,
    RsaSignatureAlgorithm signatureAlgorithm = RsaSignatureAlgorithm.Sha256WithRsa,
    X509CertificateOptions? options = null);

string GenerateCertificateSigningRequest(
    string subjectDistinguishedName, string privateKeyPem,
    RsaSignatureAlgorithm signatureAlgorithm = RsaSignatureAlgorithm.Sha256WithRsa,
    char[]? password = null);
// ->
string GenerateCertificateSigningRequest(
    string subjectDistinguishedName, RsaKey privateKey,
    RsaSignatureAlgorithm signatureAlgorithm = RsaSignatureAlgorithm.Sha256WithRsa);

string IssueCertificate(
    string certificateSigningRequestPem, string issuerCertificatePem, string issuerPrivateKeyPem,
    DateTimeOffset notBefore, DateTimeOffset notAfter,
    RsaSignatureAlgorithm signatureAlgorithm = RsaSignatureAlgorithm.Sha256WithRsa,
    char[]? password = null, X509CertificateOptions? options = null);
// ->
string IssueCertificate(
    string certificateSigningRequestPem, string issuerCertificatePem, RsaKey issuerPrivateKey,
    DateTimeOffset notBefore, DateTimeOffset notAfter,
    RsaSignatureAlgorithm signatureAlgorithm = RsaSignatureAlgorithm.Sha256WithRsa,
    X509CertificateOptions? options = null);

byte[] ExportPkcs12(string certificatePem, string privateKeyPem, char[] password,
                    IReadOnlyList<string>? chainPems = null);
// ->
byte[] ExportPkcs12(string certificatePem, RsaKey privateKey, char[] password,
                    IReadOnlyList<string>? chainPems = null);

(string certificatePem, string privateKeyPem) ImportPkcs12(byte[] pkcs12, char[] password);
// ->
(string certificatePem, RsaKey privateKey) ImportPkcs12(byte[] pkcs12, char[] password);
```

**Unchanged:** `IsCertificateSigningRequestValid`, `ValidateChain`, `IsRevoked`,
`GetCertificateInfo`, `ExportCertificateToDer`, `ImportCertificateFromDer`, `CertificateInfo`,
`X509CertificateOptions`, `X509KeyUsage`, `IX509CertificateServiceFactory`.

## Scope

**In scope**

| File | Change |
|---|---|
| `src/Enigma.Core/Certificates/IX509CertificateService.cs` | five signatures migrated; XML docs rewritten |
| `src/Enigma.Core/Certificates/X509CertificateService.cs` | lines 36, 57, 89, 183, 199 rewritten against `RsaKey`; no `PemUtils` reference remains |
| `src/Enigma.Core/Asymmetric/PublicKey/PemUtils.cs` | **deleted** |
| `tests/…/Certificates/CertificateKeyFixture.cs` | exposes `RsaKey` instances instead of PEM strings |
| `tests/…/Certificates/EncryptedKeyPemTests.cs` | password assertions relocate to the import call site |
| `tests/…/Certificates/SelfSignedCertificateTests.cs` | call sites updated |
| `tests/…/Certificates/CertificateSigningRequestTests.cs` | call sites updated |
| `tests/…/Certificates/IssueCertificateTests.cs` | call sites updated |
| `tests/…/Certificates/ChainValidationTests.cs` | call sites updated |
| `tests/…/Certificates/RevocationTests.cs` | call sites updated |
| `tests/…/Certificates/Pkcs12Tests.cs` | call sites updated, incl. `ImportPkcs12`'s new return |
| `tests/…/Certificates/CertificateInfoTests.cs`, `CertificateFormatTests.cs`, `TestCrlBuilder.cs`, `TestPkcs12Builder.cs`, `X509CertificateServiceFactoryTests.cs`, `CertificatesBouncyCastleIsolationTests.cs` | updated **only** where the compiler requires it |
| `docs/guides/certificates.md` | **rewritten** for the new API, with a migration section |
| `docs/guides/public-key.md` | cross-reference added if the guide's migration section needs it |

**Out of scope**
- Certificates, CSRs, CRLs staying PEM strings — not revisited.
- ML-DSA / ML-KEM support in `Certificates/` — separate future work.
- `Enigma.Core.Internal.PemEnvelope` becoming public — it stays `internal`, permanently.
- The version bump and release notes — FEATURE-19C7 (this item only *supplies* the copy).

## Design / approach

1. **`IX509CertificateService`** — apply the five signature changes above. Rewrite the affected XML
   docs: the `<remarks>` sentence "Where a private-key PEM is encrypted, the passphrase is passed
   directly as a `char` array" is deleted and replaced with a statement that key material crosses this
   API as `RsaKey` and that any passphrase is supplied once, at import. `ImportPkcs12`'s `<returns>`
   drops "unencrypted private key (PEM-encoded)" in favour of the handle.

2. **`X509CertificateService`** —
   - lines 36, 57, 89: `PemUtils.ParsePrivateKey(privateKeyPem, password)` → `privateKey.BcKey`,
     preceded by a `null` guard on the handle and the private-key-required check. Use the **same**
     exception mapping as `PublicKeyService`: `ArgumentNullException` for a null handle, then
     `ArgumentException` with the handle's `paramName` if `HasPrivateKey` is `false`.
   - line 183 (`ExportPkcs12`): same substitution.
   - line 199 (`ImportPkcs12`): it currently writes an **unencrypted** private-key PEM via
     `PemUtils.WritePrivateKeyPem(privateKey, password: null)`. Replace that with construction of an
     `RsaKey` around the BouncyCastle key directly, through the `internal` constructor/factory
     FEATURE-6852-PHASE01 adds. **No PEM is produced or re-parsed on this path any more** — that is
     the point of the change.
   - `X509CertUtils.WritePem` and everything else in the module stay as they are.

3. **Delete `src/Enigma.Core/Asymmetric/PublicKey/PemUtils.cs`.** Confirm with a repository-wide
   search that no reference remains, in `src/` or `tests/`. If any behaviour still lives only in
   `PemUtils` at this point (it should not — FEATURE-6852-PHASE01 reduced it to delegation), move it
   into `PemEnvelope` rather than keeping the file alive, and record that as a deviation.

4. **`CertificateKeyFixture`** — the collection fixture generates four independent RSA-2048 keys plus
   one that exercises the encrypted path. Rework it to expose `RsaKey` instances
   (`RootPrivateKey`, `IntermediatePrivateKey`, `LeafPrivateKey`, `UnrelatedRootPrivateKey`), and keep
   the encrypted-key scenario meaningful by **storing the encrypted PEM string and its passphrase**
   (`EncryptedPrivateKeyPem`, `EncryptedKeyPassword`) so tests can still import it under password.
   Generation now goes through `GenerateRsaKey(2048)`; the encrypted PEM comes from
   `ExportPrivateKeyPem(EncryptedKeyPassword)`.

5. **`EncryptedKeyPemTests` — preserve every assertion, relocating three.** The file has **six**
   `[Fact]` tests, not five. Three assert that a correct passphrase works and three that a wrong or
   missing one raises `CryptographicException` *at the certificate call*. After this item the
   passphrase is consumed at import, so:
   - the three success tests — `GenerateSelfSigned_EncryptedKey_CorrectPassword_Succeeds` (:22),
     `GenerateCsr_EncryptedKey_CorrectPassword_Succeeds` (:45),
     `IssueCertificate_EncryptedIssuerKey_CorrectPassword_Succeeds` (:55) — keep their certificate
     assertions verbatim, operating on
     `RsaKey.ImportPrivateKeyPem(keys.EncryptedPrivateKeyPem, keys.EncryptedKeyPassword)`;
   - the three failure tests — `GenerateSelfSigned_EncryptedKey_WrongPassword_ThrowsCryptographicException`
     (:31), `GenerateSelfSigned_EncryptedKey_NoPassword_ThrowsCryptographicException` (:38),
     `IssueCertificate_EncryptedIssuerKey_WrongPassword_ThrowsCryptographicException` (:71) — keep
     asserting `CryptographicException` but around the **import** call.

   Note that once the passphrase leaves the certificate API, the two wrong-password tests (:31 and
   :71) collapse to the same assertion, since neither touches a certificate operation any more. Keep
   both only if they still differ; otherwise drop one as a **deliberate, recorded** deduplication and
   say so in `docs/done/FEATURE-57A9.md`. Nothing may be dropped silently and no assertion may be
   weakened; the class documentation is updated to say where the passphrase is now consumed.

6. **`SelfSignedCertificateTests.GenerateSelfSigned_MalformedPrivateKeyPem_Throws` (:144-148) is the
   one certificate test whose call site ceases to exist.** It passes the literal string `"not a pem"`
   as `privateKeyPem` and asserts `ArgumentException`; after the migration there is no string
   parameter to pass it to, so it cannot be a mechanical call-site update. Relocate the assertion to
   `RsaKey.ImportPrivateKeyPem("not a pem")` — still `ArgumentException`, `paramName: "pem"`
   (FEATURE-6852-PHASE01 acceptance criterion 9) — and rename it accordingly; or delete it as
   redundant with `RsaKeyTests`. **Pick one and record which** in the completion doc.

7. **All other certificate tests** — mechanical call-site updates only. Every assertion about
   behaviour (certificate contents, chain validity, revocation results, CSR validity, PKCS#12
   round-trips, `CertificateInfo` fields, DER conversions) must survive **unchanged**. Do not weaken
   an assertion to make a test compile. Steps 5 and 6 above are the **only** two exceptions; if the
   compiler turns up a third test whose call site cannot exist after the migration, treat it the same
   way — relocate the assertion and record the decision — rather than deleting it.

8. **`docs/guides/certificates.md` — rewritten.** House guide shape, every snippet against the real
   API. Add a migration section: a before/after table for the five changed members, plus a worked
   example replacing `password:`-per-call with a single `RsaKey.ImportPrivateKeyPem`, and a note that
   `ImportPkcs12` now returns a handle (callers who genuinely want a file can call
   `ExportPrivateKeyPem`).

9. **Release-note copy** — produce, in `docs/done/FEATURE-57A9.md`, ready-to-paste prose for
   FEATURE-19C7 covering the five signature changes and the `ImportPkcs12` return-type change.

## Acceptance criteria

1. `IX509CertificateService` matches the "after" signatures above exactly; no `char[]? password`
   parameter remains on any key-taking method, and `ExportPkcs12`/`ImportPkcs12` keep their archive
   password.
2. No `[Obsolete]` attribute is added anywhere; no PEM-string overload is retained.
3. `src/Enigma.Core/Asymmetric/PublicKey/PemUtils.cs` is **deleted** and a repository-wide search for
   `PemUtils` returns no hits in `src/` or `tests/`.
4. `Enigma.Core.Internal.PemEnvelope` is still `internal` and is still the only implementation of the
   PBES2 scheme, the iteration constant and the PEM exception mapping.
5. `ImportPkcs12` produces a working `RsaKey` with **no** intermediate PEM: the returned handle signs
   data that verifies against the returned certificate's public key.
6. Round trip: `GenerateRsaKey` → `ExportPkcs12` → `ImportPkcs12` → the recovered handle and
   certificate match the originals (same modulus, same certificate subject/serial).
7. A `null` `RsaKey` on any of the four key-taking methods → `ArgumentNullException`; a public-only
   handle → `ArgumentException` with that parameter's `paramName`.
8. An encrypted private-key PEM still works end-to-end for self-signed generation, CSR generation and
   issuance, via `RsaKey.ImportPrivateKeyPem(pem, password)`; wrong password and missing password both
   → `CryptographicException` at the import call.
9. **Every behavioural assertion in the pre-existing certificate suite is still present and still
   passing**, with the two relocations of design steps 5 and 6 accounted for in the completion doc —
   self-signed generation (incl. every `X509CertificateOptions` combination), CSR
   generation and validation, issuance and issuer/subject linkage, chain validation against trusted
   and untrusted roots, CRL revocation, `CertificateInfo` parsing (incl. the malformed-SAN
   characterization test), DER import/export, and the PKCS#12 tests.
10. `Certificates/CertificatesBouncyCastleIsolationTests`, `PublicKey/PublicKeyBouncyCastleIsolationTests`
    and `Api/BouncyCastleIsolationTests` are all green with `RsaKey` on the certificate surface.
11. Release build clean with **zero warnings** on all three TFMs; the full suite green on net8.0 and
    net10.0.
12. `docs/guides/certificates.md` is rewritten with its migration section and every snippet compiles
    against the new API.
13. `docs/done/FEATURE-57A9.md` is written, including the ready-to-paste release-note copy for
    FEATURE-19C7 and any deviation from this plan.

## Out of scope / suggestions recorded (not planned here)

- **PQC certificates** — ML-DSA-signed X.509 certificates and CSRs. BouncyCastle 2.7.0 can do it;
  it is a substantial FEATURE of its own (new signature-algorithm enum, OIDs, CSR and chain paths).
- **A key-material abstraction spanning RSA and PQC** for the certificate module — premature until
  PQC certificates exist.
