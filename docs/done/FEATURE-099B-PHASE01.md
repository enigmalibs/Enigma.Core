# FEATURE-099B PHASE01 — Generation, CSR & issuance (+ restored extension controls & CSR verification)

- **Status:** DONE
- **Type:** FEATURE phase (1 of 3)
- **Branch:** `feature/feature-099b-phase01-certificates-x509` (cut from `feature/feature-0d6d-pqc` @ `a68c0d6`)
- **Basis:** ported from Enigma.Cryptography v5.0.0 (`/home/jo/Dev/Enigma.Cryptography`), `X509` module + `Utils/X509Utils`, `Utils/PemUtils`, `SignatureAlgorithms`.

## Summary
Implemented the first slice of the X.509 certificate service behind the BouncyCastle-free PEM contract frozen
by FEATURE-4442 PHASE06 and amended (user-approved 2026-07-21) by this feature: **self-signed generation**,
**PKCS#10 CSR generation**, **issuance from a CSR**, **CSR verification**, and the **X.509 extension controls**
(`BasicConstraints` CA flag / `KeyUsage` / SAN) — all with the BouncyCastle generator, `Asn1SignatureFactory`
and PKCS#10 logic ported verbatim into internal code. The parameterless factory now returns a working service.
No `Org.BouncyCastle.*` type appears on the public surface (proven by a namespace-scoped reflection guard).

**Contract amendments landed this phase** (added as the API change, then implemented): the two new BC-free
types `X509KeyUsage` (`[Flags]`) and `X509CertificateOptions` (sealed record); the trailing
`X509CertificateOptions? options = null` parameter on `GenerateSelfSignedCertificate` and `IssueCertificate`;
and the new `bool IsCertificateSigningRequestValid(string csrPem)`. The Phase 3 amendments
(`CertificateInfo` extension fields, `ExportPkcs12`/`ImportPkcs12`, DER overloads) are **not** in this phase.

## Deviations & follow-ups
- **`GetCertificateInfo` core brought forward into Phase 1 (user-approved 2026-07-22).** The plan scheduled
  `GetCertificateInfo` for Phase 3, but in the PEM-only API it is the only public read path, and Phase 1 in
  isolation had almost no public-API way to assert generation correctness (`ValidateChain`/`IsRevoked` are
  Phase 2; the `CertificateInfo` extension fields are Phase 3). Per the `/build` reconciliation step, the user
  chose to implement `GetCertificateInfo` over the **eight fields the `CertificateInfo` record already defines**
  (Subject, Issuer, SerialNumber, NotBefore, NotAfter, SignatureAlgorithm, Version, Thumbprint). The **restored**
  extension fields (`IsCertificateAuthority`/`KeyUsage`/`SubjectAlternativeNames`) and their read-back, plus PFX
  and DER, **remain in Phase 3** as planned.
- **Cross-phase acceptance.** Phase 1's "CA extensions produce validatable anchors" is only *provable* once
  `ValidateChain` lands in Phase 2, and CA/KeyUsage/SAN *read-back* only once the `CertificateInfo` fields land
  in Phase 3. Phase 1 therefore asserts that CA-option certificates **generate and parse** and that a three-level
  root→intermediate→leaf hierarchy builds with correct issuer/subject linkage; the extension emission itself
  (`X509CertUtils.ApplyExtensions`) gets its end-to-end proof in Phase 2 (PKIX requires `cA=true`) and Phase 3
  (read-back). This matches the plan's stated intent that Phase 1 "gates CA-capable certs needed by Phase 2".
- **Shared internal JCA mapping (plan reconciliation).** The plan assumed the publickey feature already exposed
  the `RsaSignatureAlgorithm`→JCA-name mapping as shared internal logic; in the delivered FEATURE-2E3E it was a
  **private** method inside `PublicKeyService`. To honour the plan's "reuse to avoid casing drift" intent, the
  mapping was extracted to a new internal `Enigma.Core.SignatureAlgorithms.ToJcaName(...)` and `PublicKeyService`
  was refactored to delegate to it (behaviour identical; the RSA sign/verify suite stays green). The X.509
  service uses the same helper.
- **CSR tamper case is asserted via the "throws" branch.** The plan allows "false/throws" for a tampered CSR.
  With no BouncyCastle reference in the test project this phase (the test-side CRL helper's BC reference arrives
  in Phase 2), a *structurally valid but bad-signature* CSR cannot be forged from a PEM string alone, so the
  negative coverage asserts that a corrupted CSR PEM, a certificate-PEM-as-CSR, and an empty PEM all throw
  `ArgumentException`. `IsCertificateSigningRequestValid` still returns `false` (not throws) for a parseable CSR
  whose signature does not verify — that path is internal to `VerifyCsr` and is exercised end-to-end by
  `IssueCertificate`'s internal verification.
- **No CRLF/line-ending issues observed** in the touched files.

## Files / modules touched

### Added — library (`src/Enigma.Core/`)
- `SignatureAlgorithms.cs` — internal shared `RsaSignatureAlgorithm`→JCA-name mapping (single source of truth).
- `Certificates/X509KeyUsage.cs` — new public BC-free `[Flags]` enum (nine usage bits + `None`).
- `Certificates/X509CertificateOptions.cs` — new public sealed record (`IsCertificateAuthority`, `KeyUsage`, `SubjectAlternativeNames`).
- `Certificates/X509CertUtils.cs` — internal BouncyCastle plumbing: DN parse, RSA public-key derivation, random
  128-bit serial, `ApplyExtensions` (BasicConstraints/KeyUsage/SAN), cert & CSR PEM read/write, core
  `CertificateInfo` extraction (incl. uppercase-hex SHA-256 thumbprint via `BitConverter`), BC→`System.Numerics`
  serial and BC→`DateTimeOffset` conversions. Malformed PEM/DER surfaces as `ArgumentException` here.

### Modified — library (`src/Enigma.Core/Certificates/`)
- `IX509CertificateService.cs` — amended `GenerateSelfSignedCertificate`/`IssueCertificate` with the trailing
  `options` parameter; added `IsCertificateSigningRequestValid`. Full XML docs.
- `X509CertificateService.cs` — implemented generation, CSR, issuance, CSR verification and core
  `GetCertificateInfo`; internal CSR verification inside `IssueCertificate` (throws `CryptographicException` on
  an invalid CSR); signing failures wrapped as `CryptographicException`. `ValidateChain`/`IsRevoked` remain
  `NotImplementedException` (Phase 2).
- `X509CertificateServiceFactory.cs` — implemented the parameterless `CreateX509CertificateService()`.

### Modified — library (`src/Enigma.Core/Asymmetric/PublicKey/`)
- `PublicKeyService.cs` — removed the private `ToJcaName`; delegates to the shared `SignatureAlgorithms.ToJcaName`.

### Added — tests (`tests/Enigma.Core.UnitTests/Certificates/`)
- `CertificateKeyFixture.cs` — generate-once collection fixture (three independent RSA-2048 private keys + one
  password-encrypted key); exposes a service factory helper.
- `SelfSignedCertificateTests.cs` — subject/issuer, DN, v3, validity (`DateTimeOffset`), positive random serial,
  per-algorithm `SignatureAlgorithm` read-back, thumbprint shape, CA/SAN options generate a well-formed cert,
  argument guards.
- `CertificateSigningRequestTests.cs` — CSR PEM shape, valid-signature true, corrupted/non-CSR/empty throw.
- `IssueCertificateTests.cs` — issuer=CA-subject / subject=CSR-subject, distinct serials, three-level hierarchy
  linkage, malformed CSR / issuer cert throw.
- `EncryptedKeyPemTests.cs` — encrypted-key generation/CSR/issuance with correct password; wrong/absent password
  → `CryptographicException`.
- `X509CertificateServiceFactoryTests.cs` — factory returns fresh `X509CertificateService` instances.
- `CertificatesBouncyCastleIsolationTests.cs` — reflection guard: no `Org.BouncyCastle.*` type on any exported
  `Enigma.Core.Certificates` member (plus the shared `RsaSignatureAlgorithm`).

## Build / test evidence
- **Build:** `dotnet build -c Debug` and `-c Release` both succeed with **0 warnings / 0 errors** across
  `netstandard2.0`, `net8.0`, `net10.0` under `TreatWarningsAsErrors` + `GenerateDocumentationFile` (CS1591 as
  error → every new public type/member is documented).
- **Tests:** full suite green on both TFMs — **3162 passed, 0 failed, 0 skipped** (net8.0 + net10.0), up from the
  1546-per-framework baseline by the **35 new Certificates tests** (× 2 frameworks). The existing RSA/PQC/other
  suites remain green after the `PublicKeyService` JCA refactor.

## Acceptance criteria (Phase 1)
- Self-signed / CSR / issuance behaviours pass. ✅
- CA-capable certificates generate and build a validatable hierarchy (issuer/subject linkage asserted now;
  PKIX validation of the anchor lands in Phase 2). ✅ (scoped)
- `IsCertificateSigningRequestValid` correct (true for a valid CSR; malformed/non-CSR/empty rejected). ✅
- Reflection guard green (no BouncyCastle on the certificates public surface). ✅
