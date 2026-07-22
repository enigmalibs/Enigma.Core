# FEATURE-099B PHASE02 — Chain validation & CRL revocation

- **Status:** DONE
- **Type:** FEATURE phase (2 of 3)
- **Branch:** `feature/feature-099b-phase02-chain-validation` (cut from `feature/feature-099b-phase01-certificates-x509` @ `a9210f9`)
- **Basis:** ported from Enigma.Cryptography v5.0.0 (`/home/jo/Dev/Enigma.Cryptography`), `X509/X509CertificateService.ValidateChain` + `UnitTests/X509/ChainValidationTests`.

## Summary
Implemented the two remaining trust operations behind the PEM contract: **`ValidateChain`** (PKIX path
validation) and **`IsRevoked`** (CRL-based revocation), keeping every BouncyCastle type internal.

- **`ValidateChain(certificatePem, trustedRootPems, intermediatePems?)`** — the old single, auto-classified
  trust collection is replaced by **explicit** `trustedRootPems` (all treated as PKIX trust anchors) plus
  optional `intermediatePems`. It **builds** the path with `PkixCertPathBuilder` (see the fix below), performs
  **no revocation** (`IsRevocationEnabled = false`), and preserves the two legacy semantics: **empty
  `trustedRootPems` → `false`**, and a chain that cannot be built/validated → `false` (not thrown). Malformed
  PEM input still throws `ArgumentException`.
- **`IsRevoked(certificatePem, crlPem, issuerCertificatePem)`** — parses the CRL, **verifies it was signed by
  the issuer certificate's key** (an unverifiable CRL is rejected with `CryptographicException`), then reports
  whether the certificate's serial is listed (`GetRevokedCertificate(serial) is not null`).
- **CRL generation stays out of the product API** (settled design): the revocation tests mint issuer-signed
  CRL fixtures with a **test-only** `TestCrlBuilder` (BouncyCastle referenced by the test project only). The
  product surface only *reads* CRLs.

## Adversarial review & fixes
After the implementation passed, an adversarial multi-lens review (PKIX / revocation / contract / fidelity,
each finding independently re-verified) surfaced **3 real issues (all high-confidence, 0 refuted)**, fixed
before declaring DONE — each locked in with a regression test:

1. **`ValidateChain` was intermediate-order-sensitive (correctness).** The first cut validated a caller-ordered
   `PkixCertPath` with `PkixCertPathValidator`, which does not build/reorder a path. A valid chain with ≥2
   intermediates supplied in any order other than strict leaf→root returned `false` — contradicting the
   interface doc's "…needed to **build** the chain / a valid chain … can be **built**". **Fix:** switched to
   `PkixCertPathBuilder` + `PkixBuilderParameters` with an `X509CertStoreSelector` targeting the leaf; ordering
   is now irrelevant. The failure type to catch changed accordingly (`PkixCertPathBuilderException`, not
   `PkixCertPathValidatorException`). **Regression test:** `ValidateChain_TwoIntermediates_OrderIndependent_Succeeds`
   (asserts both `[int2, int1]` and `[int1, int2]` validate on a 4-level chain).
2. **`IsRevoked` leaked `InvalidCastException` (contract).** A CRL signed with a non-RSA key type (e.g. Ed25519)
   verified against the RSA issuer threw `System.InvalidCastException` from BouncyCastle's verifier setup, which
   escaped the `GeneralSecurityException`/`CryptoException` catch filter — a non-contract exception on the public
   surface. **Fix:** added `InvalidCastException` to the filter (the `try` wraps only `crl.Verify`, so any
   verification failure correctly becomes `CryptographicException`). **Regression test:**
   `IsRevoked_CrlSignedWithMismatchedKeyType_ThrowsCryptographicException` (Ed25519-signed CRL via a new
   `TestCrlBuilder.CreateEd25519SignedCrl`).
3. **Test gap: signature-vs-name trust was unproven (test adequacy).** No test distinguished cryptographic path
   validation from DN matching — a regression that trusted any anchor with a matching name would have passed.
   **Fix / new test:** `ValidateChain_ImposterRootSameDnDifferentKey_Fails` — an anchor sharing the real root's
   subject DN (`CN=Root CA`) but built with a different key is correctly rejected.

## Deviations & follow-ups
- **Path builder vs. validator (deviation from the literal port).** The v5.0.0 source used
  `PkixCertPathValidator` over a pre-ordered list; this phase deliberately uses `PkixCertPathBuilder` instead,
  which is the correct PKIX primitive for the new "supply an unordered set of intermediates" contract. Behaviour
  for the plan's acceptance cases is unchanged; multi-intermediate order-independence is strictly better.
- One workflow verify-agent hit a transient API stall; the three distinct issues were each still confirmed by at
  least one completed verifier (5 confirmed findings collapsing to 3 issues), so no finding went unverified.
- The review agents left three throwaway probe files (`ZzProbe*.cs`) in the test folder; these were deleted and
  are **not** part of the commit.
- **No CRLF/line-ending issues observed** in the touched files.

## Files / modules touched

### Modified — library (`src/Enigma.Core/Certificates/`)
- `X509CertificateService.cs` — implemented `ValidateChain` (PKIX path **builder**, explicit anchors + optional
  intermediates, no revocation, empty-anchor/`PkixCertPathBuilderException` → `false`) and `IsRevoked` (CRL parse
  + issuer-signature verify + revoked-serial lookup; verify failures → `CryptographicException`). Added the
  `Org.BouncyCastle.Pkix` / `Utilities.Collections` / `X509.Store` usings.
- `X509CertUtils.cs` — added internal `ReadCrl(crlPem, paramName)` (PEM → `X509Crl`, malformed → `ArgumentException`).

### Modified — tests (`tests/Enigma.Core.UnitTests/`)
- `Enigma.Core.UnitTests.csproj` — added the **test-only** `BouncyCastle.Cryptography` package reference (CRL
  fixtures). Never reaches `Enigma.Core`'s public surface — the reflection guards inspect the product assembly.
- `Certificates/CertificateKeyFixture.cs` — added a fourth independent RSA key (`UnrelatedRootPrivateKeyPem`).

### Added — tests (`tests/Enigma.Core.UnitTests/Certificates/`)
- `TestCrlBuilder.cs` — test-only CRL fixture builder (`X509V2CrlGenerator` + `Asn1SignatureFactory`); RSA-signed
  `CreateCrl` and the mismatched-key-type `CreateEd25519SignedCrl`.
- `ChainValidationTests.cs` — full chain, order-independent two-intermediate, imposter-root (same DN / different
  key), missing-intermediate, self-signed-against-itself, untrusted-root, expired, not-yet-valid, empty-anchor,
  null-anchor, malformed-leaf.
- `RevocationTests.cs` — revoked-true, unrevoked-false (empty CRL and CRL revoking others), wrong-issuer CRL →
  throws, mismatched-key-type CRL → throws, malformed CRL → throws, and `ValidateChain` performs no revocation.

## Build / test evidence
- **Build:** `dotnet build -c Debug` and `-c Release` both **0 warnings / 0 errors** across `netstandard2.0`,
  `net8.0`, `net10.0` (`TreatWarningsAsErrors` + `GenerateDocumentationFile`).
- **Tests:** full suite green on both TFMs — **3198 passed, 0 failed, 0 skipped** (net8.0 + net10.0). The
  Certificates namespace now has **53 tests** (35 from PHASE01 + 18 from PHASE02, incl. the 3 review-driven
  regression tests).

## Acceptance criteria (Phase 2)
- 3-level chain validates; missing-intermediate / untrusted-root / expired / not-yet-valid / empty-anchor all
  `false`. ✅ (plus order-independent multi-intermediate and imposter-root, added by review)
- `IsRevoked` true for a revoked leaf, false for an unrevoked leaf; `ValidateChain` performs no revocation on its
  own. ✅
- No `Org.BouncyCastle.*` type or exception escapes any member (incl. the CRL key-type-mismatch path). ✅
