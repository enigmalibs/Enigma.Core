# FEATURE-099B PHASE02 — Chain validation & CRL revocation

- **Status:** DONE
- **Type:** FEATURE phase (2 of 3)
- **Branch:** `feature/feature-099b-phase02-chain-validation` (cut from `feature/feature-099b-phase01-certificates-x509` @ `a9210f9`)
- **Scope:** `X509/X509CertificateService.ValidateChain` + `UnitTests/X509/ChainValidationTests`.

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

## Follow-up re-review (2026-07-23)
The original adversarial review above was interrupted before it fully swept the `IsRevoked` verification surface. A
second, independent multi-lens re-review (5 dimensions, every finding refute-verified; 1 confirmed of 8 raw) found
**one further real defect — a sibling of issue 2 above — fixed here, empirically reproduced end-to-end first:**

4. **`IsRevoked` leaked `SecurityUtilityException` for an unrecognised signature-algorithm OID (contract / principle 1).**
   A CRL whose signature `AlgorithmIdentifier` carries an OID no signer recognises still parses via `ReadCrl`, but
   `crl.Verify` then reaches `SignerUtilities.InitSigner`, which throws `Org.BouncyCastle.Security.SecurityUtilityException`
   ("Signing mechanism … not recognised."). That type derives directly from `System.Exception` — not from
   `GeneralSecurityException`/`CryptoException`/`InvalidCastException` — so it escaped the catch filter as a raw
   BouncyCastle type, contradicting this doc's own "no BouncyCastle type escapes" claim. This is distinct from the
   Ed25519 case (issue 2): a recognised-but-wrong-key mechanism fails later at the key cast, whereas an entirely
   unknown OID fails earlier at mechanism lookup. **Fix:** added `SecurityUtilityException` to the catch filter (still
   scoped to only `crl.Verify`). **Regression test:** `IsRevoked_CrlWithUnknownSignatureAlgorithm_ThrowsCryptographicException`,
   backed by a new `TestCrlBuilder.CreateCrlWithUnknownSignatureAlgorithm` (DER-rewrites a valid CRL's inner+outer
   signature-algorithm OID to `1.2.3.4.5.6.7.8.9`). Confirmed the test fails against the pre-fix code (raw
   `SecurityUtilityException` at `X509CertificateService.cs:154`) and passes after the fix.

The other 7 raw findings were refuted on verification as documented design decisions (serial-only revocation lookup,
no CRL-freshness/`cRLSign` check, fail-closed `CryptographicException` on unverifiable CRLs), XML-doc-completeness
nits, a hypothetical-refactor test-coverage concern, and working-tree noise (probe files left by the review agents
themselves, never part of any commit).

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
  `Org.BouncyCastle.Pkix` / `Utilities.Collections` / `X509.Store` usings. The `IsRevoked` verify catch filter
  covers `GeneralSecurityException`/`CryptoException`/`InvalidCastException`/**`SecurityUtilityException`** (the last
  added by the 2026-07-23 follow-up re-review, issue 4).
- `X509CertUtils.cs` — added internal `ReadCrl(crlPem, paramName)` (PEM → `X509Crl`, malformed → `ArgumentException`).

### Modified — tests (`tests/Enigma.Core.UnitTests/`)
- `Enigma.Core.UnitTests.csproj` — added the **test-only** `BouncyCastle.Cryptography` package reference (CRL
  fixtures). Never reaches `Enigma.Core`'s public surface — the reflection guards inspect the product assembly.
- `Certificates/CertificateKeyFixture.cs` — added a fourth independent RSA key (`UnrelatedRootPrivateKeyPem`).

### Added — tests (`tests/Enigma.Core.UnitTests/Certificates/`)
- `TestCrlBuilder.cs` — test-only CRL fixture builder (`X509V2CrlGenerator` + `Asn1SignatureFactory`); RSA-signed
  `CreateCrl`, the mismatched-key-type `CreateEd25519SignedCrl`, and (follow-up re-review) the unknown-signature-OID
  `CreateCrlWithUnknownSignatureAlgorithm` (DER-rewrites the inner+outer signature-algorithm identifier).
- `ChainValidationTests.cs` — full chain, order-independent two-intermediate, imposter-root (same DN / different
  key), missing-intermediate, self-signed-against-itself, untrusted-root, expired, not-yet-valid, empty-anchor,
  null-anchor, malformed-leaf.
- `RevocationTests.cs` — revoked-true, unrevoked-false (empty CRL and CRL revoking others), wrong-issuer CRL →
  throws, mismatched-key-type CRL → throws, **unknown-signature-OID CRL → throws** (follow-up re-review), malformed
  CRL → throws, and `ValidateChain` performs no revocation.

## Build / test evidence
- **Build:** `dotnet build -c Debug` and `-c Release` both **0 warnings / 0 errors** across `netstandard2.0`,
  `net8.0`, `net10.0` (`TreatWarningsAsErrors` + `GenerateDocumentationFile`).
- **Tests:** full suite green on both TFMs — **3200 passed, 0 failed, 0 skipped** (net8.0 + net10.0). The
  Certificates namespace now has **19 PHASE02 test methods** (11 `ChainValidationTests` + 8 `RevocationTests`),
  incl. the 3 original review-driven regressions and the 2026-07-23 follow-up regression
  (`IsRevoked_CrlWithUnknownSignatureAlgorithm_ThrowsCryptographicException`). (The initial commit was 3198;
  the follow-up fix added one test → +1 per TFM → 3200.)

## Acceptance criteria (Phase 2)
- 3-level chain validates; missing-intermediate / untrusted-root / expired / not-yet-valid / empty-anchor all
  `false`. ✅ (plus order-independent multi-intermediate and imposter-root, added by review)
- `IsRevoked` true for a revoked leaf, false for an unrevoked leaf; `ValidateChain` performs no revocation on its
  own. ✅
- No `Org.BouncyCastle.*` type or exception escapes any member (incl. the CRL key-type-mismatch path **and the
  unrecognised-signature-OID path fixed by the 2026-07-23 follow-up re-review**). ✅
