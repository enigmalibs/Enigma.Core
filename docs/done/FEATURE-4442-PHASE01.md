# FEATURE-4442-PHASE01 — Shared foundation (DONE)

## Summary
First phase of the abstraction skeleton: established the shared root vocabulary that later phases
depend on, before any service interfaces exist. Ported the pure `CryptoDefaults` constant verbatim and
**decided, once, the redesigned signature-algorithm representation** — replacing the old library's
JCA-style `SignatureAlgorithms` string constants with a BouncyCastle-free Enigma enum,
`RsaSignatureAlgorithm`. No services, no algorithm logic. This de-risks PHASE05 (RSA signing) and
PHASE06 (certificate signing), which both consume the signature-algorithm type, so its public shape is
fixed now rather than reshaped mid-feature.

## Files/modules touched

### Created — library (root namespace `Enigma.Core`)
- `src/Enigma.Core/CryptoDefaults.cs` — `public static class CryptoDefaults` with
  `public const int StreamBufferSize = 4096`. Ported verbatim from the source (renamespaced
  `Enigma.Cryptography` → `Enigma.Core`); doc comment unchanged (no BouncyCastle references to scrub).
- `src/Enigma.Core/RsaSignatureAlgorithm.cs` — `public enum RsaSignatureAlgorithm` with members
  `Sha1WithRsa`, `Sha256WithRsa`, `Sha384WithRsa`, `Sha512WithRsa`. Replaces the source's public
  `SignatureAlgorithms` string constants; XML docs on the type and every member.

### Modified — workflow tracking
- `docs/roadmap.md` — FEATURE-4442 base row `TODO` → `IN PROGRESS`; PHASE01 row `TODO` →
  `IN PROGRESS` → `DONE`. Realigned the Status column to accommodate `IN PROGRESS`.
- `docs/plan/FEATURE-4442.md` — top-level Status `TODO` → `IN PROGRESS`; PHASE01 Status `TODO` →
  `IN PROGRESS` → `DONE`; recorded the build-time signature design (per principle 8) in the PHASE01
  section, including the signature-algorithm decision.

## Design decisions (recorded for downstream phases)
- **Signature-algorithm representation = the plan's recommended enum.** `SignatureAlgorithms`
  (public JCA strings `"SHA1withRSA".."SHA512withRSA"`) → `enum RsaSignatureAlgorithm
  { Sha1WithRsa, Sha256WithRsa, Sha384WithRsa, Sha512WithRsa }`. Removes the JCA/BouncyCastle naming
  leak (principle 1); the implementation maps each member to its JCA name internally.
  - **Name justified as RSA-specific, not too narrow:** source review confirmed the only *choosable*
    signing algorithms across both consumers — `PublicKeyServiceFactory` (RSA signing, PHASE05) and
    `X509CertificateServiceFactory` (certificate signing, PHASE06) — are exactly these four RSA
    variants (default `Sha256WithRsa`). `X509Utils` only reads back an existing certificate's
    `SigAlgName`; it never selects an algorithm. **PHASE05/06 consume this enum and must not revisit
    the representation.**
- **No other shared root type introduced.** A symmetric cipher-mode enum is single-module (Symmetric —
  PHASE02), so per the plan it belongs in its owning module, not root. No unified hash-algorithm enum
  was created: the support-type triage deliberately keeps per-module hash enums (`OtpHashAlgorithm`,
  `RsaOaepHash`, `Pbkdf2Prf`, ported verbatim later); unifying them would contradict the plan.

## Deviations & follow-ups
- **None material.** Implementation matches the plan; the signature-algorithm decision took the plan's
  explicitly recommended option.
- **Line endings (CRLF):** none observed — the two new files are LF, consistent with `.gitattributes`
  `* text=auto eol=lf`. No action taken (recommendation-only per `dev-workflow`).
- **No dev branch switch to default:** branched `feature/feature-4442-phase01-shared-foundation` from
  `HEAD` (which was `main`), per the workflow.

## Build/test evidence
- **Build:** `dotnet build Enigma.Core.slnx -warnaserror` → `Build succeeded. 0 Warning(s) 0 Error(s)`,
  producing `Enigma.Core.dll` for `netstandard2.0`, `net8.0`, and `net10.0` under
  `TreatWarningsAsErrors` + `GenerateDocumentationFile` (so all-public-members XML docs are enforced).
- **Test:** `dotnet test --solution Enigma.Core.slnx` (MTP) → `Passed! total: 1, failed: 0,
  succeeded: 1, skipped: 0`. Per acceptance criterion 5, **no new unit tests** were added (nothing
  meaningful to assert — the phase adds only a constant and an enum, no throwing stubs even); Definition
  of Done criterion 2 is satisfied by the existing smoke test staying green.
- **No BouncyCastle exposure:** the two new public types use only `int` and enum members — no
  BouncyCastle types in any signature. `BouncyCastle.Cryptography` remains unreferenced by the project.

## Acceptance criteria — all met
1. ✅ Builds clean (zero warnings) across `netstandard2.0`, `net8.0`, `net10.0` under
   `TreatWarningsAsErrors`.
2. ✅ No BouncyCastle types in any public signature, base type, or support-type member.
3. ✅ XML docs present on all public types and members (enforced by CS1591-as-error).
4. ✅ No new unit tests; existing smoke test passes green (criterion 5 of the per-phase list).
5. ✅ Roadmap + plan PHASE01 status updated; this completion doc written.
6. ✅ Signature-algorithm representation decided and recorded once, in PHASE01, per the plan.
