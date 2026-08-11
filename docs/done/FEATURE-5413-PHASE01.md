# FEATURE-5413-PHASE01 — Shared PEM internals + ML-DSA PEM service

**Status:** DONE
**Type:** FEATURE (multi-phase, phase 1 of 2)
**Branch:** `feature/feature-5413-phase01-mldsa-pem` (cut from `develop` @ `51f8dc7`)

## Summary

Added PEM serialization for ML-DSA keys as a **purely additive** concern, and created the shared
internal PEM implementation that FEATURE-6852 and FEATURE-57A9 will adopt.

Two things landed:

1. **`Enigma.Core.Internal.PemEnvelope`** — the assembly's single PEM/PBES2 implementation. It is
   deliberately key-family-agnostic: it only ever handles `AsymmetricKeyParameter` and
   `PrivateKeyInfo`, so the same code serves RSA, ML-DSA and ML-KEM. It owns the encryption scheme,
   the iteration count, the read dispatch and the BouncyCastle exception mapping — each declared
   exactly once.
2. **The ML-DSA PEM service** — `IMLDsaPemService` / `MLDsaPemService` plus its factory and the
   public `MLPrivateKeyPemFormat` enum. `IMLDsaService` is untouched; nothing about the existing raw
   `byte[]` API changed.

`MLDsaServiceFactory` was re-pointed at the new shared `MLParameterSets` mapping (plan decision 6) —
the only edit to an existing product file, and a pure internal refactor.

### The seed blocker and its resolution

The plan's central finding, confirmed again here: **a FIPS 204 expanded private key does not contain
the seed it was derived from.** `MLDsaPrivateKeyParameters.FromEncoding(...).GetSeed()` returns
`null`, and `WithPreferredFormat(SeedOnly)` / `(SeedAndEncoding)` on such a key throws
`InvalidOperationException: no seed available`. A `ToPrivateKeyPem(bytes, set, format)` overload — the
shape the original brief called for — therefore cannot work: two of its three formats would be
unreachable for every key the library hands out.

The resolution shipped as planned, in two halves:

- **`ToPrivateKeyPem` takes no `format` parameter** and always writes the expanded encoding
  (`EncodingOnly`, pinned explicitly rather than relied on as a default).
- **`GenerateKeyPairPem` is where the format lives.** It generates the key internally, so the seed is
  still present when `WithPreferredFormat` is applied, and all three formats are genuinely
  producible. `Seed` is the default.

### Corrected upstream fact

`MLDsaPrivateKeyParameters.DefaultFormat` is **`SeedOnly`**, not `SeedAndEncoding` as the source
brief claimed. The observed per-instance behaviour is more subtle than a single default: a *generated*
key reports `SeedAndEncoding`, while one rebuilt via `FromEncoding` reports `EncodingOnly`. This is
why the implementation never relies on the ambient default and always states the format it wants.

## Files/modules touched

**Created — product**
- `src/Enigma.Core/Internal/PemEnvelope.cs` — the shared PEM/PBES2 implementation (new namespace
  `Enigma.Core.Internal`, deliberately neutral so `Asymmetric.Pqc` gains no dependency on
  `Asymmetric.PublicKey` — see `docs/plan/FEATURE-0D6D.md:74`).
- `src/Enigma.Core/Asymmetric/Pqc/MLParameterSets.cs` — internal two-way parameter-set mapping for
  **both** PQC families (the ML-KEM half is used by PHASE02).
- `src/Enigma.Core/Asymmetric/Pqc/MLPrivateKeyPemFormat.cs` — public enum.
- `src/Enigma.Core/Asymmetric/Pqc/IMLDsaPemService.cs`, `MLDsaPemService.cs`,
  `IMLDsaPemServiceFactory.cs`, `MLDsaPemServiceFactory.cs`.

**Created — tests**
- `tests/Enigma.Core.UnitTests/Pqc/MLDsaPemServiceTests.cs` — round-trips, formats, OID recovery,
  labels, sizes.
- `tests/Enigma.Core.UnitTests/Pqc/MLDsaPemErrorTests.cs` — nulls, undefined enums, malformed PEMs,
  wrong-key-family PEMs, wrong-length keys, password paths, no-BouncyCastle-exception guard.
- `tests/Enigma.Core.UnitTests/Pqc/MLDsaPemServiceFactoryTests.cs` — factory/service shape and the
  exported-surface list.

**Modified**
- `src/Enigma.Core/Asymmetric/Pqc/MLDsaServiceFactory.cs` — its private `ToBcParameters` switch
  deleted; now calls `MLParameterSets.ToBcParameters`. No behaviour change; its existing tests pass
  untouched.
- `docs/guides/pqc.md` — new `## PEM serialization` section with an `### ML-DSA key PEM` subsection
  (envelope table, format table, signatures, three runnable samples) plus an error-handling table and
  a note in `## Notes`. PHASE02 slots `### ML-KEM key PEM` in alongside.
- `docs/roadmap.md` — `FEATURE-5413` + `PHASE01` → `IN PROGRESS` → `DONE` (PHASE01); the item row
  stays `IN PROGRESS` pending PHASE02. The whole table was re-padded to the current widest cell, per
  the dev-workflow table-formatting rule.
- `docs/plan/FEATURE-5413.md` — item and PHASE01 statuses updated.
- `CLAUDE.md` — project-layout tree gained the new `Internal/` line and a PEM note on
  `Asymmetric/Pqc/` (documentation freshness sweep).
- `README.md` — the PQC feature bullet now mentions ML-DSA PEM import/export and parameter-set
  recovery (documentation freshness sweep). Deliberately scoped to **ML-DSA**, since ML-KEM PEM lands
  in PHASE02; PHASE02 should generalize the wording.

**Not modified (deliberately)**
- `IMLDsaService` / `MLDsaService` / `IMLKemService` / `MLKemService` — signatures and behaviour
  untouched, as the plan requires.
- `src/Enigma.Core/Asymmetric/PublicKey/PemUtils.cs` — untouched (plan decision 3). It keeps its own
  exception mapping until FEATURE-6852-PHASE01 re-points it; doing that here would change the RSA
  encrypted-write format inside an item billed as non-breaking.
- `MLKemServiceFactory.cs` — still holds its own mapping switch; PHASE02 re-points it.
- No test-project `.csproj` edit was needed (no new fixture files; the wrong-key-family PEMs are
  generated at test time).

## Build/test evidence

```
dotnet build Enigma.Core.slnx -c Release
  Build succeeded.  0 Warning(s)  0 Error(s)
  → netstandard2.0, net8.0, net10.0

dotnet test --solution Enigma.Core.slnx -c Release
  Test run summary: Passed!
  total: 3400   failed: 0   succeeded: 3400   skipped: 0
  → net8.0 and net10.0
```

**3280 → 3400 tests** (+120 = **60 new test cases × 2 test TFMs**). Targeted re-run,
`--filter-class '*MLDsaPem*'`: **120 passed, 0 failed** across both TFMs.

### PBES2 output verified on the wire

The emitted `ENCRYPTED PRIVATE KEY` envelope was decoded and its algorithm identifiers read back, to
confirm the constants are the ones that actually reach the file:

| Field | Value |
|---|---|
| Outer scheme | `1.2.840.113549.1.5.13` (PBES2) |
| KDF | `1.2.840.113549.1.5.12` (PBKDF2) |
| Iterations | **600000** |
| Salt | **16 bytes** |
| PRF | `1.2.840.113549.2.9` (hmacWithSHA256) |
| Cipher | `2.16.840.1.101.3.4.1.42` (aes256-CBC) |

### Guide samples verified by compilation *and* execution

All three runnable snippets in the new `docs/guides/pqc.md` section were extracted, compiled against
the built `Enigma.Core.dll` (`LangVersion=14`, `Nullable=enable`, `ImplicitUsings=disable` — matching
the repo's settings) and **run**: zero warnings, zero errors, and the signing sample prints
`Signature valid: True`. The two signature-listing blocks were diffed against a reflection dump of
the real interfaces and match verbatim.

## Acceptance criteria

1. ✔ `PemEnvelope` exists, is `internal`, and is the **only** place in the assembly naming
   `EncryptedPrivateKeyInfoFactory` or holding an iteration-count constant
   (`Pbkdf2IterationCount = 600_000`) — both verified by grep over `src/`. It is also the only **new**
   exception-mapping implementation; `PemUtils` keeps its own until FEATURE-6852-PHASE01, as planned.
2. ✔ Verified by inspection (no `InternalsVisibleTo`, so not assertable here). The mapping helper
   `ReadMappingFailures` has exactly the four branches in the specified order —
   `PasswordException` → `InvalidCipherTextException` → `PemException` → `IOException` — and both
   readers unwrap `AsymmetricCipherKeyPair` with the specified arm ordering
   (`pair.Private` first in `ReadPrivateKey`; `AsymmetricKeyParameter { IsPrivate: false }` first in
   `ReadPublicKey`). The type hierarchy that makes the order load-bearing was re-confirmed against
   2.7.0: `OpenSsl.PasswordException : Security.PasswordException : IOException`,
   `OpenSsl.PemException : IOException`, `OpenSsl.EncryptionException : Security.EncryptionException :
   IOException`.
3. ✔ Public surface added is exactly `MLPrivateKeyPemFormat`, `IMLDsaPemService`, `MLDsaPemService`,
   `IMLDsaPemServiceFactory`, `MLDsaPemServiceFactory`; signatures confirmed against the plan by
   reflection dump; all XML-documented; factory and service both parameterless and `new`-constructible
   (asserted in `MLDsaPemServiceFactoryTests`).
4. ✔ `ToPrivateKeyPem` has no `format` parameter.
5. ✔ `GenerateKeyPairPem_EveryFormat_RoundTripsToASigningKey` — `[Theory]`, 3 parameter sets × 3
   formats: bytes come back at the expanded FIPS length and sign/verify through `IMLDsaService`
   against the public key from `FromPublicKeyPem`.
6. ✔ `ToPem_FromPem_ReturnsByteIdenticalKeys` — all three sets, private **and** public halves
   byte-identical.
7. ✔ Parameter set recovered correctly for all three sets from public, private and **encrypted**
   private PEMs (`FromPrivateKeyPem_EncryptedPem_RecoversParameterSetAndKey`).
8. ✔ Encrypted round-trip succeeds; wrong password → `CryptographicException`; encrypted PEM with
   `password: null` → `CryptographicException`; the caller's array is unchanged after all four
   password-taking calls (`EncryptedPem_RoundTrips_AndNeverClearsTheCallersPassword`).
9. ✔ Labels are exactly `-----BEGIN PUBLIC KEY-----`, `-----BEGIN PRIVATE KEY-----`,
   `-----BEGIN ENCRYPTED PRIVATE KEY-----`, and the encrypted PEM contains no `Proc-Type` or
   `DEK-Info` (`EncryptedPrivateKeyPem_IsPkcs8_NotALegacyOpenSslHybrid`).
10. ✔ `Seed` ML-DSA-65 PEM is 128 chars (< 200); `ExpandedKey` is 5555 (> 5000); `SeedAndExpandedKey`
    is 5604 and asserted larger than `ExpandedKey`. See the deviation note on these figures below.
11. ✔ All eight wrong-input cases → `ArgumentException` with `ParamName` asserted: private-for-public,
    public-for-private, ML-KEM PEM, RSA PEM, truncated PEM, empty string, whitespace-only, non-PEM
    text — plus invalid base64 and an `ENCRYPTED PRIVATE KEY` label over non-EPKI DER.
12. ✔ Every `null` argument → `ArgumentNullException` (4 tests); every undefined enum value →
    `ArgumentOutOfRangeException` (4 tests, covering both enums on all entry points).
13. ✔ `NoPublicMethod_LeaksABouncyCastleExceptionType` walks seven failure paths and asserts the
    surfaced type's namespace is not `Org.BouncyCastle.*` and is an `ArgumentException` or
    `CryptographicException`.
14. ✔ `Pqc/PqcBouncyCastleIsolationTests` and `Api/BouncyCastleIsolationTests` green with the five new
    exported types. Both guards filter by namespace/assembly, so they covered the new types with no
    test edit.
15. ✔ `MLDsaServiceFactory`'s existing tests pass untouched, and the duplication is gone:
    `MLDsaServiceFactory` contains no parameter-set switch of its own, and
    `MLDsaParameters.ml_dsa_` appears in exactly one product file,
    `src/Enigma.Core/Asymmetric/Pqc/MLParameterSets.cs` (verified by grep over `src/`).
16. ✔ `docs/guides/pqc.md` documents the ML-DSA PEM API; every sample compiles and runs (see above).
17. ✔ This document.

## Deviations & follow-ups

- **PEM character counts differ from the plan's figures, by line ending only.** The plan quotes
  132 / 5642 / 5692 characters for the three ML-DSA-65 formats; measured here they are
  **128 / 5555 / 5604**. The difference is exactly one `\r` per line (4, 87 and 88 lines
  respectively) — the plan's numbers were measured on CRLF, this repo is `eol=lf`. The underlying
  PKCS#8 DER bodies (54 / 4060 / 4098 bytes) are identical and platform-independent.
  Consequences: the acceptance thresholds (< 200, > 5000) hold on both; the tests assert thresholds
  and relative ordering rather than exact equalities, so they stay green on either platform; and the
  XML docs and guide quote the **DER byte sizes** as exact and PEM character counts as approximate
  ("roughly 130 characters"), rather than pinning a platform-specific figure as the plan's design
  step 4 literally specified.
- **One helper added beyond the plan's `PemEnvelope` sketch:** `ParseEncryptedPrivateKeyInfo`. A
  well-formed `ENCRYPTED PRIVATE KEY` envelope whose payload is not a valid `EncryptedPrivateKeyInfo`
  makes BouncyCastle raise a bare `System.ArgumentException` with **no** `ParamName`, which would
  have violated the "malformed PEM → `ArgumentException` with `paramName`" row of the exception
  contract. The helper re-wraps it with the caller's parameter name. This is deliberately kept
  *outside* `ReadMappingFailures`, so the shared mapper still has exactly the four specified branches
  in the specified order (criterion 2) and FEATURE-6852 inherits it unchanged.
- **`MLParameterSets.FromBcParameters` takes an extra `paramName` argument** beyond the plan's
  shorthand signature (`FromBcParameters(MLDsaParameters)`). Needed so the "unsupported parameter set"
  `ArgumentException` can name the caller's parameter, per the exception contract. It is an internal
  helper, so this is not a public-surface change. The read direction uses `ReferenceEquals` against
  BouncyCastle's static parameter instances — verified to hold across a full PEM round trip, and it is
  what distinguishes `ml_dsa_65` from the pre-hash `ml_dsa_65_with_sha512` that shares its security
  level.
- **RSA-specific paths in `PemEnvelope` are written but not yet asserted**, exactly as the plan
  anticipated: the `AsymmetricCipherKeyPair` unwrap and mapping branches 1 and 4 are only reachable
  through an RSA PEM, and this phase ships no public RSA path through `PemEnvelope`. They are written
  to specification so FEATURE-6852-PHASE01 can adopt `PemEnvelope` without re-opening it, and are
  covered there by that phase's acceptance criteria 3, 6 and 11. The
  `WritePrivateKeyPem(AsymmetricKeyParameter, char[])` overload is likewise unused until that phase.
- **`docs/pem-work-brief.md` (the untracked source brief) is not present in the working tree.** It was
  never tracked, so nothing is missing from the repository; the plan is self-contained and was the
  contract used here.
- **Line endings:** no CRLF noise in any touched file — all LF, and `.gitattributes` already enforces
  `eol=lf`. No recommendation applies.
- **PHASE02 (ML-KEM PEM service) is next.** It should be a close mirror of this phase: `PemEnvelope`
  needs no change (it never sees an algorithm-specific type), `MLPrivateKeyPemFormat` is reused as-is,
  and the ML-KEM half of `MLParameterSets` is already written and waiting. The remaining work is the
  four ML-KEM files, re-pointing `MLKemServiceFactory` at `MLParameterSets`, the test mirror with
  `Encapsulate`/`Decapsulate` cross-use in place of sign/verify, and the guide's
  `### ML-KEM key PEM` subsection.
- **A note for PHASE02's format mapping:** the `MLPrivateKeyPemFormat` → BouncyCastle `Format` switch
  cannot be shared between the families. `MLDsaPrivateKeyParameters.Format` and
  `MLKemPrivateKeyParameters.Format` are two distinct nested enum types, so `MLKemPemService` needs
  its own private `ToBcFormat`. This is unavoidable without generics and is not drift.
