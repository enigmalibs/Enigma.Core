# FEATURE-5413-PHASE02 — ML-KEM PEM service

**Status:** DONE
**Type:** FEATURE (multi-phase, phase 2 of 2 — completes `FEATURE-5413`)
**Branch:** `feature/feature-5413-phase02-mlkem-pem` (cut from `feature/feature-5413-phase01-mldsa-pem` @ `4a0c03d`)

## Summary

Added PEM serialization for ML-KEM keys, completing the PQC PEM item. The phase is what the plan
predicted it would be: a **close mirror of PHASE01 with no new infrastructure**. Every shared piece
built in PHASE01 was reused exactly as-is —

- `PemEnvelope` — **not touched** (byte-identical to `4a0c03d`). It never sees an algorithm-specific
  type, so the ML-KEM family needed no branch in it. This is the phase's real result: the claim that
  the shared PEM code is family-agnostic stopped being a design intention and became a measured fact.
- `MLParameterSets` — **not touched**. Its ML-KEM half was written in PHASE01 and was waiting.
- `MLPrivateKeyPemFormat` — **reused**, not duplicated. One enum serves both families.

The new work was the four ML-KEM files, re-pointing `MLKemServiceFactory` at `MLParameterSets`
(finishing the de-duplication PHASE01 started on the ML-DSA side), the test mirror, and the guide
section. `IMLKemService` is untouched; nothing about the existing raw `byte[]` API changed.

### Confirmed: the seed blocker applies identically to ML-KEM

The BouncyCastle surface was re-probed against 2.7.0 before building.
`MLKemPrivateKeyParameters` carries the same nested `Format` enum (`SeedOnly`, `EncodingOnly`,
`SeedAndEncoding`), the same `WithPreferredFormat`, and the same seedless-rebuild behaviour as its
ML-DSA counterpart. The PHASE01 resolution therefore transfers unchanged: `ToPrivateKeyPem` takes no
`format` argument and pins `EncodingOnly`; `GenerateKeyPairPem` owns the format choice because it
generates the key while the seed still exists.

`MLKemParameters` publishes exactly three statics (`ml_kem_512/768/1024`) — there is no pre-hash
variant as there is for ML-DSA, so `MLParameterSets.FromBcParameters(MLKemParameters, …)` has no
reachable "unsupported parameter set" case today. It is kept anyway, symmetric with the ML-DSA half
and defensive against an upstream addition.

## Files/modules touched

**Created — product**
- `src/Enigma.Core/Asymmetric/Pqc/IMLKemPemService.cs`
- `src/Enigma.Core/Asymmetric/Pqc/MLKemPemService.cs`
- `src/Enigma.Core/Asymmetric/Pqc/IMLKemPemServiceFactory.cs`
- `src/Enigma.Core/Asymmetric/Pqc/MLKemPemServiceFactory.cs`

**Created — tests**
- `tests/Enigma.Core.UnitTests/Pqc/MLKemPemServiceTests.cs` — round-trips over all three parameter
  sets × all three formats, `Encapsulate`/`Decapsulate` cross-use, OID recovery, labels, sizes.
- `tests/Enigma.Core.UnitTests/Pqc/MLKemPemErrorTests.cs` — nulls, undefined enums, malformed PEMs,
  wrong-key-family PEMs, wrong-length keys, password paths, no-BouncyCastle-exception guard.
- `tests/Enigma.Core.UnitTests/Pqc/MLKemPemServiceFactoryTests.cs` — factory/service shape, exported
  surface, and the shared-`MLPrivateKeyPemFormat` assertion.

**Modified**
- `src/Enigma.Core/Asymmetric/Pqc/MLKemServiceFactory.cs` — its private `ToBcParameters` switch
  deleted; now calls `MLParameterSets.ToBcParameters`. No behaviour change; its existing tests pass
  untouched.
- `tests/Enigma.Core.UnitTests/Pqc/MLDsaPemErrorTests.cs` — its ML-KEM wrong-family fixture now uses
  the real `IMLKemPemService` instead of test-only BouncyCastle (see *Deviations*).
- `docs/guides/pqc.md` — new `### ML-KEM key PEM` subsection (size table, signatures, two runnable
  samples), three new rows in the key-types table, and the `## Notes` PEM bullet generalized to both
  families.
- `docs/roadmap.md` — `PHASE02` → `IN PROGRESS` → `DONE`, and the `FEATURE-5413` item row → `DONE`.
  The whole table was re-padded per the dev-workflow table-formatting rule: with no `IN PROGRESS` row
  left anywhere, the Status column narrowed from 11 to 6 characters on **every** row.
- `docs/plan/FEATURE-5413.md` — item and PHASE02 statuses updated.
- `README.md` — the PQC feature bullet now reads "Both families also have PEM import/export" rather
  than naming ML-DSA alone (documentation freshness sweep). PHASE01 scoped that line to ML-DSA
  deliberately and flagged it for this phase to generalize.

**Not modified (deliberately)**
- `src/Enigma.Core/Internal/PemEnvelope.cs` — **byte-identical to PHASE01**, verified by
  `git diff 4a0c03d`. Acceptance criterion 5.
- `src/Enigma.Core/Asymmetric/Pqc/MLParameterSets.cs` — unchanged; its ML-KEM half already existed.
- `src/Enigma.Core/Asymmetric/Pqc/MLPrivateKeyPemFormat.cs` — unchanged and reused as-is.
- `IMLKemService` / `MLKemService` / `IMLDsaService` / `MLDsaService` — signatures and behaviour
  untouched.
- `src/Enigma.Core/Asymmetric/PublicKey/PemUtils.cs` — still out of scope; FEATURE-6852-PHASE01
  re-points it at `PemEnvelope`.
- `docs/guides/README.md` — its PQC entry describes the module ("ML-KEM key encapsulation and ML-DSA
  signatures"), which is still accurate; PEM is a sub-capability the entry never enumerated. Plan
  scope said "only if the PQC index entry's description changes" — it did not.
- No test-project `.csproj` edit needed (no new fixture files).

## Build/test evidence

```
dotnet build Enigma.Core.slnx -c Release
  Build succeeded.  0 Warning(s)  0 Error(s)
  → netstandard2.0, net8.0, net10.0

dotnet test --solution Enigma.Core.slnx -c Release
  Test run summary: Passed!
  total: 3522   failed: 0   succeeded: 3522   skipped: 0
  → net8.0 and net10.0
```

**3400 → 3522 tests** (+122 = **61 new test cases × 2 test TFMs**). Targeted re-run,
`--filter-class '*Pem*'` (both families, to prove the ML-DSA suite still passes after its fixture
change): **254 passed, 0 failed** across both TFMs.

### Measured ML-KEM-768 sizes

Measured on the built assembly, and the source of the guide's size table:

| Format | PKCS#8 DER | PEM (LF) |
|---|---:|---:|
| `Seed` | 86 B | 172 chars |
| `ExpandedKey` | 2,428 B | 3,345 chars |
| `SeedAndExpandedKey` | 2,498 B | 3,439 chars |

The DER sizes match the plan's measured figures exactly. Criterion 3's thresholds hold with room:
172 < 250, and 3,345 > 2,000.

### PBES2 output verified on the wire

The emitted ML-KEM `ENCRYPTED PRIVATE KEY` envelope was decoded and its algorithm identifiers read
back. They are **identical to the ML-DSA figures recorded in PHASE01** — the direct evidence that
`PemEnvelope` treats the two families the same way:

| Field | Value |
|---|---|
| Outer scheme | `1.2.840.113549.1.5.13` (PBES2) |
| KDF | `1.2.840.113549.1.5.12` (PBKDF2) |
| Iterations | **600000** |
| Salt | **16 bytes** |
| PRF | `1.2.840.113549.2.9` (hmacWithSHA256) |
| Cipher | `2.16.840.1.101.3.4.1.42` (aes256-CBC) |

### Guide samples verified by compilation *and* execution

Both runnable snippets in the new `### ML-KEM key PEM` section were extracted verbatim, compiled
against the built `Enigma.Core.dll` (`LangVersion=14`, `Nullable=enable`, `ImplicitUsings=disable`,
`TreatWarningsAsErrors=true` — matching the repo's settings) and **run**: zero warnings, zero errors.
The encapsulation sample prints `Secrets match: True`; the serialization sample confirms both halves
round-trip byte-identically. The two signature-listing blocks were diffed against a reflection dump
of the real interfaces and match verbatim.

## Acceptance criteria

1. ✔ Public surface added is exactly `IMLKemPemService`, `MLKemPemService`, `IMLKemPemServiceFactory`,
   `MLKemPemServiceFactory`, mirroring the ML-DSA contract with `MLKemParameterSet` (signatures
   confirmed by reflection dump); all XML-documented; factory and service both parameterless and
   `new`-constructible. `MLPrivateKeyPemFormat` is **reused** — asserted by
   `PrivateKeyPemFormat_IsSharedBetweenBothFamilies_NotDuplicated`, which pins that exactly one such
   exported enum exists and that both families' `GenerateKeyPairPem` bind to that same type.
2. ✔ PHASE01 criteria 5-14 hold for ML-KEM, with `Encapsulate`/`Decapsulate` cross-use replacing
   sign/verify:
   - **5** — `GenerateKeyPairPem_EveryFormat_RoundTripsToADecapsulatingKey`, `[Theory]` over 3
     parameter sets × 3 formats: bytes come back at the expanded FIPS 203 length, and the secret
     encapsulated against the recovered public key equals the one the recovered private key
     decapsulates. (Equality is the load-bearing assertion here: FIPS 203 implicit rejection means a
     wrong-but-well-formed key returns a *different* secret rather than throwing.)
   - **6** — `ToPem_FromPem_ReturnsByteIdenticalKeys`, all three sets, both halves.
   - **7** — parameter set recovered for all three sets from public, private and **encrypted**
     private PEMs.
   - **8** — encrypted round-trip succeeds; wrong password → `CryptographicException`; encrypted PEM
     with `password: null` → `CryptographicException`; the caller's array is unchanged after all four
     password-taking calls.
   - **9** — labels are exactly the three expected ones, and the encrypted PEM carries no `Proc-Type`
     or `DEK-Info`.
   - **11** — private-for-public, public-for-private, **ML-DSA** PEM, RSA PEM, truncated PEM, empty
     string, whitespace-only, non-PEM text, invalid base64, and an `ENCRYPTED PRIVATE KEY` label over
     non-EPKI DER → all `ArgumentException` with `ParamName` asserted.
   - **12** — every `null` argument → `ArgumentNullException` (4 tests); every undefined enum value →
     `ArgumentOutOfRangeException` (4 tests, both enums).
   - **13** — `NoPublicMethod_LeaksABouncyCastleExceptionType` walks seven failure paths.
   - **14** — `Pqc/PqcBouncyCastleIsolationTests` and `Api/BouncyCastleIsolationTests` green with the
     four new exported types; both filter by namespace/assembly, so no test edit was needed.
   - **10** — superseded by PHASE02 criterion 3 (the ML-KEM thresholds), below.
3. ✔ A `Seed`-format ML-KEM-768 private-key PEM is **172 chars** (< 250); an `ExpandedKey` one is
   **3,345** (> 2,000); `SeedAndExpandedKey` (3,439) is asserted larger than `ExpandedKey`.
4. ✔ `MLKemServiceFactory`'s existing tests pass untouched, and it contains no mapping switch of its
   own: `MLKemParameters.ml_kem_` appears in exactly one product file,
   `src/Enigma.Core/Asymmetric/Pqc/MLParameterSets.cs` (verified by grep over `src/`).
5. ✔ `PemEnvelope` gained no ML-KEM-specific branch — it is **byte-identical** to its PHASE01 state
   (`git diff 4a0c03d -- src/Enigma.Core/Internal/PemEnvelope.cs` is empty). Corroborated
   behaviourally by the PBES2 wire dump above matching PHASE01's ML-DSA figures field for field.
6. ✔ `docs/guides/pqc.md` covers both families; both new samples compile and run.
   `docs/guides/README.md` deliberately not updated — its PQC entry's description did not change (see
   *Not modified*).
7. ✔ This document; `FEATURE-5413`'s roadmap row flipped to `DONE` alongside `PHASE02`.

## Deviations & follow-ups

- **One file was changed beyond the plan's in-scope table: `MLDsaPemErrorTests.cs`.** Its
  "a valid PEM of the wrong key family" fixture built ML-KEM PEMs directly with BouncyCastle through
  eight `Bc*` aliases, because PHASE01 shipped no ML-KEM PEM service — a limitation the file's own
  header comment flagged and attributed to PHASE02. That service now exists, so the fixture calls it
  instead: eight aliases and a local `WritePem` helper deleted, test-only BouncyCastle use removed
  from the file entirely, and the fixture is now exactly the PEM a real user would hand over. What is
  asserted is unchanged, and the ML-DSA suite passes untouched otherwise. Recorded here because the
  plan's PHASE02 scope table did not list the file.
- **The two PEM services share no code beyond `PemEnvelope` and `MLParameterSets`, by necessity.**
  `MLDsaPrivateKeyParameters.Format` and `MLKemPrivateKeyParameters.Format` are distinct nested enum
  types with no common base, so each service keeps its own three-arm `ToBcFormat`. PHASE01's
  completion doc anticipated this exactly; it is unavoidable without generics and is not drift. The
  same applies to the `FromEncoding` / `WithPreferredFormat` calls, which are static members of
  family-specific types.
- **`MLParameterSets.FromBcParameters(MLKemParameters, …)` has no reachable failure branch today.**
  BouncyCastle 2.7.0 publishes only the three `ml_kem_*` statics the library already exposes, so the
  "unsupported parameter set" `ArgumentException` cannot currently be triggered from an ML-KEM PEM
  (unlike the ML-DSA side, where the pre-hash `ml_dsa_*_with_sha512` sets make it live). It is kept
  for symmetry and to fail safe if upstream adds a variant.
- **Line endings:** no CRLF noise in any touched file — all LF, and `.gitattributes` already enforces
  `eol=lf`. No recommendation applies.
- **`FEATURE-5413` is now complete.** The next items in the roadmap, `FEATURE-6852` and
  `FEATURE-57A9`, are the ones that adopt `PemEnvelope` for RSA. Two notes for
  **FEATURE-6852-PHASE01** specifically:
  - `PemEnvelope`'s RSA-only paths (the `AsymmetricCipherKeyPair` unwrap in both readers, exception
    mapping branches 1 and 4, and the `WritePrivateKeyPem(AsymmetricKeyParameter, char[])` overload)
    are still written-but-unasserted — two phases of PQC work have not exercised them. They remain
    covered by that phase's acceptance criteria 3, 6 and 11.
  - That phase also owns re-pointing `PemUtils` at `PemEnvelope` and asserting **assembly-wide**
    uniqueness of the exception mapping (its criterion 10). Until then, `PemUtils` still holds a
    second copy of that mapping — the one remaining duplication this item set out to eliminate.
