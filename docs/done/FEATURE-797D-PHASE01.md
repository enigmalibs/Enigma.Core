# FEATURE-797D-PHASE01 — Upgrade to BouncyCastle 2.7.0

**Status:** DONE
**Type:** FEATURE (multi-phase, phase 1 of 2)
**Branch:** `feature/feature-797d-phase01-bouncycastle-270` (cut from `develop` @ `21ff121`)

## Summary

Moved Enigma.Core's runtime dependency from **BouncyCastle.Cryptography 2.6.2 → 2.7.0** and proved
nothing broke, with particular attention to ML-KEM and ML-DSA.

The upgrade forced exactly two source edits, both caused by the repo's zero-warning gate
(`TreatWarningsAsErrors=true`) turning BouncyCastle deprecations into hard build failures:

1. **CS0104 (ambiguous reference), `src/…/PemUtils.cs`.** 2.7.0 introduces
   `Org.BouncyCastle.OpenSsl.PasswordException` and demotes `Org.BouncyCastle.Security.PasswordException`
   to its `[Obsolete]` base. `PemUtils` imports both namespaces, so the unqualified `catch
   (PasswordException ex)` became ambiguous. Resolved with a `using` alias binding explicitly to the
   **OpenSsl** type — binding to the `Security` one instead would raise CS0618 and fail the build.
2. **CS0618 (obsolete member), `tests/…/CertificateInfoTests.cs`.** `new DerInteger(int)` is obsolete
   (*"Use ValueOf instead."*); replaced with `DerInteger.ValueOf(1)`. The DER payload is byte-identical,
   so the malformed-SAN fixture's intent is preserved.

Three test additions were made in the same phase, per the plan's design decisions:

- **PQC encoding-contract tests** (new, two classes). The pre-existing fixed-vector tests prove a
  *pinned* key still works; they would not catch `GenerateKeyPair` starting to return a **seed**
  instead of the **expanded** encoding — a change that still round-trips while breaking every
  previously persisted key. Since 2.7.0 adds `MLDsaPrivateKeyParameters.DefaultFormat = SeedOnly`
  upstream, the XML-doc promise is now an enforced assertion.
- **PEM characterization test** (1). Pins the current mapping for an unsupported `DEK-Info` cipher.
  Per decision 5, `PemUtils` deliberately gained **no** new `catch` clause; the existing behaviour is
  pinned instead so future BouncyCastle drift on that path shows up as a red test.

Also bumped `coverlet.collector` 6.0.4 → **10.0.1** (test-only, `PrivateAssets=all`, never
redistributed).

## Files/modules touched

**Modified**
- `Directory.Packages.props` — `BouncyCastle.Cryptography` 2.6.2 → 2.7.0; `coverlet.collector`
  6.0.4 → 10.0.1. No `Version=` attribute on any `PackageReference` (CPM intact).
- `src/Enigma.Core/Asymmetric/PublicKey/PemUtils.cs` — **+3 lines only** (a commented `using
  PasswordException = Org.BouncyCastle.OpenSsl.PasswordException;` alias). Line 67's
  `catch (PasswordException ex)` is unchanged. This is the phase's **entire** product-code diff.
- `tests/Enigma.Core.UnitTests/Certificates/CertificateInfoTests.cs` — `new DerInteger(1)` →
  `DerInteger.ValueOf(1)` (1 line).
- `tests/Enigma.Core.UnitTests/PublicKey/RsaArgumentValidationTests.cs` — added
  `PrivateKeyOperation_UnsupportedDekAlgorithm_ThrowsArgumentException`.
- `docs/roadmap.md` — `FEATURE-797D` + `PHASE01` `TODO` → `IN PROGRESS` → `DONE` (PHASE01);
  the item row stays `IN PROGRESS` pending PHASE02.
- `docs/plan/FEATURE-797D.md` — item and PHASE01 statuses updated.

**Created**
- `tests/Enigma.Core.UnitTests/Pqc/MLKemEncodingContractTests.cs`
- `tests/Enigma.Core.UnitTests/Pqc/MLDsaEncodingContractTests.cs`
- `docs/done/FEATURE-797D-PHASE01.md` — this completion record.

**Not modified (deliberately)**
- Every PQC fixture (`kem1024_{A,B}_private.key`, `dsa87_{A,B}_public.key`, `encapsulation.bin`,
  `secret.bin`, `signature.bin`, `message.txt`) is **byte-identical** — verified via `git status`.
  They are the cross-version compatibility evidence and had to pass unmodified.
- No other `src/` file. No version bump, no release documentation — that is PHASE02.

## ML-KEM / ML-DSA cross-version evidence

All re-verified at build time in the repository (not carried over from planning):

| Claim | Build-time evidence |
|---|---|
| **API additive-only** — nothing we depend on was removed or obsoleted | Release build clean, **0 warnings**, all three TFMs. The only two deprecations the whole solution hit were the `PasswordException` ambiguity and `DerInteger` — neither in PQC code. |
| **Encodings unchanged (backward)** — material persisted by 1.0.0 still works | `MLKemFixedVectorTests` + `MLDsaFixedVectorTests` pass against **byte-identical, unmodified** fixtures: the 2.6.2-era ML-KEM-1024 key A recovers `secret.bin` from `encapsulation.bin`, unrelated key B does not, and the pinned ML-DSA-87 signature still verifies. |
| **Encodings unchanged (forward)** — 2.7.0 still emits expanded keys, not seeds | New `MLKemEncodingContractTests` / `MLDsaEncodingContractTests` pass for **all six** parameter sets at the exact FIPS sizes: KEM 512/768/1024 → pub 800/1184/1568, priv 1632/2400/3168, ct 768/1088/1568, secret 32; DSA 44/65/87 → pub 1312/1952/2592, priv 2560/4032/4896. |
| **`DefaultFormat = SeedOnly` does not leak into this library** | The not-a-seed assertions (private key length ≠ 32 and ≠ 64) pass for all six sets. `DefaultFormat` governs BouncyCastle's PKCS#8/ASN.1 serialization default, not the raw `GetEncoded()` path this library uses. |
| **No BouncyCastle type on the public surface** | `Api/BouncyCastleIsolationTests` and every per-category isolation test green. |

Targeted re-run (net10.0): `-class '*EncodingContractTests' -class '*FixedVectorTests'
-class '*BouncyCastleIsolationTests'` → **27 passed, 0 failed**; the new PEM characterization test
→ **1 passed**.

## Build/test evidence

```
dotnet build Enigma.Core.slnx -c Release
  Build succeeded.  0 Warning(s)  0 Error(s)
  → netstandard2.0, net8.0, net10.0

dotnet test --solution Enigma.Core.slnx -c Release
  Test run summary: Passed!
  total: 3280   failed: 0   succeeded: 3280   skipped: 0
  → net8.0 and net10.0
```

**3254 → 3280 tests** (+26 = 13 new tests × 2 test TFMs): 12 PQC encoding-contract cases (6 size +
6 not-a-seed) and 1 PEM characterization test.

Resolved versions confirmed in both projects' `project.assets.json`:
`BouncyCastle.Cryptography/2.7.0`, `coverlet.collector/10.0.1`.

## Acceptance criteria

1. ✔ `Directory.Packages.props` pins BouncyCastle 2.7.0 + coverlet.collector 10.0.1; no `Version=`
   on any `PackageReference` (grepped across all `.csproj`/`.props` — none).
2. ✔ Release build, 0 warnings, all three TFMs.
3. ✔ Full suite green on net8.0 and net10.0 — 3280/3280, 0 failures.
4. ✔ Both encoding-contract classes pass for all six parameter sets, not-a-seed assertions included.
5. ✔ Both fixed-vector classes pass with byte-identical fixtures — no `*.key`, `*.bin` or
   `message.txt` regenerated or modified.
6. ✔ The unsupported-DEK characterization test passes.
7. ✔ `Api/BouncyCastleIsolationTests` and all per-category isolation tests green.
8. ✔ `PemUtils` gained no new `catch` clause (5 before, 5 after); the `PasswordException` binding is
   the only product-code change.
9. ✔ This document.

## Deviations & follow-ups

- **No deviation from the plan.** Both predicted compile breaks occurred exactly at the predicted
  locations with the predicted error codes; no third break appeared, and no unplanned edit was needed.
- **Line endings:** no CRLF noise in any touched file — all LF, `.gitattributes` already enforces
  `eol=lf`. No recommendation applies.
- **`coverlet.collector` 10.0.1 — restored and built cleanly, suite green, `PrivateAssets=all` so it
  never enters the package.** Worth noting for a future item (not a regression from this bump): under
  the MTP-native runner there is no wired-up coverage-collection command in this repo, and
  `dotnet test --coverage` is not a recognised option here — `coverlet.collector` is a VSTest
  datacollector, so with `Microsoft.NET.Test.Sdk` absent it is effectively inert. That is
  **pre-existing** and unchanged by the bump, but it means the 6 → 10 transition is verified by
  restore + build + a green suite rather than by an actual coverage run. If coverage reporting is
  ever wanted, wiring it (e.g. `Microsoft.Testing.Extensions.CodeCoverage`) is its own work item.
- **`Directory.Packages.props` header comment is stale** — it still reads *"BouncyCastle/System.Buffers
  are referenced by the real implementation features later, NOT at skeleton stage."* Left untouched
  (out of this phase's scope); a one-line cleanup for whenever that file is next opened.
- **PHASE02 (release v1.1.0) is next** — version bump, release notes, doc version refreshes and
  pack-verify. Note that this phase already makes the dependency floor `>= 2.7.0` binding: the
  assembly now references `OpenSsl.PasswordException`, which does not exist in 2.6.x.
