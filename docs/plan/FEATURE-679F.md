# FEATURE-679F — KeyDerivation implementation (PBKDF2 + Argon2)

- **Status:** DONE
- **Type:** FEATURE (single-phase)
- **Depends on:** FEATURE-26A5 (hashing — PRF/HMAC alignment + shared harness); transitively FEATURE-61D1
- **Suggested branch (at build):** `feature/feature-679f-keyderivation`
- **Basis:** ported from Enigma.Cryptography v5.0.0 (`/home/jo/Dev/Enigma.Cryptography`); redesign decisions validated by user 2026-07-21.

## Objective
Implement the two in-memory key-derivation services behind the FROZEN `Enigma.Core.KeyDerivation` contract by porting the working logic from Enigma.Cryptography v5.0.0 `KDF/`, keeping BouncyCastle strictly internal. Fill the four sealed stubs (`Pbkdf2Service`, `Pbkdf2ServiceFactory`, `Argon2Service`, `Argon2ServiceFactory`), AMEND the frozen `Pbkdf2Prf` enum to restore `HmacSha384` (the one dropped capability for this feature, restored per the maximum-fidelity directive), and port the test vectors to the new API.

## Basis — port from Enigma.Cryptography v5.0.0
Exact old source files (from the spec's oldToNewMapping):
- `src/Enigma.Cryptography/KDF/IPbkdf2Service.cs`, `src/Enigma.Cryptography/KDF/Pbkdf2Service.cs`
- `src/Enigma.Cryptography/KDF/IPbkdf2ServiceFactory.cs`, `src/Enigma.Cryptography/KDF/Pbkdf2ServiceFactory.cs`
- `src/Enigma.Cryptography/KDF/Pbkdf2Prf.cs`
- `src/Enigma.Cryptography/KDF/IArgon2Service.cs`, `src/Enigma.Cryptography/KDF/Argon2Service.cs`
- `src/Enigma.Cryptography/KDF/IArgon2ServiceFactory.cs`, `src/Enigma.Cryptography/KDF/Argon2ServiceFactory.cs`
- `src/Enigma.Cryptography/KDF/Argon2Variant.cs`, `src/Enigma.Cryptography/KDF/Argon2Version.cs`
- Tests: `src/UnitTests/KDF/Pbkdf2ServiceTests.cs`, `src/UnitTests/KDF/Argon2IdTests.cs`, `src/UnitTests/KDF/pbkdf2.csv`, `src/UnitTests/Infrastructure/CsvData.cs`

## Scope & mapping
| Old | New home | Disposition | Note |
|-----|----------|-------------|------|
| `KDF/IPbkdf2Service.GenerateKey(int size, string password, byte[] salt, int iter=600_000, Pbkdf2Prf=HmacSha1)` | `KeyDerivation/IPbkdf2Service.DeriveKey(byte[] password, byte[] salt, int iterations, int keySizeBytes, Pbkdf2Prf=HmacSha256)` | PORT behind frozen stub | rename; string→byte[]; reorder; defaults removed; default PRF SHA1→SHA256. Already frozen. |
| `KDF/Pbkdf2Service.cs` | `KeyDerivation/Pbkdf2Service.cs` | PORT (impl) | no UTF8 encode, no `Array.Clear` of caller array; keep `Pkcs5S2ParametersGenerator` + `CreateDigest` switch; keep Sha384 arm (restored). |
| `KDF/IPbkdf2ServiceFactory.cs` / `Pbkdf2ServiceFactory.cs` | `KeyDerivation/IPbkdf2ServiceFactory.cs` / `Pbkdf2ServiceFactory.cs` | PORT verbatim / behind stub | `CreatePbkdf2Service()`, no `bufferSize`. |
| `KDF/Pbkdf2Prf {SHA1,256,384,512}` | `KeyDerivation/Pbkdf2Prf {SHA1,256,384,512}` | AMEND frozen enum (restore HmacSha384) | frozen skeleton had 3; HmacSha384 restored per decisions.json `trims_restore.pbkdf2Sha384`. |
| `KDF/IArgon2Service.GenerateKey(int size, byte[] passwordBytes, byte[] salt, int iter=10, int parallelism=4, int memoryPowOfTwo=16, variant, version)` | `KeyDerivation/IArgon2Service.DeriveKey(byte[] password, byte[] salt, int iterations, int memorySizeKb, int degreeOfParallelism, int keySizeBytes, variant, version)` | PORT behind frozen stub | rename; **memoryPowOfTwo→memorySizeKb (absolute KiB)**; renames; reorder; defaults removed. Already frozen. |
| `KDF/Argon2Service.cs` | `KeyDerivation/Argon2Service.cs` | PORT (impl) | use `WithMemoryAsKB`; explicit enum→BC version/variant mapping (never a cast). |
| `KDF/IArgon2ServiceFactory.cs` / `Argon2ServiceFactory.cs` | `KeyDerivation/IArgon2ServiceFactory.cs` / `Argon2ServiceFactory.cs` | PORT verbatim / behind stub | `CreateArgon2Service()`, no `bufferSize`. |
| `KDF/Argon2Variant` (0x00/0x01/0x02) | `KeyDerivation/Argon2Variant` (0,1,2) | already frozen (pure enum) | BC docs scrubbed; map explicitly in impl, do not rely on the value coincidence. |
| `KDF/Argon2Version` (0x10/0x13) | `KeyDerivation/Argon2Version` (0,1) | already frozen (pure enum) | **underlying values changed** → map to BC constants, never cast. |
| `UnitTests/KDF/Pbkdf2ServiceTests.cs` | `tests/Enigma.Core.UnitTests/KeyDerivation/Pbkdf2ServiceTests.cs` | PORT/adapt | see Test plan. |
| `UnitTests/KDF/Argon2IdTests.cs` | `tests/Enigma.Core.UnitTests/KeyDerivation/Argon2ServiceTests.cs` | PORT/adapt | see Test plan. |
| `UnitTests/KDF/pbkdf2.csv` | `tests/Enigma.Core.UnitTests/KeyDerivation/pbkdf2.csv` | COPY (PreserveNewest) | 10 rows: string password, hex salt, hex expected key (SHA1, 50k iters, 32 bytes). |
| `UnitTests/Infrastructure/CsvData.cs` | `tests/Enigma.Core.UnitTests/Infrastructure/CsvData.cs` | UN-DEFER (reuse foundation port) | shared CSV loader; `Hex()` via `Convert.FromHexString`. Introduced by the foundation test-harness port; reused here. |

## Contract amendments to the frozen skeleton (FEATURE-4442)
Approved by user 2026-07-21.

| Member | Signature (BC-free) | Restores (old member/test) | Notes |
|--------|---------------------|----------------------------|-------|
| `Pbkdf2Prf.HmacSha384` | `public enum Pbkdf2Prf { HmacSha1, HmacSha256, HmacSha384, HmacSha512 }` — add `HmacSha384` between `HmacSha256` and `HmacSha512` | old `KDF/Pbkdf2Prf.cs` 4-member set; `Pbkdf2Service.CreateDigest` `HmacSha384→Sha384Digest` arm; old `Pbkdf2ServiceTests` distinct-PRF test that iterated all four PRFs | Enum member only — exposes no BouncyCastle type, so principle-1 BC-hiding holds. Added FIRST to the frozen enum; the internal `CreateDigest` switch's `HmacSha384` arm initially throws (falls through to the `ArgumentOutOfRangeException` default), then is implemented to return an internal `Sha384Digest`. Inserting mid-enum shifts `HmacSha512`'s implicit ordinal 2→3; the enum is never persisted by ordinal, so this is safe. |

No other amendments: the Argon2 signatures, the PBKDF2 signature, the two factories, and `Argon2Variant`/`Argon2Version` are implemented as frozen. The old Argon2 exposed no `secret`/`associatedData` (interface had no such params; impl never called `WithSecret`/`WithAdditional`), so the FEATURE-4442 source-parity note resolves as "no change needed" — the frozen contract already matches the source.

## BouncyCastle usage (internal only)
- **PBKDF2:** `Org.BouncyCastle.Crypto.Generators.Pkcs5S2ParametersGenerator` — `.Init(password, salt, iterations)`, `.GenerateDerivedParameters("AES", keySizeBytes*8)`; `Org.BouncyCastle.Crypto.Parameters.KeyParameter` (`.GetKey()`); PRF backing digests `Org.BouncyCastle.Crypto.IDigest` implemented by `Sha1Digest`, `Sha256Digest`, `Sha384Digest` (restored), `Sha512Digest` (`Org.BouncyCastle.Crypto.Digests`).
- **Argon2:** `Org.BouncyCastle.Crypto.Generators.Argon2BytesGenerator` — `.Init(params)`, `.GenerateBytes(password, out, 0, len)`; `Org.BouncyCastle.Crypto.Parameters.Argon2Parameters` + `Argon2Parameters.Builder` with `.WithVersion`, `.WithIterations`, `.WithParallelism`, `.WithSalt`, and **`.WithMemoryAsKB`** (NOT `.WithMemoryPowOfTwo`); the `Argon2Parameters` variant constants `Argon2d`/`Argon2i`/`Argon2id` and version constants `Version10`/`Version13` for the explicit enum→constant mapping.
- None of these types may appear in any public signature, base type, or public support member; enforced by the API-surface reflection test. The `BouncyCastle.Cryptography` package reference is added to `Enigma.Core.csproj` (all TFMs) by the foundation feature (per decisions.json `orchestrator_impl_choices`); this feature only consumes it. `System.Buffers` is not needed for the KDFs.

## Redesign decisions
### Already frozen (FEATURE-4442, PHASE03)
- `GenerateKey`→`DeriveKey` on both services.
- PBKDF2 `password` is `byte[]` (caller owns encoding + clearing).
- PBKDF2 default PRF `HmacSha256` (was `HmacSha1`).
- Argon2 `memorySizeKb` (absolute KiB) replacing `memoryPowOfTwo`; `parallelism`→`degreeOfParallelism`; `passwordBytes`→`password`; `size`→`keySizeBytes` reordered near-last.
- All convenience cost defaults removed (PBKDF2 `iterations=600_000`; Argon2 `iterations=10`/`parallelism=4`/`memoryPowOfTwo=16`) — now mandatory positional args.
- `Argon2Variant`/`Argon2Version`/`Pbkdf2Prf` ported as pure enums with BouncyCastle references scrubbed from docs and explicit underlying values removed.
- Factories: single `CreatePbkdf2Service()` / `CreateArgon2Service()`, no `bufferSize`; sync `byte[]` APIs.

### Restored per user validation (2026-07-21)
- **PBKDF2-HMAC-SHA384 restored** (`Pbkdf2Prf.HmacSha384`): per decisions.json `trims_restore.pbkdf2Sha384`, the maximum-fidelity directive requires restoring every dropped capability. The old enum had four PRFs and `CreateDigest` mapped `HmacSha384→Sha384Digest`; the skeleton's 3-member alignment with the HMAC service was a design-driven trim, not source-driven, so it is reversed. The restored member is BC-free (enum only); `Sha384Digest` stays internal.

Settled implementation decisions (from decisions.json `orchestrator_impl_choices` — no user question needed):
- **Argon2 `memorySizeKb` = absolute KiB** via `WithMemoryAsKB(memorySizeKb)`; old vectors convert `memoryPowOfTwo=5 → memorySizeKb=32`. Using `WithMemoryPowOfTwo` would be catastrophically wrong.
- **Argon2Version / Argon2Variant → BC constant mapping** by explicit `switch`, never `(int)` cast: `Version10→Argon2Parameters.Version10 (0x10)`, `Version13→Argon2Parameters.Version13 (0x13)`; variants mapped explicitly too even though 0/1/2 currently coincide with BC.
- **PBKDF2 password ownership**: feed bytes straight into `generator.Init(password, salt, iterations)`; no UTF-8 re-encode, no `Array.Clear` of the caller's array.
- **Argument validation preserved**: keep guard clauses (`ArgumentNullException` on null password/salt; `ArgumentException` on non-positive size/iterations/parallelism/memory) and the `ArgumentOutOfRangeException` default arm in the PRF switch; add additive `<exception>` XML docs.
- **Recommended cost values preserved in XML-doc remarks** (OWASP ≥600,000 PBKDF2-HMAC-SHA256 iterations; RFC 9106 Argon2 second-recommended iterations=3, memory=65536 KiB, parallelism=4) so guidance survives the removal of defaults.

### Open for PR
- **Optional Argon2 `secret` / `associatedData`**: not covered by any decision key; the old source never exposed or used these (`WithSecret`/`WithAdditional` unused), so there is no dropped capability to restore. Recommended default: keep omitted (faithful to source); note internally that `WithSecret`/`WithAdditional` remain available should a future feature choose to surface keyed Argon2.

## Test plan
Port both old test files into `tests/Enigma.Core.UnitTests/KeyDerivation/` and reuse the shared harness introduced by the foundation test port.
- **Harness:** reuse `tests/Enigma.Core.UnitTests/Infrastructure/CsvData.cs` (un-deferred in foundation); its `Hex()` uses `System.Convert.FromHexString` to avoid coupling to the Encoding feature. Add `pbkdf2.csv` as `CopyToOutputDirectory=PreserveNewest` content. Replace old `.FromHexString()`/`.ToHexString()` extension usages with `System.Convert.FromHexString`/`ToHexString` (test project targets net10.0).
- **PBKDF2 (`Pbkdf2ServiceTests`):**
  - CSV theory (10 rows) — UTF-8-encode the ASCII-string column-0 password to `byte[]`, hex salt, hex expected key; run at 50_000 iterations with **explicit `HmacSha1`** (the PRF the vectors were generated under, since the default changed).
  - Inline canonical PBKDF2-HMAC-SHA256 vectors (`password`/`salt`, 1/2/4096 iterations, 32 bytes) — RFC 8018 / PKCS#5 v2.0.
  - Default-PRF pin test **rewritten** to assert default-call output == explicit `HmacSha256` output.
  - Distinct-PRF test iterating **all four** restored PRFs `{HmacSha1, HmacSha256, HmacSha384, HmacSha512}` and asserting **4 distinct** outputs (restores the original 4-PRF coverage).
  - Password-not-mutated test: `DeriveKey` does not mutate or clear the caller's `byte[]`.
  - Argument-validation tests: null password/salt, non-positive keySize/iterations.
- **Argon2 (`Argon2ServiceTests`):**
  - Port 2 Argon2id vectors (one 32-byte password, one empty password) converting `memoryPowOfTwo=5 → memorySizeKb=32`; args reordered to `(password, salt, iterations=3, memorySizeKb=32, degreeOfParallelism=4, keySizeBytes=32, variant, version)`; hex via `Convert.FromHexString` — RFC 9106.
  - Version-mapping regression test: `Version10` vs `Version13` on identical inputs produce **different** output, proving the enum→BC-constant mapping (not a raw cast).
  - Argument-validation tests: null password/salt, non-positive iterations/memory/parallelism/keySize.
- **New cross-cutting test:** API-surface **reflection test** asserting no public member, signature, base type, or public support member in `Enigma.Core.KeyDerivation` exposes any `Org.BouncyCastle.*` type.
- **No vector regeneration required** for this feature: PBKDF2 CSV and canonical vectors are reused; Argon2 vectors only need the arithmetic `memoryPowOfTwo→KiB` substitution, not regeneration. (SHA-3 per-size and PQC raw-byte regeneration are other features' concerns.)

## Dependencies
- **FEATURE-61D1 (foundation)** — MUST land first: adds the `BouncyCastle.Cryptography` (+ `System.Buffers`) package references to `Enigma.Core.csproj`, finalizes the 3-TFM build/warnings config (`TreatWarningsAsErrors`, `GenerateDocumentationFile`), and ports the shared test harness (`CsvData`, `SyncProgress<T>`) and net10 test-project conventions this feature reuses.
- **FEATURE-26A5 (hashing)** — soft/ordering dependency (no compile-time type dependency; PBKDF2 uses BouncyCastle digests directly, not `IHmacService`). Sibling PHASE03 module; landing it first keeps the HMAC/PBKDF2 PRF algorithm-set story coherent. With `HmacSha384` restored on both sides, the two PRF sets stay aligned.

## Phases
Single-phase — all four stubs, the `Pbkdf2Prf.HmacSha384` amendment, and the full test port land together. No phase breakdown.

## Acceptance criteria
- `Enigma.Core` builds clean with **zero warnings** across `netstandard2.0`, `net8.0`, `net10.0` under `TreatWarningsAsErrors` + `GenerateDocumentationFile` (no CS1591).
- `BouncyCastle.Cryptography` package reference present on `Enigma.Core` (added by foundation); `System.Buffers` not added for this feature.
- **No `Org.BouncyCastle.*` type** appears in any public signature, base type, or public member of `Enigma.Core.KeyDerivation` — enforced by the automated API-surface reflection test.
- `Pbkdf2Service.DeriveKey`, `Pbkdf2ServiceFactory.CreatePbkdf2Service`, `Argon2Service.DeriveKey`, `Argon2ServiceFactory.CreateArgon2Service` no longer throw `NotImplementedException`.
- **`Pbkdf2Prf.HmacSha384` present and functional**: the enum has all four members, `CreateDigest` maps `HmacSha384` to the internal `Sha384Digest`, and a PBKDF2-HMAC-SHA384 derivation produces a correct non-empty key.
- Ported PBKDF2 CSV vectors (10 rows, HMAC-SHA1, 50_000 iterations, 32 bytes) all pass.
- Canonical PBKDF2-HMAC-SHA256 vectors (`password`/`salt` at 1, 2, 4096 iterations) pass.
- Default-PRF is `HmacSha256`: default-call output equals explicit `HmacSha256` output.
- Distinct-PRF test over `{HmacSha1, HmacSha256, HmacSha384, HmacSha512}` yields **4 distinct** keys.
- Both Argon2id vectors pass with `memorySizeKb=32` (iterations 3, degreeOfParallelism 4, keySizeBytes 32), confirming `WithMemoryAsKB` is used.
- Argon2 `Version10` vs `Version13` produce different output for identical inputs, confirming the enum→BC-version-constant mapping (not a raw cast).
- `DeriveKey` does not mutate or clear the caller's password `byte[]`.
- Argument validation preserved: null password/salt and non-positive keySize/iterations/memory/parallelism throw, with matching `<exception>` XML docs.
- `dotnet test` green on `net10.0` for the KeyDerivation test set.
- Roadmap (`docs/roadmap.md`) and plan status updated; completion record `docs/done/FEATURE-679F.md` written.
