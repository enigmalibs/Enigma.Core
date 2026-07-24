# FEATURE-679F — KeyDerivation implementation (PBKDF2 + Argon2)

- **Status:** DONE
- **Type:** FEATURE (single-phase)
- **Branch:** `feature/feature-679f-keyderivation` (cut from `feature/feature-26a5-hashing` @ `fc64994`)
- **Scope:** `KDF` module.

## Summary
Implemented the two in-memory key-derivation services behind the API frozen by FEATURE-4442 PHASE03,
porting the working logic and BouncyCastle wiring from v5.0.0 at maximum fidelity, plus the one approved
contract amendment (restore `Pbkdf2Prf.HmacSha384`). All four stubs no longer throw
`NotImplementedException`.

1. **`Pbkdf2Service.DeriveKey(byte[] password, byte[] salt, int iterations, int keySizeBytes,
   Pbkdf2Prf prf = HmacSha256)`** — `Pkcs5S2ParametersGenerator` over the private `CreateDigest` PRF
   switch → `GenerateDerivedParameters("AES", keySizeBytes * 8)` → `KeyParameter.GetKey()`. The
   caller's `password` is fed straight in: **no UTF-8 re-encode, no `Array.Clear`** of the caller's
   array (v5.0.0 did both — dropped per the frozen byte[]/caller-owns contract).
2. **`Pbkdf2ServiceFactory.CreatePbkdf2Service()`** — returns a stateless `Pbkdf2Service` (no `bufferSize`).
3. **`Argon2Service.DeriveKey(byte[] password, byte[] salt, int iterations, int memorySizeKb,
   int degreeOfParallelism, int keySizeBytes, Argon2Variant variant = Argon2id,
   Argon2Version version = Version13)`** — `Argon2Parameters.Builder` + `Argon2BytesGenerator`, using
   **`WithMemoryAsKB(memorySizeKb)`** (absolute KiB, NOT `WithMemoryPowOfTwo`). Variant and version are
   mapped to BouncyCastle constants by **explicit `switch`, never a `(int)` cast**.
4. **`Argon2ServiceFactory.CreateArgon2Service()`** — returns a stateless `Argon2Service` (no `bufferSize`).
5. **`Pbkdf2Prf` amendment** — `HmacSha384` restored between `HmacSha256` and `HmacSha512`; `CreateDigest`
   maps it to the internal `Sha384Digest`. Enum-only, so no BouncyCastle type reaches the surface.

Every BouncyCastle type (`Pkcs5S2ParametersGenerator`, `IDigest`, `Sha1/256/384/512Digest`,
`Argon2BytesGenerator`, `Argon2Parameters`, `KeyParameter`) is used only in service bodies and private
helpers — never on the public surface.

## Files / modules touched

### Modified — library (`src/Enigma.Core/KeyDerivation/`)
- `Pbkdf2Service.cs` — implemented `DeriveKey` + private `CreateDigest` (includes the restored SHA-384 arm);
  argument guards (null password/salt; non-positive iterations/keySizeBytes).
- `Pbkdf2ServiceFactory.cs` — implemented `CreatePbkdf2Service()`.
- `Pbkdf2Prf.cs` — **amended**: `HmacSha384` inserted between `HmacSha256` and `HmacSha512`.
- `Argon2Service.cs` — implemented `DeriveKey` + private `MapVariant`/`MapVersion` (explicit BC-constant
  maps); argument guards (null password/salt; non-positive iterations/memory/parallelism/keySizeBytes).
- `Argon2ServiceFactory.cs` — implemented `CreateArgon2Service()`.
- `IPbkdf2Service.cs` / `IArgon2Service.cs` — **doc-only additive** `<remarks>` (OWASP ≥600,000 PBKDF2-
  HMAC-SHA256 iterations; RFC 9106 Argon2 second-recommended `t=3, m=65536 KiB, p=4`) + `<exception>`
  tags. Signatures unchanged (frozen contract preserved).

(`IPbkdf2ServiceFactory`, `IArgon2ServiceFactory`, `Argon2Variant`, `Argon2Version` were already frozen
correctly — no change.)

### Created — tests (`tests/Enigma.Core.UnitTests/KeyDerivation/`)
- `Pbkdf2ServiceTests.cs` — CSV theory (10 rows, HMAC-SHA1, 50,000 iters, 32 bytes; column-0 password
  UTF-8-encoded); canonical PBKDF2-HMAC-SHA256 (1/2/4096 iters, RFC 8018); default-PRF == explicit
  HmacSha256; distinct-PRF over all four `{HmacSha1, HmacSha256, HmacSha384, HmacSha512}` → 4 distinct
  keys; SHA-384 produces a correct non-empty key of the requested length; password-not-mutated; argument
  guards (null password/salt, non-positive iterations/keySize).
- `Argon2ServiceTests.cs` — 2 Argon2id vectors (`memoryPowOfTwo=5 → memorySizeKb=32`; one 32-byte, one
  empty password); version-mapping regression (`Version10` ≠ `Version13` output); password-not-mutated;
  argument guards (null password/salt, non-positive iterations/memory/parallelism/keySize).
- `KeyDerivationBouncyCastleIsolationTests.cs` — reflection guard scoped to `Enigma.Core.KeyDerivation`.

### Created — test vectors (`tests/Enigma.Core.UnitTests/KeyDerivation/`)
- `pbkdf2.csv` — ported verbatim (10 rows, `password,salt,key`). Auto-copied to output by the test
  project's existing `**/*.csv` PreserveNewest glob (no csproj change needed).

## Deviations & follow-ups
- **CSV password column is an ASCII string, UTF-8-encoded — not hex.** The v5.0.0 test passed column 0
  (e.g. `d376e1f90da29a92`) as a `string` to an API that UTF-8-encoded it internally; the vectors were
  therefore generated over the 16 ASCII *characters*, not the 8 decoded hex bytes. The port encodes
  column 0 with `Encoding.UTF8.GetBytes` (not `Convert.FromHexString`) to stay byte-exact — all 10 rows pass.
- **`Encoding` name collision.** The sibling test namespace `Enigma.Core.UnitTests.Encoding` shadows the
  simple name `System.Text.Encoding` inside `Enigma.Core.UnitTests.KeyDerivation`; a `using`-alias was
  itself shadowed by the enclosing-namespace member, so the PBKDF2 test encodes through a small
  `global::System.Text.Encoding`-qualified `Utf8` helper. Test-only, no product impact.
- **Optional Argon2 `secret` / `associatedData` (plan "Open for PR"): kept omitted.** v5.0.0 never
  exposed or called `WithSecret`/`WithAdditional`, so there is no dropped capability to restore. Faithful
  to source; `WithSecret`/`WithAdditional` remain available internally should a future feature choose to
  surface keyed Argon2.
- **No vector regeneration.** PBKDF2 CSV and canonical vectors reused as-is; Argon2 vectors needed only the
  arithmetic `memoryPowOfTwo=5 → memorySizeKb=32` substitution (`WithMemoryAsKB(32)` reproduces
  `WithMemoryPowOfTwo(5)`), confirmed by both vectors matching.
- **`System.Buffers`** not added for this feature (KDFs are synchronous `byte[]` APIs, no ArrayPool);
  the plan explicitly expected this.
- **Line endings:** no CRLF/line-ending anomalies observed in the touched files; no action taken
  (recommendation-only per workflow).

## Build / test evidence
- **Build:** `dotnet build -c Release` → **Build succeeded, 0 Warning(s), 0 Error(s)** across all three
  library TFMs (`netstandard2.0;net8.0;net10.0`) under `TreatWarningsAsErrors` + `GenerateDocumentationFile`.
- **Tests:** `dotnet test -c Release` → **672 passed, 0 failed, 0 skipped** across both test TFMs
  (`net8.0`, `net10.0`); +76 over the prior 596 (38 new KeyDerivation tests × 2 TFMs). The 38 were
  confirmed to actually execute via the xunit query filter `/*/Enigma.Core.UnitTests.KeyDerivation/*/*`.
- **Acceptance criteria:** all met — four stubs implemented (no `NotImplementedException`); `Pbkdf2Prf`
  has all four members with SHA-384 → `Sha384Digest`; 10 ported PBKDF2 CSV rows pass; canonical
  HMAC-SHA256 (1/2/4096) pass; default PRF == HmacSha256; 4 distinct PRF keys; both Argon2id vectors pass
  at `memorySizeKb=32`; `Version10` ≠ `Version13`; password not mutated; argument validation with matching
  `<exception>` docs; namespace-scoped + assembly-wide BouncyCastle reflection guards green.
