# FEATURE-61D1 — Implementation foundation (packages, test harness, shared Extensions/Utils)

- **Status:** DONE
- **Type:** FEATURE (single-phase)
- **Branch:** `feature/feature-61d1-foundation` (cut from `develop`)

## Summary
Made Enigma.Core buildable and testable against the frozen FEATURE-4442 skeleton and provided the
shared, BouncyCastle-free plumbing every downstream crypto module needs. Concretely:

1. **Package references** — added `BouncyCastle.Cryptography` (all TFMs) to the library. This is the
   enabling reference for every later restoration (RSA core, PFX/PKCS#12, OTP RFC parity, configurable
   SHA-3, GCM AAD, PQC raw-byte keys). `System.Buffers` was added on `netstandard2.0` only (see
   Deviations). No algorithm logic ships here and no BouncyCastle type appears on the public surface.
2. **Test project** — multi-targeted `net8.0;net10.0` (was `net10.0` only) so net8.0 code paths (and the
   netstandard2.0 polyfill surface reachable through them) are actually exercised; kept MTP-native
   xunit.v3; added `coverlet.collector`; stood up the CSV test-vector convention.
3. **Shared support code** — ported `Extensions/StreamExtensions.*` (public), `StreamReadHelpers`
   (internal), `EncodingExtensions`, and `Utils/RandomUtils` into `Enigma.Core.Extensions` /
   `Enigma.Core.Utils`, plus the reusable test harness (`CsvData`, `SyncProgress<T>`).

## Files / modules touched

### Created — library (`src/Enigma.Core/`)
- `Extensions/StreamReadHelpers.cs` — **internal** `ReadExact`/`ReadExactAsync` read-loop (throws `IOException` on short read).
- `Extensions/StreamExtensions.Bool.cs`, `.Bytes.cs`, `.Int16.cs`, `.Int32.cs`, `.Int64.cs`, `.Float.cs`,
  `.Double.cs`, `.LengthValue.cs`, `.TagLengthValue.cs` — **public** C# 14 `extension(Stream)` blocks
  (little-endian; sync + async; `LengthValue` guards negative/oversized length with `InvalidOperationException`).
- `Extensions/EncodingExtensions.cs` — **public**; delegates to `Enigma.Core.Encoding`
  (`Base64Service`/`HexService`/`Base32Service`); UTF-8 default (not `Encoding.Default`);
  `using TextEncoding = System.Text.Encoding;` breaks the `Enigma.Core.Encoding` namespace collision.
- `Utils/RandomUtils.cs` — **public** `GenerateRandomBytes(int)` returning `byte[]`; BouncyCastle
  `SecureRandom` kept as an internal `[ThreadStatic]`; throws `ArgumentException` for size ≤ 0.

### Created — tests (`tests/Enigma.Core.UnitTests/`)
- `Infrastructure/CsvData.cs` — `Rows(params string[])` ported as-is; `Hex` reimplemented with
  `System.Convert.FromHexString` (no dependency on the stubbed `HexService`).
- `Infrastructure/SyncProgress.cs` — `SyncProgress<T> : IProgress<T>` (the reusable helper only; the
  Hash/BlockCipher progress/cancellation facts remain deferred to those features).
- `Extensions/StreamExtensions*Tests.cs` (9 files) — ported round-trip + async round-trip tests, plus
  **new** `LengthValue` negative/max-length `InvalidOperationException` guard tests (sync + async).
- `Extensions/EncodingExtensionsTests.cs` — the `System.Text` half only (UTF-8-default contract +
  explicit-encoding helpers); Base64/Hex/Base32 round-trips deferred to the Encoding feature.
- `Utils/RandomUtilsTests.cs` — **new** guard tests: `(0)`/`(-1)` throw `ArgumentException`; positive
  size returns exactly that many bytes.
- `Api/BouncyCastleIsolationTests.cs` — **new** reflection guard (principle 1): walks every exported
  type's public/protected members (return, parameter, field, base, interface, generic-arg types;
  properties/events via accessors) and fails if any lives in `Org.BouncyCastle.*`.

### Modified
- `src/Enigma.Core/Enigma.Core.csproj` — added `BouncyCastle.Cryptography` (all TFMs) and `System.Buffers`
  (netstandard2.0 only).
- `tests/Enigma.Core.UnitTests/Enigma.Core.UnitTests.csproj` — `net8.0;net10.0`; added
  `coverlet.collector` (`PrivateAssets=all`); added the `<None Update="**/*.csv"
  CopyToOutputDirectory=PreserveNewest>` vector-file convention.
- `Directory.Packages.props` — added central `coverlet.collector` 6.0.4 version.
- `docs/roadmap.md`, `docs/plan/FEATURE-61D1.md` — status → DONE.

### Deleted
- `tests/Enigma.Core.UnitTests/SmokeTest.cs` — the skeleton bootstrap smoke test, whose own doc comment
  said "Enigma.Core has no public types yet … Replace/expand once real types exist." Real types and
  real tests now exist and subsume it; its comment was factually stale. (Deviation — see below.)

## Deviations & follow-ups
- **`System.Buffers` conditioned to `netstandard2.0`.** The old v5.0.0 library referenced it
  unconditionally, but that project had no `TreatWarningsAsErrors`. Enigma.Core does, and `System.Buffers`
  is framework-provided on net8.0+ — an unconditional reference raises **NU1510** and would fail the
  zero-warnings build. Conditioning it to `netstandard2.0` (where it is genuinely needed for Span/Memory
  polyfills) keeps the port faithful in intent while meeting acceptance criterion 1. BouncyCastle stays
  unconditional (not framework-provided).
- **CSV convention expressed as a glob.** The plan said "establish the `<None Update … PreserveNewest>`
  vector-file convention." Since foundation ships no CSVs, I used a single `**/*.csv` glob rather than
  per-file entries, so the convention is genuinely in place and each future feature only needs to drop
  its CSV under the test project (matches the plan's "per-module CSVs arrive with their features").
- **`SmokeTest.cs` removed** (see Deleted). Not named in the plan, but removing it was invited by the
  file's own comment and avoids a test asserting a now-false statement.
- **`CsvData`/`SyncProgress<T>` are currently unused** in foundation (their consumers are deferred).
  They are harness scaffolding required by acceptance criterion 6; they compile clean with no warnings.
- **No line-ending (CRLF) issues observed** in the touched files.

## Build / test evidence
- **Build:** `dotnet build -c Release` — **Build succeeded, 0 Warning(s), 0 Error(s)** across
  `netstandard2.0;net8.0;net10.0` under `TreatWarningsAsErrors` + `EnforceCodeStyleInBuild`. Confirms the
  C# 14 `extension(...)` blocks lower cleanly on netstandard2.0 via PolySharp, and that BouncyCastle
  linking + the System.Buffers conditioning produce no NU1510.
- **Tests:** `dotnet test -c Release` — **Passed! total: 90, failed: 0, skipped: 0** (45 per TFM ×
  net8.0 + net10.0), MTP-native. Includes all ported round-trip/async extension tests, the LengthValue
  guard tests, the TagLengthValue round-trip, the EncodingExtensions System.Text half, the RandomUtils
  guards, and the reflection BouncyCastle-isolation guard.

## Acceptance criteria — all met
1. ✔ `Enigma.Core.csproj` references `BouncyCastle.Cryptography` (+ `System.Buffers` on netstandard2.0);
   library builds clean with ZERO warnings across all 3 TFMs.
2. ✔ Test project multi-targets `net8.0;net10.0` (MTP-native xunit.v3, `coverlet.collector` present);
   `dotnet test` green on both TFMs.
3. ✔ `StreamExtensions.*` public, `StreamReadHelpers` internal; round-trip + async + LengthValue guard +
   TagLengthValue tests pass on both TFMs.
4. ✔ `EncodingExtensions` ported and compiling clean (UTF-8 default; `TextEncoding` alias);
   `GetBytes/GetString/UTF-8/ASCII` tests pass; Base64/Hex/Base32 round-trips deferred.
5. ✔ `RandomUtils.GenerateRandomBytes` ported; `(0)`/`(-1)` throw `ArgumentException`; positive size
   returns exact length; BouncyCastle `SecureRandom` stays internal.
6. ✔ CSV harness stood up: `CsvData.Rows` ported, `CsvData.Hex` via `System.Convert.FromHexString`;
   `SyncProgress<T>` ported; `CopyToOutputDirectory=PreserveNewest` convention in place.
7. ✔ Reflection test proves no exported member of `Enigma.Core` exposes an `Org.BouncyCastle.*` type.
8. ✔ `PemUtils`/`X509Utils` not introduced (remain deferred); `ProgressAndCancellation` module tests,
   `ArgumentValidationTests`, `CryptoKeyPairFixture`, `PemUtilsTests` remain deferred.
9. ✔ Roadmap + plan status updated; this completion doc written.
