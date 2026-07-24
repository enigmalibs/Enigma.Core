# FEATURE-61D1 — Implementation foundation (packages, test harness, shared Extensions/Utils)

- **Status:** DONE
- **Type:** FEATURE (single-phase)
- **Depends on:** FEATURE-4442 (abstraction skeleton — DONE); first implementation feature
- **Suggested branch (at build):** `feature/feature-61d1-foundation`
- **Basis:** redesign decisions validated by user 2026-07-21.

## Objective
Make Enigma.Core buildable and testable against the frozen FEATURE-4442 skeleton and provide the shared, BouncyCastle-free plumbing every downstream crypto module needs. Concretely: (1) add the `BouncyCastle.Cryptography` + `System.Buffers` package references to the library (this is the reference that unblocks every later restoration — RSA core, PFX/PKCS#12, OTP RFC parity, configurable SHA-3, GCM AAD, PQC raw-byte keys); (2) multi-target the test project so `net8.0` is exercised alongside `net10.0`, add `coverlet.collector`, and stand up the CSV test-vector harness (`CsvData` + `SyncProgress<T>`); (3) port the genuinely shared support code — `Extensions/StreamExtensions.*`, `Extensions/StreamReadHelpers` (internal), `Extensions/EncodingExtensions`, and `Utils/RandomUtils`. No algorithm logic ships here and no BouncyCastle type appears in any public signature, base type, thrown-in-signature type, or public support member.

## Scope & mapping
| Old file | New home / verdict | Note |
|----------|--------------------|------|
| `Extensions/StreamExtensions.Bool.cs` | `src/Enigma.Core/Extensions/StreamExtensions.Bool.cs` — un-defer, **public** | `WriteBool/ReadBool` + async; namespace `Enigma.Core.Extensions`; BC-free, test-only consumers |
| `Extensions/StreamExtensions.Bytes.cs` | `src/Enigma.Core/Extensions/StreamExtensions.Bytes.cs` — un-defer, **public** | `WriteByteAsync/ReadByteAsync/WriteBytes/ReadBytes` + async; sync `WriteByte/ReadByte` intentionally omitted (Stream instance methods shadow them) — keep that note |
| `Extensions/StreamExtensions.Int16.cs` | `src/Enigma.Core/Extensions/StreamExtensions.Int16.cs` — un-defer, **public** | `WriteShort/ReadShort/WriteUShort/ReadUShort` (little-endian) + async; UShort used by TagLengthValue |
| `Extensions/StreamExtensions.Int32.cs` | `src/Enigma.Core/Extensions/StreamExtensions.Int32.cs` — un-defer, **public** | `WriteInt/ReadInt/WriteUInt/ReadUInt` (little-endian) + async; used by LengthValue |
| `Extensions/StreamExtensions.Int64.cs` | `src/Enigma.Core/Extensions/StreamExtensions.Int64.cs` — un-defer, **public** | `WriteLong/ReadLong/WriteULong/ReadULong` + async |
| `Extensions/StreamExtensions.Float.cs` | `src/Enigma.Core/Extensions/StreamExtensions.Float.cs` — un-defer, **public** | `WriteFloat/ReadFloat` + async |
| `Extensions/StreamExtensions.Double.cs` | `src/Enigma.Core/Extensions/StreamExtensions.Double.cs` — un-defer, **public** | `WriteDouble/ReadDouble` + async |
| `Extensions/StreamExtensions.LengthValue.cs` | `src/Enigma.Core/Extensions/StreamExtensions.LengthValue.cs` — un-defer, **public** | `WriteLengthValue/ReadLengthValue(maxLength=10MB)` + async; guards negative/oversized length with `InvalidOperationException`; depends on Int32 + Bytes |
| `Extensions/StreamExtensions.TagLengthValue.cs` | `src/Enigma.Core/Extensions/StreamExtensions.TagLengthValue.cs` — un-defer, **public** | `WriteTagLengthValue/ReadTagLengthValue` + async; depends on Int16(UShort) + LengthValue |
| `Extensions/StreamReadHelpers.cs` | `src/Enigma.Core/Extensions/StreamReadHelpers.cs` — un-defer, **INTERNAL** | `ReadExact/ReadExactAsync` read-loop; throws `IOException` on short read; consumed by every read method |
| `Extensions/EncodingExtensions.cs` | `src/Enigma.Core/Extensions/EncodingExtensions.cs` — un-defer **code** | Delegates to renamespaced `Enigma.Core.Encoding` (`Base64Service/HexService/Base32Service`); UTF-8 default (not `Encoding.Default`) preserved; add `using TextEncoding = System.Text.Encoding;` to break the `Enigma.Core.Encoding` collision; **encode/decode round-trip tests move to Encoding feature** |
| `Utils/RandomUtils.cs` | `src/Enigma.Core/Utils/RandomUtils.cs` — un-defer, **public** | ns → `Enigma.Core.Utils`; `GenerateRandomBytes(int)` returns `byte[]` (no BC leak); `[ThreadStatic]` BC `SecureRandom` stays internal; throws `ArgumentException` for size ≤ 0 |
| `Utils/PemUtils.cs` | **DEFER → PublicKey (FEATURE-2E3E)** | Becomes INTERNAL detail behind `IPublicKeyService` (not dropped — see Restored) |
| `Utils/X509Utils.cs` | **DEFER → Certificates (FEATURE-099B)** | Becomes INTERNAL detail behind `IX509CertificateService`; PFX is RESTORED as a BC-free `byte[]` API there (not dropped — see Restored) |
| `CryptoDefaults.cs` | `src/Enigma.Core/CryptoDefaults.cs` — already ported | PHASE01 (`StreamBufferSize=4096`); no foundation action |
| `SignatureAlgorithms.cs` | **DROP** | Superseded by root enum `RsaSignatureAlgorithm` (PHASE01) |
| `src/Enigma.Core/Enigma.Core.csproj` | edit | add `BouncyCastle.Cryptography` + `System.Buffers` refs (BC 2.6.2, System.Buffers 4.6.1 central in `Directory.Packages.props`); keep 3 TFMs + PolySharp on netstandard2.0 |
| `tests/Enigma.Core.UnitTests/Enigma.Core.UnitTests.csproj` | edit | `<TargetFramework>net10.0</TargetFramework>` → `<TargetFrameworks>net8.0;net10.0</TargetFrameworks>`; keep MTP-native xunit.v3; add `coverlet.collector`; establish `CopyToOutputDirectory=PreserveNewest` CSV convention |
| `UnitTests/Infrastructure/CsvData.cs` | `tests/Enigma.Core.UnitTests/Infrastructure/CsvData.cs` — port | `Rows(params string[])` ports as-is; `Hex(string)` reimplemented with `System.Convert.FromHexString` (self-contained, no Encoding-stub dependency) |
| `UnitTests/Infrastructure/ProgressAndCancellationTests.cs` | `tests/.../Infrastructure/` (SyncProgress only) | port `SyncProgress<T> : IProgress<T>`; the Hash/BlockCipher `[Fact]`s DEFER to Hashing/Symmetric |
| `UnitTests/Validation/CryptoKeyPairFixture.cs` | **DEFER → per feature** | BC-typed + stub-driven; rebuild BC-free (PEM string / byte[]) with impl features |
| `UnitTests/Validation/ArgumentValidationTests.cs` | **DEFER → split per feature** | reuse only the `Assert.Throws` guard pattern |
| `UnitTests/Extensions/StreamExtensions*Tests.cs` (9) | `tests/.../Extensions/*Tests.cs` — port | run on net8.0;net10.0; `TestContext.Current.CancellationToken` preserved |
| `UnitTests/Extensions/EncodingExtensionsTests.cs` | **SPLIT** | System.Text (GetBytes/GetString/UTF-8/ASCII) tests → foundation; Base64/Hex/Base32 round-trips → Encoding feature |
| `UnitTests/Utils/PemUtilsTests.cs` | **DEFER → PublicKey** | rewrite against PEM-string API |

## Contract amendments to the frozen skeleton (FEATURE-4442)
Approved by user 2026-07-21.

**None to the frozen crypto-service contracts — the frozen contract is implemented as-is by foundation.** All user-validated capability restorations (RSA `GenerateRsaKeyPair`, `X509CertificateOptions`/`CertificateInfo` extension read-back, PFX `ExportPkcs12`/`ImportPkcs12`, HOTP window + matched-counter, TOTP matched-step/`GetRemainingSeconds`, configurable SHA-3, `Pbkdf2Prf.HmacSha384`, GCM AAD, ML-DSA `deterministic`, PQC raw-byte keys) are amendments to **downstream** feature contracts (PublicKey/Certificates/Otp/Hashing/KeyDerivation/Symmetric/Pqc) and are specified in those features' plans — each added there first as a throwing stub, then implemented, each keeping principle-1 BC-hiding. Foundation adds none of them; it only makes them buildable by adding the BouncyCastle package reference.

The public types foundation introduces (`StreamExtensions.*`, `EncodingExtensions`, `RandomUtils`) are **un-defers of pre-existing BC-free v5.0.0 support types**, not amendments to any frozen service member — they are ported with their original BC-free signatures unchanged and every one keeps principle-1 BC-hiding (`RandomUtils.GenerateRandomBytes` returns `byte[]` with the BC `SecureRandom` strictly internal).

## BouncyCastle usage (internal only)
Only one type is touched in foundation scope:
- `Org.BouncyCastle.Security.SecureRandom` (+ `.NextBytes(byte[])`) — an internal `[ThreadStatic]`, lazily created, behind `Utils/RandomUtils`. Public surface is `byte[] GenerateRandomBytes(int)` — no leak.

Adding the `BouncyCastle.Cryptography` package reference to the library here is the enabling step for every downstream feature. The heavy BC consumers named in the spec (`AsymmetricKeyParameter`, `AsymmetricCipherKeyPair`, `PemReader/PemWriter/IPasswordFinder`, `X509Certificate/X509CertificateParser`, `Pkcs12StoreBuilder/X509CertificateEntry/AsymmetricKeyEntry`, `X509Extensions/GeneralNames`, `CertificateExpired/NotYetValidException`) belong to the deferred `PemUtils`/`X509Utils` and are out of foundation scope.

## Redesign decisions
### Already frozen (FEATURE-4442)
- `CryptoDefaults` ported verbatim (PHASE01); `SignatureAlgorithms` string constants → root enum `RsaSignatureAlgorithm { Sha1WithRsa, Sha256WithRsa, Sha384WithRsa, Sha512WithRsa }` (PHASE01) — old `SignatureAlgorithms.cs` is dropped, not ported.
- `DataEncoding` → `Enigma.Core.Encoding` with `IEncodingService.Encode(byte[])/Decode(string)` + `Base64Service/Base32Service/HexService` stubs (PHASE04) — the delegation target for `EncodingExtensions`.
- `PemPasswordFinder` dropped; PublicKey keys cross the API as PEM `string` + `char[]?` password (PHASE05). Certificates use PEM `string`; `CertificateInfo.SerialNumber` → `System.Numerics.BigInteger` (PHASE06).
- `Enigma.Core` multi-targets `netstandard2.0;net8.0;net10.0`, LangVersion 14, Nullable enable, TreatWarningsAsErrors, GenerateDocumentationFile, PolySharp on netstandard2.0 (established pre-foundation).

### Restored per user validation (2026-07-21)
- **Test suite exercises net8.0** — change the test project from `net10.0` only to `net8.0;net10.0`, so net8.0 code paths (and the netstandard2.0 polyfill surface reachable through them) are actually run. The library still builds all 3 TFMs; netstandard2.0 is build-only (cannot host a runner). Rationale: the feature's explicit goal is to exercise net8.0.
- **coverlet.collector restored** — re-added to the test project to match the old suite's coverage tooling (`orchestrator_impl_choices`). The rest of the harness stays MTP-native xunit.v3 (no `Microsoft.NET.Test.Sdk`).
- **PemUtils kept (as INTERNAL), not dropped** — deferred to PublicKey (FEATURE-2E3E) where it becomes an internal PEM-string ↔ BC-key detail behind `IPublicKeyService` (`orchestrator_impl_choices`). Foundation does not port it; this corrects the spec draft's "internal-vs-drop" open question.
- **X509Utils PFX RESTORED (not dropped)** — the spec listed PKCS#12/PFX as a capability drop; the user decision **re-adds it** as a BC-free `byte[]` API in Certificates (FEATURE-099B): `byte[] ExportPkcs12(string certPem, string privateKeyPem, char[] password, IReadOnlyList<string>? chainPems=null)` and `(string certPem, string privateKeyPem) ImportPkcs12(byte[] pfx, char[] password)` — binary→`byte[]` is the one documented exception to all-PEM. X509Utils load/save/inspect logic becomes internal behind `IX509CertificateService`. Foundation does not port it, but its mapping note is corrected here from "PFX dropped" to "PFX restored in Certificates."
- **Validation harness rebuilt BC-free per feature** — `CryptoKeyPairFixture` + `ArgumentValidationTests` are deferred and rebuilt with PEM-string/byte[] keys+certs in each implementation feature (`orchestrator_impl_choices`); foundation ports only the reusable `CsvData` + `SyncProgress<T>` scaffolding.
- **`EncodingExtensions` split** — class ported in foundation (compiles clean against the Encoding stubs); its Base64/Hex/Base32 round-trip tests move to the Encoding feature; only the `System.Text`-backed tests stay in foundation (`orchestrator_impl_choices`).
- **`CsvData.Hex` self-contained** — reimplemented with `System.Convert.FromHexString` so the harness takes no runtime dependency on the stubbed `HexService`.
- **`RandomUtils` keeps the BC `SecureRandom` backend** — faithful port retained (BC is referenced library-wide and downstream features share this randomness source); the `RandomNumberGenerator` alternative is noted but not taken. No public leak.

### Open for PR
- **None specific to foundation.** Every `needsUserValidation` divergence in the spec is now settled by a decision key above. (The `cert_extra_parity_implied` items — `IsCertificateSigningRequestValid`, DER load/save overloads — are flagged-at-PR but belong to the Certificates plan, not foundation.) Recommended default for the only stylistic latitude left — the `System.Text.Encoding` collision fix — is the `using TextEncoding = System.Text.Encoding;` alias over full qualification.

## Test plan
Ported vectors + old test files to port/adapt, plus new tests the redesign warrants:
- **Ported extension tests** — the 9 `StreamExtensions*Tests` (inline round-trip: write to `MemoryStream`, rewind, read back, `Assert.Equal`; each with a sync + async variant, async using `TestContext.Current.CancellationToken`), including the `LengthValue` max-length/negative-length `InvalidOperationException` guards and the `TagLengthValue` tag+value round-trip. Run on **net8.0 and net10.0**.
- **Ported EncodingExtensions (System.Text half only)** — the UTF-8-default contract (euro sign = 3 bytes `E2 82 AC` in UTF-8 vs 1 byte in ANSI) and the `GetBytes/GetString/UTF-8/ASCII` default-encoding tests (the CODE-REVIEW-001 UTF-8-default contract). The RFC-4648 Base64/Hex/Base32 round-trips (`foobar` → `Zm9vYmFy` / `666f6f626172` / `MZXW6YTBOI======`) are **deferred to the Encoding feature**.
- **Harness infrastructure** — port `CsvData` (header-skip + comma-split loader; `Hex` via `System.Convert.FromHexString`) and `SyncProgress<T> : IProgress<T>`; establish the `<None Update ... CopyToOutputDirectory=PreserveNewest>` vector-file convention (per-module CSVs arrive with their features).
- **NEW — reflection public-API guard** — assert that no exported member of `Enigma.Core` has a parameter, return type, base type, thrown-in-signature type, or public support-type member in an `Org.BouncyCastle.*` namespace (principle 1, now that BC is referenced). This test is the load-bearing guarantee for every downstream restoration.
- **NEW — RandomUtils guards** — `GenerateRandomBytes(0)` and `(-1)` throw `ArgumentException`; a positive size returns exactly that many bytes.
- **Deferred** — `EncodingExtensions` encode/decode round-trips → Encoding; `ProgressAndCancellation` Hash/BlockCipher `[Fact]`s → Hashing/Symmetric; `ArgumentValidationTests` + `CryptoKeyPairFixture` → split per feature (BC-free); `PemUtilsTests` → PublicKey.
- **Downstream vector-regeneration notes (established here, executed later)** — the harness convention foundation stands up will carry regenerated vectors in later features: SHA-3 per-size NIST FIPS 202 (old `sha3.csv` was 512-only), Argon2 absolute-KiB conversion (`memoryPowOfTwo`→KiB, e.g. 5→32), and PQC raw FIPS 203/204 key bytes. No vectors are copied in foundation itself — only the `CopyToOutputDirectory` wiring is put in place; foundation's own vectors are the inline RFC 4648 `foobar` values used by the (deferred) Encoding round-trips.

## Dependencies
**None.** `foundation` (FEATURE-61D1) has an empty dependency list and is the prerequisite for every implementation feature — `encoding` (FEATURE-0399), `hashing` (FEATURE-26A5), `keyderivation` (FEATURE-679F), `otp` (FEATURE-5761), `symmetric` (FEATURE-534F), `publickey` (FEATURE-2E3E), `pqc` (FEATURE-0D6D), `certificates` (FEATURE-099B) — all land after it because it adds the BouncyCastle/System.Buffers references, the multi-TFM test project, and the CSV harness they build on. One soft, one-directional link is deliberately severed: `EncodingExtensions` code compiles against the Encoding stubs and `CsvData.Hex` uses `System.Convert.FromHexString`, so foundation takes **no runtime dependency** on the Encoding feature.

## Acceptance criteria
1. `Enigma.Core.csproj` references `BouncyCastle.Cryptography` and `System.Buffers` (versions resolved from `Directory.Packages.props`: BC 2.6.2, System.Buffers 4.6.1); the library builds clean with **ZERO warnings** across `netstandard2.0;net8.0;net10.0` under `TreatWarningsAsErrors` + `EnforceCodeStyleInBuild` (verifies C# 14 `extension(...)` blocks lower cleanly on netstandard2.0 with PolySharp).
2. `tests/Enigma.Core.UnitTests` multi-targets `net8.0;net10.0` (MTP-native xunit.v3, `coverlet.collector` present); `dotnet test` is green on **both** TFMs.
3. `Extensions/StreamExtensions.*` ported to `Enigma.Core.Extensions` (public), `StreamReadHelpers` ported as internal; all ported round-trip + async round-trip tests pass on net8.0 and net10.0, including the `LengthValue` max/negative-length `InvalidOperationException` guards and the `TagLengthValue` tag+value round-trip.
4. `EncodingExtensions` ported and compiling clean (UTF-8 default, not `Encoding.Default`; `System.Text.Encoding` aliased to avoid the `Enigma.Core.Encoding` collision); its `GetBytes/GetString/UTF-8/ASCII` tests pass in foundation; its Base64/Hex/Base32 round-trip tests are deferred to the Encoding feature.
5. `Utils/RandomUtils.GenerateRandomBytes` ported to `Enigma.Core.Utils`; `(0)` and `(-1)` throw `ArgumentException`; a positive size returns exactly that many bytes; BouncyCastle `SecureRandom` stays internal.
6. CSV test-vector harness stood up: `CsvData.Rows` ported and `CsvData.Hex` reimplemented with `System.Convert.FromHexString` (no dependency on the Encoding stub); `SyncProgress<T>` ported; the `<None Update ... CopyToOutputDirectory=PreserveNewest>` vector-file convention is in place.
7. A reflection-based test proves **no** exported member of `Enigma.Core` has any `Org.BouncyCastle.*` type in a public signature, base type, thrown-in-signature type, or public support-type member (principle 1), now that BouncyCastle is referenced.
8. `PemUtils` and `X509Utils` are NOT introduced in foundation (remain deferred to PublicKey and Certificates as INTERNAL details); `ProgressAndCancellation` module tests, `ArgumentValidationTests`, `CryptoKeyPairFixture`, and `PemUtilsTests` remain deferred.
9. Roadmap (`docs/roadmap.md`) + plan status updated and the completion doc `docs/done/FEATURE-61D1.md` written per the house dev-workflow.
