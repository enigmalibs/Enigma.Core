# FEATURE-4442-PHASE04 — Otp + Encoding (DONE)

## Summary
Fourth phase of the abstraction skeleton: scaffolded the **Otp** (HOTP, TOTP) and **Encoding** (Base64,
Base32, Hex) modules as redesigned, BouncyCastle-free public contracts with empty
(`throw new NotImplementedException()`) implementations. No algorithm logic — later features fill the
stubs behind these stable interfaces. Both OTP schemes and all three encodings are in-memory operations,
so they use **sync** APIs with **no `bufferSize`** on their factories (mirroring the KeyDerivation
decision from PHASE03). The ported `OtpHashAlgorithm` enum carries BouncyCastle-free docs. Per the plan's
support-type triage, `OtpProvisioning` and `OtpAuthParameters` were **deferred** (no interface references
them) to the OTP implementation feature.

## Files/modules touched

### Created — `Enigma.Core.Otp` (`src/Enigma.Core/Otp/`)
- `OtpHashAlgorithm.cs` — ported enum `{ Sha1, Sha256, Sha512 }` (pure; the HMAC hash backing an OTP).
  Referenced by the HOTP/TOTP factories.
- `IHotpService.cs` — interface: `GenerateCode(byte[] secret, long counter) : string` +
  `VerifyCode(byte[] secret, long counter, string code) : bool` (RFC 4226).
- `HotpService.cs` — sealed stub (both methods throw).
- `IHotpServiceFactory.cs` — interface:
  `CreateHotpService(int digits = 6, OtpHashAlgorithm hashAlgorithm = OtpHashAlgorithm.Sha1)`.
- `HotpServiceFactory.cs` — sealed stub (method throws).
- `ITotpService.cs` — interface: `GenerateCode(byte[] secret, DateTimeOffset timestamp) : string` +
  `VerifyCode(byte[] secret, string code, DateTimeOffset timestamp, int window = 1) : bool` (RFC 6238).
- `TotpService.cs` — sealed stub (both methods throw).
- `ITotpServiceFactory.cs` — interface:
  `CreateTotpService(int digits = 6, int periodSeconds = 30, OtpHashAlgorithm hashAlgorithm = OtpHashAlgorithm.Sha1)`.
- `TotpServiceFactory.cs` — sealed stub (method throws).

### Created — `Enigma.Core.Encoding` (`src/Enigma.Core/Encoding/`)
- `IEncodingService.cs` — interface: `Encode(byte[] data) : string` + `Decode(string encoded) : byte[]`
  (exact inverses; one interface shared by all schemes).
- `Base64Service.cs` — sealed stub (both methods throw; Base64 / RFC 4648).
- `Base32Service.cs` — sealed stub (both methods throw; Base32 / RFC 4648).
- `HexService.cs` — sealed stub (both methods throw; hexadecimal / base-16).
- `IEncodingServiceFactory.cs` — interface: `CreateBase64Service`, `CreateBase32Service`,
  `CreateHexService`, each returning `IEncodingService`.
- `EncodingServiceFactory.cs` — sealed stub (all 3 methods throw).

### Modified — workflow tracking
- `docs/roadmap.md` — PHASE04 `TODO` → `IN PROGRESS` → `DONE` (base FEATURE-4442 stays `IN PROGRESS`;
  PHASE05–06 remain `TODO`).
- `docs/plan/FEATURE-4442.md` — PHASE04 status flips; recorded the full build-time signature design in the
  PHASE04 section (per principle 8), including the source-parity note.

## Design decisions (recorded for downstream phases)
- **Config on the factory, secrets/time on the service call.** The digit count, TOTP time-step length and
  hash algorithm are authenticator configuration (fixed for a given secret), so they are `Create*Service`
  parameters (principle 2 — "algorithm chosen via factory `Create*` methods and enums"); the secret +
  counter/timestamp vary per code, so they are service-method parameters. `OtpHashAlgorithm` is therefore
  referenced by the factories, matching the plan's "referenced by the HOTP/TOTP service factories".
- **In-memory ⇒ sync + no `bufferSize`.** OTP is an HMAC over a small moving factor; encoding is a whole
  buffer transform — neither streams, so (like the KDFs in PHASE03) the APIs are sync `byte[]`/`string`
  and the factories are parameterless per-variant `Create*` methods with no `bufferSize`.
- **TOTP takes an explicit `DateTimeOffset`, not an ambient clock.** Keeps the contract deterministic and
  testable; the `window` parameter models ±time-step clock-drift tolerance as a per-verification concern.
- **Single `IEncodingService`, per-scheme stubs, per-scheme factory methods.** The scheme is a factory
  choice, not a signature difference — consistent with the block-cipher/hash single-interface +
  per-algorithm-factory pattern rather than three divergent encoding interfaces.
- **All factory `Create*` members throw too** (principle 5 / acceptance 3), so no concrete stub needs
  constructor parameters — avoids unused-field/unread-parameter errors under `TreatWarningsAsErrors`.
- **`OtpProvisioning` + `OtpAuthParameters` deferred.** No service/factory interface references either
  (support-type triage), so both land with the OTP implementation feature — pull `OtpAuthParameters`
  forward only if a redesigned OTP service/factory later surfaces it.

## Deviations & follow-ups
- **Source-parity (no source library in the repo).** As in PHASE01–03, the original library isn't present,
  so signatures were designed at build time per principle 8. To verify against source at PR: (1) the exact
  `OtpHashAlgorithm` member set — chose `{Sha1, Sha256, Sha512}`, the RFC 6238 set; (2) whether the source
  OTP services exposed a current-time convenience overload, or placed the TOTP validation `window` on the
  factory rather than the call; (3) the exact `IEncodingService` member names and whether Base32/Hex
  carried scheme options (casing, padding). All are adjustable later without disturbing the skeleton
  (stubs throw).
- **`Encoding` namespace vs `System.Text.Encoding`.** The module namespace is `Enigma.Core.Encoding`
  (folder = namespace, per the plan's taxonomy). None of the stub files reference `System.Text`, so there
  is no ambiguity today; the implementation feature should add `using System.Text;` with an alias
  (e.g. `using SysEncoding = System.Text.Encoding;`) if it needs the BCL type from within this namespace.
- **Line endings (CRLF):** none observed — all new files are LF, consistent with `.gitattributes`
  `* text=auto eol=lf`. No action taken (recommendation-only per `dev-workflow`).
- **No new unit tests** (acceptance criterion 5): stubs throw, nothing meaningful to assert; real tests
  arrive with the OTP/encoding implementation features.

## Build/test evidence
- **Build:** `dotnet build Enigma.Core.slnx -warnaserror` → `Build succeeded. 0 Warning(s) 0 Error(s)`,
  producing `Enigma.Core.dll` for `netstandard2.0`, `net8.0`, and `net10.0` under `TreatWarningsAsErrors`
  + `GenerateDocumentationFile` (so all-public-members XML docs, CS1591, are enforced as errors).
- **Test:** `dotnet test --solution Enigma.Core.slnx` (MTP) → `Passed! total: 1, failed: 0, succeeded: 1,
  skipped: 0`. Definition-of-Done criterion 2 satisfied by the existing smoke test staying green (no new
  tests this phase, per acceptance criterion 5).
- **No BouncyCastle exposure:** `grep -rniE "bouncy|org\.bouncycastle|ICipherParameters|IPasswordFinder|
  IDigest|SecureRandom|BigInteger"` over `src/Enigma.Core/Otp` and `src/Enigma.Core/Encoding` returns no
  matches; `BouncyCastle.Cryptography` remains unreferenced by the project, so the clean build proves zero
  coupling.

## Acceptance criteria (per-phase list) — all met
1. ✅ Build clean (zero warnings) across `netstandard2.0`, `net8.0`, `net10.0` under `TreatWarningsAsErrors`.
2. ✅ No BouncyCastle types in any public signature, base type, or support-type member.
3. ✅ Every service/factory is a `sealed` class implementing its interface with `throw new
   NotImplementedException()` bodies (8 stub classes, 15 members).
4. ✅ XML docs on all public types/members (enforced by CS1591-as-error).
5. ✅ No new unit tests; existing smoke test passes green.
6. ✅ Roadmap + plan PHASE04 status updated; this completion doc written.
