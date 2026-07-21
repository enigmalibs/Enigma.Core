# FEATURE-5761 — OTP implementation (HOTP, TOTP, provisioning)

- **Status:** TODO
- **Type:** FEATURE (multi-phase — 2 phases)
- **Depends on:** FEATURE-26A5 (hashing — HMAC), FEATURE-0399 (encoding — Base32 provisioning), FEATURE-61D1 (foundation — RandomUtils)
- **Suggested branch (at build):** `feature/feature-5761-phaseNN-otp` (one branch per phase)
- **Basis:** ported from Enigma.Cryptography v5.0.0 (`/home/jo/Dev/Enigma.Cryptography`); redesign decisions validated by user 2026-07-21.

## Objective
Port HOTP (RFC 4226) and TOTP (RFC 6238) generation/verification, their factories, the `OtpHashAlgorithm` enum, and the deferred `OtpProvisioning` + `OtpAuthParameters` types from Enigma.Cryptography v5.0.0 into `Enigma.Core.Otp`, behind the FEATURE-4442 frozen contract that hides BouncyCastle. Per the authoritative user decision (2026-07-21) this feature targets **FULL RFC PARITY**: every capability the frozen surface dropped is **restored** — the HOTP look-ahead resync window + matched-counter reporting, TOTP matched-step reporting, `GetRemainingSeconds`, and a current-time convenience overload — while all BouncyCastle types stay strictly internal. The frozen skeleton is AMENDED (BC-free) to carry the restored members, and the deferred provisioning types are un-deferred as a DI service.

## Basis — port from Enigma.Cryptography v5.0.0
Exact old source files (from the spec's oldToNewMapping):
- `src/Enigma.Cryptography/Otp/OtpHashAlgorithm.cs` — already ported verbatim in PHASE04; confirm parity.
- `src/Enigma.Cryptography/Otp/IHotpService.cs`, `src/Enigma.Cryptography/Otp/HotpService.cs`
- `src/Enigma.Cryptography/Otp/IHotpServiceFactory.cs`, `src/Enigma.Cryptography/Otp/HotpServiceFactory.cs`
- `src/Enigma.Cryptography/Otp/ITotpService.cs`, `src/Enigma.Cryptography/Otp/TotpService.cs`
- `src/Enigma.Cryptography/Otp/ITotpServiceFactory.cs`, `src/Enigma.Cryptography/Otp/TotpServiceFactory.cs`
- `src/Enigma.Cryptography/Otp/OtpProvisioning.cs` (deferred → un-defer)
- `src/Enigma.Cryptography/Otp/OtpAuthParameters.cs` (deferred → un-defer)
- `src/Enigma.Cryptography/Utils/RandomUtils.cs` (support type → foundation/un-defer)
- Tests: `src/UnitTests/Otp/HotpTests.cs`, `TotpTests.cs`, `OtpProvisioningTests.cs`, `hotp.csv`, `totp.csv`; `src/UnitTests/Infrastructure/CsvData.cs`.

## Scope & mapping
| Old | New home | Disposition | Note |
|---|---|---|---|
| `Otp/OtpHashAlgorithm.cs` | `Enigma.Core/Otp/OtpHashAlgorithm.cs` | Ported (PHASE04) | `{Sha1,Sha256,Sha512}`, default `Sha1`; matches old exactly — confirm only |
| `Otp/IHotpService.cs` / `HotpService.cs` | same path | Implement + AMEND | `GenerateCode(byte[] secret,long counter)`; `VerifyCode(secret,counter,code)`; **AMEND**: add window + matched-counter overloads (restore) |
| `Otp/IHotpServiceFactory.cs` / `HotpServiceFactory.cs` | same | Implement | `CreateHotpService(int digits=6, OtpHashAlgorithm hashAlgorithm=Sha1)` — secret dropped; validates digits 4-9; ctor injects `IHmacServiceFactory` |
| `Otp/ITotpService.cs` / `TotpService.cs` | same | Implement + AMEND | `GenerateCode(secret,timestamp)`; `VerifyCode(secret,code,timestamp,window=1)`; **AMEND**: add matched-step overload, `GetRemainingSeconds`, and current-time convenience overloads (restore) |
| `Otp/ITotpServiceFactory.cs` / `TotpServiceFactory.cs` | same | Implement | `CreateTotpService(int digits=6,int periodSeconds=30,OtpHashAlgorithm hashAlgorithm=Sha1)`; validates digits 4-9 and period>0; ctor injects `IHotpServiceFactory` |
| `Otp/OtpProvisioning.cs` | `Enigma.Core/Otp/OtpProvisioning*.cs` | **Un-defer as DI service** | Becomes `IOtpProvisioningService` + `OtpProvisioningService` + factory (settled) |
| `Otp/OtpAuthParameters.cs` | `Enigma.Core/Otp/OtpAuthParameters.cs` | **Un-defer** | Result DTO; sealed class, port verbatim (names/nullability preserved) |
| `Utils/RandomUtils.cs` | `Enigma.Core/Utils/RandomUtils.cs` | Dependency (foundation) | Internal util wrapping BC `SecureRandom`; owned by foundation FEATURE-61D1, else un-deferred here |

## Contract amendments to the frozen skeleton (FEATURE-4442)
**Approved by user 2026-07-21.** Every amendment below is added to the frozen skeleton **first as a throwing stub** (`throw new NotImplementedException()`), then implemented in the phase noted. Every amendment keeps **principle 1 — no BouncyCastle type appears in any public signature, return type, parameter, or thrown-type**; BC (`Arrays.FixedTimeEquals`, `SecureRandom`) stays behind the implementation.

| Member | Signature (BC-free) | Restores (old member / test) | Notes |
|---|---|---|---|
| `IHotpService.VerifyCode` (window) | `bool VerifyCode(byte[] secret, long counter, string code, int window)` | old `Verify(string code, long counter, int window=0)` (RFC 4226 §7.4 forward resync) | New overload; `code` last per frozen convention; negative window throws `ArgumentOutOfRangeException` |
| `IHotpService.VerifyCode` (matched counter) | `bool VerifyCode(byte[] secret, long counter, string code, int window, out long matchedCounter)` | old `Verify(..., out long matchedCounter)`; `Verify_ForwardWindow_FindsDriftedCounter`, `Verify_OutsideWindow_ReturnsFalse` | `matchedCounter` = matched value, `-1` when none; constant-time over the whole window (no early exit) |
| `ITotpService.VerifyCode` (matched step) | `bool VerifyCode(byte[] secret, string code, DateTimeOffset timestamp, int window, out long matchedStep)` | old `Verify(code,window,out long matchedStep,timestamp?)`; `Verify_PreviousStepWithinWindow_MatchesAndReportsStep`, `Verify_NextStepWithinWindow` | `matchedStep` = matched time step, `-1` when none; for replay rejection |
| `ITotpService.GenerateCode` (now) | `string GenerateCode(byte[] secret)` | old `Generate(DateTimeOffset? = null)` → `UtcNow`; `Generate_DefaultTimestamp_UsesCurrentTime` | Convenience delegating to the explicit-timestamp overload with `DateTimeOffset.UtcNow`; explicit overload stays primary/testable |
| `ITotpService.VerifyCode` (now) | `bool VerifyCode(byte[] secret, string code, int window = 1)` | old `Verify` nullable-timestamp default | Convenience using `UtcNow`; distinguished from the timestamp overload by parameter type (int vs `DateTimeOffset`) |
| `ITotpService.GetRemainingSeconds` | `int GetRemainingSeconds(DateTimeOffset timestamp)` | old `GetRemainingSeconds(DateTimeOffset? = null)`; `GetRemainingSeconds_ReturnsSecondsLeftInStep` | Pure arithmetic (`period - unixSeconds % period`), returns 1..period |
| `ITotpService.GetRemainingSeconds` (now) | `int GetRemainingSeconds()` | convenience for the above | `UtcNow` convenience delegating to the explicit overload |
| `IOtpProvisioningService` (+ `OtpProvisioningService`) | `string BuildUri(OtpAuthParameters parameters)`; `OtpAuthParameters ParseUri(string uri)`; `byte[] GenerateSecret(int sizeBytes = 20)` | old `static class OtpProvisioning.{BuildUri,ParseUri,GenerateSecret}` | Un-deferred as an **injectable DI service** (settled by `orchestrator_impl_choices`), not a static helper; ctor takes `IEncodingServiceFactory` + `Utils/RandomUtils`; enforces 16-byte minimum secret |
| `IOtpProvisioningServiceFactory` (+ `OtpProvisioningServiceFactory`) | `IOtpProvisioningService CreateOtpProvisioningService()` | (Core DI parity) | Factory consistent with the rest of Core; ctor injects `IEncodingServiceFactory` |
| `OtpAuthParameters` | sealed class with positional ctor + get-only props `(string? Issuer, string AccountName, byte[] Secret, int Digits, int PeriodSeconds, OtpHashAlgorithm Algorithm)` | old `OtpAuthParameters` | Un-deferred verbatim; `Issuer` nullable; no BC types |

Internal (non-public) ctors implied by the redesign and added during implementation (not public surface): `HotpService(IHmacServiceFactory, int digits, OtpHashAlgorithm)` and `TotpService(IHotpServiceFactory, int digits, int periodSeconds, OtpHashAlgorithm)`, each throwing `ArgumentNullException` on a null collaborator (the Core factories preserve the old null-factory throw).

## BouncyCastle usage (internal only)
- `Org.BouncyCastle.Utilities.Arrays.FixedTimeEquals(byte[], byte[])` — constant-time comparison of candidate vs supplied code in HOTP `VerifyCode`, applied across the whole look-ahead window (no early exit). Internal only.
- `Org.BouncyCastle.Security.SecureRandom` — behind `Utils/RandomUtils.GenerateRandomBytes`, backing `OtpProvisioningService.GenerateSecret`. Internal only.
- BC HMAC/digest primitives — reached **only** through Core's `IHmacService.ComputeHmac(data, key)` (hashing feature); OTP never references BC HMAC types directly.
None of these appear in any public signature, base type, thrown-type, or public support member (enforced by a reflection test).

## Redesign decisions
### Already frozen (FEATURE-4442)
- Config-on-factory / secret-on-call: `digits`, `periodSeconds`, `hashAlgorithm` are `Create*Service` parameters; `secret` + `counter`/`timestamp` are per-call — a direct consequence of the Core HMAC redesign where the key became a per-call `ComputeHmac(data, key)` argument. Implementations create the (secret-independent) `IHmacService` once and pass the caller's secret per call.
- Explicit non-nullable `DateTimeOffset` on the primary TOTP `GenerateCode`/`VerifyCode` (deterministic/testable) — retained as the primary overloads.
- TOTP `window` kept on the call (default 1), not on the factory — matches old.
- `OtpHashAlgorithm {Sha1,Sha256,Sha512}` verbatim; sync-only APIs, no `bufferSize`; factory param named `hashAlgorithm`; `code` placed last in verify signatures.
- Digit/period/algorithm validation at `Create*Service` (digits 4-9, period>0 → `ArgumentOutOfRangeException`); null-secret/null-code validated at the call (`ArgumentNullException`).

### Restored per user validation (2026-07-21)
- **HOTP look-ahead window** — restored so RFC 4226 §7.4 server-side counter resync is expressible again (drift detection). Rationale: full RFC parity; the old library and its tests exercised it.
- **HOTP matched-counter out-param** — restored so a resync caller learns which counter matched (`-1` when none). Rationale: required to advance the server counter after drift.
- **TOTP matched-step out-param** — restored so callers can implement replay rejection (accept only steps greater than the last accepted). Rationale: security parity with the old service.
- **TOTP current-time convenience overloads** (`GenerateCode(secret)`, `VerifyCode(secret,code,window=1)`, `GetRemainingSeconds()`) — restored using `DateTimeOffset.UtcNow`, delegating to the explicit-timestamp overloads which remain primary/testable. Rationale: user directive to add the convenience while keeping determinism for tests.
- **TOTP `GetRemainingSeconds(DateTimeOffset)`** — restored as a pure-arithmetic UI countdown helper (1..period). Rationale: user directive; no BC involvement.
- **`OtpProvisioning` → DI service** (`IOtpProvisioningService` + `OtpProvisioningService` + factory) — un-deferred as an injectable service consuming `IEncodingServiceFactory` (Base32) + `Utils/RandomUtils`, replacing the old static helper. Rationale: settled by `orchestrator_impl_choices` for Core DI consistency and testability.
- **`OtpAuthParameters`** — un-deferred verbatim as a sealed class (positional ctor, get-only props, nullable `Issuer`), preserving the round-trip test. Rationale: minimal, safe DTO.

### Open for PR
- **Record modernization of `OtpAuthParameters`** (init-only props / `record`): cosmetic; recommended default = keep the sealed class as ported (preserves property names and the round-trip test). Flag at PR only if the team wants the modern shape.

## Test plan
- Copy `hotp.csv` and `totp.csv` into `tests/Enigma.Core.UnitTests/Otp/` and register them as `CopyToOutputDirectory=PreserveNewest` in the UnitTests csproj; reuse the `CsvData` loader ported to the foundation test harness (per `orchestrator_impl_choices`).
- **HOTP** (port `HotpTests.cs`, adapted to per-call secret): all 10 RFC 4226 Appendix D vectors via `GenerateCode` (secret ASCII `12345678901234567890`, counters 0-9); 8-digit case → `84755224` for counter 0; exact-counter `VerifyCode` true, wrong-code false. **Restored** and now ported in full: `Verify_ForwardWindow_FindsDriftedCounter`, `Verify_OutsideWindow_ReturnsFalse`, `Verify_DefaultWindow`, `Verify_NegativeWindow_Throws`, and matched-counter assertions (`-1` when none).
- **TOTP** (port `TotpTests.cs`): all 15 RFC 6238 Appendix B vectors (Sha1/Sha256/Sha512 seeds, 8 digits, five timestamps); exact/wrong verify; prev/next-step within window true and out-of-window false; constant-time over the window. **Restored** and now ported: `Verify_PreviousStepWithinWindow_MatchesAndReportsStep`, `Verify_NextStepWithinWindow` (matchedStep asserted), `Generate_DefaultTimestamp_UsesCurrentTime` (against the convenience overload), and `GetRemainingSeconds_ReturnsSecondsLeftInStep`.
- **Validation**: `Create*Service` throws `ArgumentOutOfRangeException` for digits outside 4-9 and period ≤ 0; `GenerateCode`/`VerifyCode` throw `ArgumentNullException` on null secret/code; Core factories throw `ArgumentNullException` on a null collaborating factory.
- **Provisioning** (port `OtpProvisioningTests.cs`, adapted to the DI service): BuildUri known-answer vector, escaping, no-issuer, build→parse round-trip, minimal-defaults, issuer precedence, format/invalid throws, `GenerateSecret` sizes + 16-byte minimum, null/blank guards.
- **New tests warranted by the redesign**:
  1. Reflection guard asserting **no public member across `Enigma.Core.Otp` exposes an `Org.BouncyCastle.*` type** (proves no BC leak); confirms `Arrays.FixedTimeEquals` and `SecureRandom` stay internal.
  2. Full suite build + run on all three TFMs (netstandard2.0, net8.0, net10.0) — verify no net-only/Span-only overloads slip in (`Uri.Escape/UnescapeDataString`, `DateTimeOffset.ToUnixTimeSeconds`, `StringBuilder`, `string.Split`, `CultureInfo.InvariantCulture` are all ns2.0-safe).
  3. Base32 seam test pinning the otpauth secret encoding across the encoding dependency: `12345678901234567890` → `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ` (padded/uppercase encode, tolerant decode).
- No vector regeneration required for OTP — `hotp.csv`/`totp.csv` are RFC known-answer vectors ported as-is.

## Dependencies
- **hashing — FEATURE-26A5** (must land first): HOTP composes over `Core.Hashing.Hmac` (`IHmacService`/`IHmacServiceFactory`); the HMAC key-per-call redesign is exactly what drives the OTP secret to be per-call. No real codes without it.
- **encoding — FEATURE-0399** (must land before Phase 2): `OtpProvisioningService` needs a parity-preserving Base32 service via `IEncodingServiceFactory.CreateBase32Service()` (padded/uppercase encode, tolerant decode).
- **foundation — FEATURE-61D1** (must land first): owns `Utils/RandomUtils` (BC `SecureRandom` wrapper) required by `GenerateSecret`, the internal BC package references, and the ported `CsvData`/`SyncProgress` test harness. If foundation does not own `Utils/RandomUtils`, this feature un-defers it locally.

## Phases
### Phase 1 — HOTP/TOTP services + factories (full RFC parity)
- **Scope**: Implement `HotpService`, `HotpServiceFactory`, `TotpService`, `TotpServiceFactory` against the frozen contract AMENDED with the restored members; compose over `Core.Hashing.Hmac`. Port RFC 4226 §5.3 dynamic truncation and RFC 6238 time→step mapping; constant-time compare via internal BC `Arrays.FixedTimeEquals` over the whole window. Add the internal collaborator ctors.
- **Members**: base `GenerateCode`/`VerifyCode`; **restored** HOTP window + matched-counter overloads, TOTP matched-step overload, `GetRemainingSeconds(DateTimeOffset)`, and the current-time convenience overloads. Each amendment lands first as a throwing stub, then implemented.
- **Tests**: `hotp.csv`/`totp.csv` vectors + all `HotpTests`/`TotpTests` behavior tests, including the restored window/matched-counter/matched-step/GetRemainingSeconds/default-timestamp tests; the reflection BC-leak guard.
- **Depends on**: hashing (FEATURE-26A5), foundation (FEATURE-61D1).
- **Acceptance**: all 10 HOTP + 15 TOTP vectors pass; resync window finds the drifted counter and reports `matchedCounter` (`-1` when none); TOTP `matchedStep` reported; `GetRemainingSeconds` in 1..period; no BC type in any public `Enigma.Core.Otp` signature (reflection-verified); zero-warning build + green suite on ns2.0/net8.0/net10.0.

### Phase 2 — Provisioning (un-defer as DI service)
- **Scope**: Un-defer `OtpAuthParameters` (sealed DTO, verbatim) and introduce `IOtpProvisioningService` + `OtpProvisioningService` + `IOtpProvisioningServiceFactory`/`OtpProvisioningServiceFactory` (DI). Wire Base32 via `IEncodingServiceFactory` and secure randomness via `Utils/RandomUtils`. Port the otpauth `GenerateSecret`/`BuildUri`/`ParseUri` logic and validation. Amendments land first as throwing stubs, then implemented.
- **Members**: `BuildUri`, `ParseUri`, `GenerateSecret`, the factory `Create` method, and the `OtpAuthParameters` DTO.
- **Tests**: all `OtpProvisioningTests` (known-answer BuildUri, escaping, no-issuer, round-trip, minimal-defaults, issuer precedence, format/invalid throws, `GenerateSecret` sizes + 16-byte minimum, null/blank guards) + the Base32 seam test.
- **Depends on**: encoding (FEATURE-0399), foundation (FEATURE-61D1).
- **Acceptance**: provisioning round-trips the exact known-answer otpauth URI; `GenerateSecret` honors size + minimum; all guards throw; no BC type in any public signature; zero-warning build + green suite on all three TFMs.

## Acceptance criteria
- Build is clean with **zero warnings** across `netstandard2.0;net8.0;net10.0` under `TreatWarningsAsErrors`.
- **No public member of `Enigma.Core.Otp` exposes any `Org.BouncyCastle.*` type** (reflection-checked); `Arrays.FixedTimeEquals` and `SecureRandom` remain internal.
- All 10 HOTP RFC 4226 Appendix D vectors (`hotp.csv`, counters 0-9) pass via `GenerateCode`; the 8-digit case yields `84755224` for counter 0.
- All 15 TOTP RFC 6238 Appendix B vectors (`totp.csv`) pass at 8 digits for Sha1/Sha256/Sha512 across all five timestamps.
- **Restored HOTP resync**: the window overload finds a drifted counter within the window, rejects codes outside it, throws on a negative window, and the matched-counter overload reports the matched counter (`-1` when none); verification is constant-time over the window (no early exit).
- **Restored TOTP replay support**: the matched-step overload reports the matching step (`-1` when none); prev/next-step within window accepted, out-of-window and wrong codes rejected.
- **Restored convenience**: `GenerateCode(secret)`, `VerifyCode(secret,code,window=1)`, and `GetRemainingSeconds()` behave as their explicit-timestamp counterparts at `DateTimeOffset.UtcNow`; `GetRemainingSeconds(DateTimeOffset)` returns 1..period.
- `Create*Service` validates digits (4-9) and period (>0) with `ArgumentOutOfRangeException`; `GenerateCode`/`VerifyCode` throw `ArgumentNullException` on null secret/code; Core factories throw `ArgumentNullException` on a null collaborating factory.
- `OtpProvisioningService` (DI) + `OtpAuthParameters` are un-deferred and functional: `BuildUri` produces the exact known-answer otpauth URI, `ParseUri` round-trips it, `GenerateSecret` honors size and enforces the 16-byte minimum, and all provisioning validation/format guards throw as before.
- Every restored member is implemented AND covered by a ported/new test; no obsolete test is left failing (previously-dropped tests are restored, not deleted).
- Every amendment was added first as a throwing stub, then implemented, and keeps principle-1 BC-hiding.
- Roadmap (`docs/roadmap.md`) and this plan's status are updated; completion records `docs/done/FEATURE-5761-PHASE01.md` and `docs/done/FEATURE-5761-PHASE02.md` are written.
- Test suite runs green on all three TFMs.
