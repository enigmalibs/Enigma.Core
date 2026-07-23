# FEATURE-5761 PHASE01 — HOTP/TOTP services + factories (full RFC parity)

- **Status:** DONE
- **Type:** FEATURE phase (1 of 2)
- **Branch:** `feature/feature-679f-keyderivation` continued → dev branch `feature/feature-5761-phase01-otp` (cut from `feature/feature-679f-keyderivation` @ `8a3c95e`)
- **Basis:** ported from Enigma.Cryptography v5.0.0 (`/home/jo/Dev/Enigma.Cryptography`), `Otp` module (HOTP/TOTP).

## Summary
Implemented HOTP (RFC 4226) and TOTP (RFC 6238) generation/verification and their factories behind the
API frozen by FEATURE-4442 PHASE04, ported at maximum fidelity and AMENDED (BC-free) with every restored
member the user approved for full RFC parity. BouncyCastle stays strictly internal. PHASE02 (provisioning:
`OtpAuthParameters`, `IOtpProvisioningService`) is a separate dev and untouched here.

**Key adaptation — secret moved from construction to per call.** The old library baked the secret into
the HMAC service at construction (`CreateHmacSha1Service(secret)` + `ComputeHmac(data)`). Core's HMAC
redesign (FEATURE-26A5) made the key a per-call argument (`ComputeHmac(data, key)`). Accordingly:
- `HotpService` creates a single **secret-independent** `IHmacService` once at construction and threads
  the caller's `secret` through every `ComputeHmac(counterBytes, secret)` call.
- The Core factories no longer take a secret: `CreateHotpService(digits, hashAlgorithm)` /
  `CreateTotpService(digits, periodSeconds, hashAlgorithm)`.
- Old "null secret at Create" tests move to call time (`GenerateCode`/`VerifyCode` throw on null secret).
This is exactly what the plan anticipated (§Redesign / lines 57, 62).

### Members implemented
- **HOTP**: `GenerateCode(secret, counter)` (RFC 4226 §5.3 dynamic truncation); base
  `VerifyCode(secret, counter, code)`; **restored** `VerifyCode(secret, counter, code, window)` and
  `VerifyCode(secret, counter, code, window, out long matchedCounter)` — forward look-ahead resync,
  constant-time over the whole window (no early exit), `matchedCounter = -1` when none.
- **TOTP** (composed over HOTP): `GenerateCode(secret, timestamp)`; base
  `VerifyCode(secret, code, timestamp, window = 1)`; **restored**
  `VerifyCode(secret, code, timestamp, window, out long matchedStep)` (replay support, `-1` when none),
  the current-time convenience overloads `GenerateCode(secret)` / `VerifyCode(secret, code, window = 1)` /
  `GetRemainingSeconds()`, and `GetRemainingSeconds(DateTimeOffset)` (pure arithmetic, 1..period).
- **Factories**: `HotpServiceFactory(IHmacServiceFactory)` and
  `TotpServiceFactory(IHotpServiceFactory)` — DI ctors throwing `ArgumentNullException` on a null
  collaborator; internal `HotpService`/`TotpService` ctors validate digits (4-9) / period (>0) with
  `ArgumentOutOfRangeException`.

BouncyCastle (`Org.BouncyCastle.Utilities.Arrays.FixedTimeEquals` for the constant-time code compare, and
BC HMAC primitives reached only through Core `IHmacService`) is confined to service bodies — never on the
public surface.

## Files / modules touched

### Modified — library (`src/Enigma.Core/Otp/`)
- `IHotpService.cs` — **amended**: added the `window` and `window + out matchedCounter` `VerifyCode`
  overloads with XML docs.
- `HotpService.cs` — implemented; internal `(IHmacServiceFactory, digits, algorithm)` ctor; per-call
  secret; dynamic truncation; constant-time window scan.
- `HotpServiceFactory.cs` — implemented; injects `IHmacServiceFactory`; `CreateHotpService(digits, algorithm)`.
- `ITotpService.cs` — **amended**: added the matched-step overload, the current-time convenience overloads,
  and `GetRemainingSeconds` (both overloads), with XML docs.
- `TotpService.cs` — implemented; internal `(IHotpServiceFactory, digits, periodSeconds, algorithm)` ctor;
  symmetric window mapped onto HOTP's forward window; convenience overloads delegate to explicit ones.
- `TotpServiceFactory.cs` — implemented; injects `IHotpServiceFactory`; `CreateTotpService(digits, periodSeconds, algorithm)`.

(`OtpHashAlgorithm`, `IHotpServiceFactory`, `ITotpServiceFactory` were already frozen correctly — no change.)

### Created — tests (`tests/Enigma.Core.UnitTests/Otp/`)
- `HotpTests.cs` — RFC 4226 Appendix D CSV vectors (counters 0-9), 8-digit case (`84755224`), exact/wrong
  verify, default-window non-match, forward-window drift + `matchedCounter`, outside-window `-1`, negative
  window throws, null-secret (generate + verify) and null-code guards, invalid-digits + null-HMAC-factory guards.
- `TotpTests.cs` — RFC 6238 Appendix B CSV vectors (Sha1/256/512, 8 digits, five timestamps), default-
  timestamp convenience, exact/wrong verify, prev/next-step within window + `matchedStep`, outside-window
  `-1`, current-time verify convenience, negative window / null code / null secret guards,
  `GetRemainingSeconds` vectors + current-time convenience range, invalid-digits/period + null-HOTP-factory guards.
- `OtpBouncyCastleIsolationTests.cs` — reflection guard scoped to `Enigma.Core.Otp`.

### Created — test vectors (`tests/Enigma.Core.UnitTests/Otp/`)
- `hotp.csv` (10 rows) and `totp.csv` (15 rows) ported verbatim; auto-copied to output by the test
  project's existing `**/*.csv` PreserveNewest glob (no csproj change needed).

## Deviations & follow-ups
- **Secret ownership relocated (design, not defect).** As above — secret is per call, not per service, a
  direct consequence of the Core HMAC redesign; old ctor/factory `secret` parameter dropped and its
  null-guard tests moved to call time. Faithful to the frozen contract and the plan.
- **`Encoding` name collision.** The sibling namespace `Enigma.Core.Encoding` (product) /
  `Enigma.Core.UnitTests.Encoding` (tests) shadows the simple name `System.Text.Encoding` inside the OTP
  namespaces; `ConstantTimeEquals` and the test seed helpers use `global::System.Text.Encoding` to compile
  cleanly under the zero-warning / unnecessary-using analyzer.
- **Amendments landed fully implemented, not stub-first-then-filled.** The plan asked each amendment to be
  added as a throwing stub first and then implemented in separate history. Under this workflow all commits
  are the user's (one commit per dev) and I never commit, so the stub-first sub-step collapses into the
  single dev commit — same as recorded for FEATURE-26A5. Signatures + behaviour of every amendment are
  correct and tested.
- **Line endings:** no CRLF/line-ending anomalies observed in the touched files; no action taken
  (recommendation-only per workflow).

## Build / test evidence
- **Build:** `dotnet build -c Release` → **Build succeeded, 0 Warning(s), 0 Error(s)** across all three
  library TFMs (`netstandard2.0;net8.0;net10.0`) under `TreatWarningsAsErrors` + `GenerateDocumentationFile`.
- **Tests:** `dotnet test -c Release` → **786 passed, 0 failed, 0 skipped** across both test TFMs
  (`net8.0`, `net10.0`); +114 over the prior 672 (57 new OTP tests × 2 TFMs). The 57 were confirmed to
  actually execute via the xunit query filter `/*/Enigma.Core.UnitTests.Otp/*/*`.
- **Acceptance criteria (PHASE01):** all met — 10 HOTP + 15 TOTP RFC vectors pass; 8-digit counter 0 =
  `84755224`; HOTP resync finds the drifted counter and reports `matchedCounter` (`-1` when none), rejects
  outside-window codes, throws on negative window, scans constant-time; TOTP `matchedStep` reported (`-1`
  when none); prev/next-step accepted within window, out-of-window rejected; `GetRemainingSeconds`
  1..period and current-time convenience overloads behave as their explicit counterparts; `Create*Service`
  validates digits (4-9)/period(>0), calls throw on null secret/code, factories throw on null collaborator;
  namespace-scoped + assembly-wide BouncyCastle reflection guards green.

## Remaining
- **PHASE02** (`TODO`) — un-defer `OtpAuthParameters` + `IOtpProvisioningService`/`OtpProvisioningService`
  (+ factory) as a DI service over Base32 (FEATURE-0399) and `Utils/RandomUtils`; port
  `OtpProvisioningTests` + the Base32 seam test.
