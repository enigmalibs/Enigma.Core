# FEATURE-534F PHASE01 — Padding

- **Status:** DONE
- **Type:** FEATURE phase (1 of 3)
- **Branch:** `feature/feature-534f-phase01-padding` (cut from `feature/feature-5761-phase02-otp` @ `f63c043`)
- **Basis:** ported from Enigma.Cryptography v5.0.0 (`/home/jo/Dev/Enigma.Cryptography`), `Padding` module.

## Summary
Implemented the Padding module behind the API frozen by FEATURE-4442 PHASE02, ported at maximum fidelity
from v5.0.0 and kept strictly BouncyCastle-free on the public surface. The three service stubs
(`PaddingService`, `NoPaddingService`, `PaddingServiceFactory`) now work; the low-level
`PaddingScheme` → BouncyCastle-padding seam is re-introduced as an internal concern of `PaddingService`.
This is the dependency of the block-cipher padded path (PHASE02, untouched here).

**Key adaptation — scheme replaces the `Func<IBlockCipherPadding>` ctor.** The old `PaddingService`
took a public `Func<IBlockCipherPadding>` constructor (leaking the BouncyCastle padding type). Following
the frozen redesign and the house pattern already used by `HashService`, `PaddingService` now exposes
**only** an `internal PaddingService(PaddingScheme scheme)` constructor — construction is factory-only, so
the public surface exposes no BouncyCastle type and no parameterized constructor. The scheme→padder
mapping (and its BouncyCastle types) lives in a private method.

### Members implemented
- **`PaddingService`** — `internal PaddingService(PaddingScheme)`; `Pad`/`Unpad(byte[], int)` port the
  v5.0.0 logic verbatim (block-size validation 1..255, padded-length/alignment validation, PadCount-based
  unpadding). Private `CreatePadding()` maps `PaddingScheme` → BouncyCastle `Pkcs7Padding` /
  `ISO7816d4Padding` / `ISO10126d2Padding` / `X923Padding`.
- **`NoPaddingService`** — pass-through `Pad`/`Unpad` (null-guarded), returning the input unchanged
  (`PaddingScheme.None`).
- **`PaddingServiceFactory`** — the five `Create*Service()` members return the pass-through service or a
  scheme-configured `PaddingService`.

### Notable fidelity/behaviour decisions
- **ISO 10126-2 must be seeded.** BouncyCastle's `ISO10126d2Padding.AddPadding` dereferences its random
  source, so an un-`Init`-ed padder throws `NullReferenceException`. In v5.0.0 this scheme was never
  exercised by a Pad test (no `iso10126.csv`), so the latent gap was invisible. Here `CreatePadding()`
  seeds it with a fresh `Org.BouncyCastle.Security.SecureRandom` before use, and a new Pad/Unpad
  round-trip test proves it works.
- **X9.23 left zero-filling.** `X923Padding` zero-fills when no random source is supplied; that matches
  the ported `x923.csv` vectors, so it is deliberately **not** seeded (unlike ISO 10126-2).
- **Padding progress/cancellation not applicable.** The `IPaddingService` contract is synchronous
  (`byte[] Pad/Unpad(byte[], int)`) with no `IProgress`/`CancellationToken`, so the plan's "where
  applicable" progress/cancellation item does not apply to this module.

## Files / modules touched

### Modified — library (`src/Enigma.Core/Padding/`)
- `PaddingService.cs` — implemented; internal scheme ctor; private `PaddingScheme` → BouncyCastle padder
  seam; ISO 10126-2 seeded with `SecureRandom`.
- `NoPaddingService.cs` — implemented pass-through; scrubbed the skeleton-stub remark.
- `PaddingServiceFactory.cs` — implemented the five `Create*` members; no BouncyCastle `using` remains.

(`IPaddingService`, `IPaddingServiceFactory`, `PaddingScheme` were already frozen correctly — no change.)

### Created — tests (`tests/Enigma.Core.UnitTests/Padding/`)
- `Pkcs7PaddingTests.cs` — PKCS#7 KAT (Pad + Unpad) against `pkcs7.csv` (50 rows).
- `Iso7816PaddingTests.cs` — ISO/IEC 7816-4 KAT (Pad + Unpad) against `iso7816.csv` (50 rows).
- `X923PaddingTests.cs` — ANSI X9.23 KAT (Pad + Unpad) against `x923.csv` (50 rows), proving zero-fill.
- `Iso10126PaddingTests.cs` — ISO 10126-2 round-trip (random padding; block-aligned output, trailing
  length byte, Pad/Unpad recovers data) over seven data lengths — no KAT (padding is random).
- `PaddingServiceFactoryTests.cs` — factory returns the right service types, fresh instance per call,
  no-padding pass-through (same reference back), round-trip per scheme, and block-size / non-aligned
  validation guards.
- `PaddingBouncyCastleIsolationTests.cs` — reflection guard scoped to `Enigma.Core.Padding`.

### Created — test vectors (`tests/Enigma.Core.UnitTests/Padding/`)
- `pkcs7.csv`, `iso7816.csv`, `x923.csv` ported verbatim; auto-copied to output by the test project's
  existing `**/*.csv` PreserveNewest glob (no csproj change needed).

## Deviations & follow-ups
- **`Func<IBlockCipherPadding>` ctor dropped for an internal scheme ctor (design, not defect).** As above —
  faithful to the frozen redesign and consistent with `HashService`. Public surface exposes no
  constructor; construction is factory-only.
- **Scheme→padder seam kept private to `PaddingService`, not a separate internal factory.** The plan's
  mapping table anticipates an internal `BlockCipherPaddingFactory` under `Symmetric/BlockCiphers/`, but
  that file belongs to PHASE02's scope. Keeping the mapping private here keeps PHASE01 self-contained and
  does not preempt PHASE02; the block-cipher factory can be introduced (and reuse/duplicate the small
  four-case switch) when PHASE02 is built. No public-surface impact either way.
- **Line endings:** no CRLF/line-ending anomalies observed in the touched files (all LF); no action taken
  (recommendation-only per workflow).

## Build / test evidence
- **Build:** `dotnet build src/Enigma.Core` → **Build succeeded, 0 Warning(s), 0 Error(s)** across all
  three library TFMs (`netstandard2.0;net8.0;net10.0`) under `TreatWarningsAsErrors` +
  `GenerateDocumentationFile` + `EnforceCodeStyleInBuild`.
- **Tests:** `dotnet test` → **1468 passed, 0 failed, 0 skipped** across both test TFMs (`net8.0`,
  `net10.0`). The Padding namespace contributes 317 tests per TFM, confirmed to actually execute via
  `--filter-namespace Enigma.Core.UnitTests.Padding` (317 passed).
- **Acceptance criteria (PHASE01):** all met — PKCS#7 / ISO 7816-4 / X9.23 KAT vectors pass (Pad and
  Unpad, 50 rows each); ISO 10126-2 Pad/Unpad round-trip passes; no BouncyCastle type appears on the
  public Padding surface (namespace-scoped + assembly-wide reflection guards green); every padding
  service/factory member no longer throws `NotImplementedException`; XML docs present on every public
  member.

## Remaining
- **PHASE02** (`TODO`) — BlockCiphers (12 algorithms, 4 modes incl. GCM + AAD): internal engine/mode/
  parameters/padding factories, `BlockCipherService` + `BlockCipherServiceFactory`, GCM AAD restore.
- **PHASE03** (`TODO`) — StreamCiphers (ChaCha20 / ChaCha20-RFC7539 / Salsa20).
