# FEATURE-534F PHASE02 — BlockCiphers (12 algorithms, 4 modes incl. GCM + AAD)

- **Status:** DONE
- **Type:** FEATURE phase (2 of 3)
- **Branch:** `feature/feature-534f-phase02-blockciphers` (cut from `feature/feature-534f-phase01-padding` @ `465e82e`)
- **Basis:** ported from Enigma.Cryptography v5.0.0 (`/home/jo/Dev/Enigma.Cryptography`), `BlockCiphers` module.

## Summary
Implemented the block-cipher subsystem behind the API frozen by FEATURE-4442 PHASE02, ported at maximum
fidelity from v5.0.0 and kept strictly BouncyCastle-free on the public surface. All twelve algorithms
(AES, DES, 3DES, Blowfish, Twofish, Serpent, Camellia, CAST-128, IDEA, SEED, ARIA, SM4) work across four
modes (ECB, CBC, CTR (== BouncyCastle SIC), GCM), with per-call key/IV/mode/padding/tag-size and the
restored GCM associated-data (AAD) capability. The low-level engine/padding/parameters wiring that
FEATURE-4442 dropped is re-introduced as **internal** types.

**Key redesign — mode is now per-call, algorithm is per-service.** v5.0.0 baked the mode into the
service at construction (`CreateCbcService(engine)`) and exposed public `Func<IBufferedCipher>` / JCA
`string` constructors. Core's frozen redesign inverts this: the factory picks the **algorithm**
(`CreateAesService(bufferSize)`), and mode/padding/IV/tag/AAD are supplied per call on
`Encrypt/DecryptAsync`. `BlockCipherService` therefore holds only a `Func<IBlockCipher>` engine selector
(internal ctor, mirroring `HashService`) and assembles the buffered cipher per call from the requested
mode + padding. The dropped public BouncyCastle/JCA constructors are gone; construction is factory-only.

### Members implemented
- **`IBlockCipherService` (amended)** — added the optional `byte[]? associatedData = null` parameter to
  `EncryptAsync`/`DecryptAsync` (inserted after `gcmMacSizeBits`, before the `progress`/`cancellationToken`
  tail), with XML docs. AAD is a plain `byte[]?` on the surface; it becomes BouncyCastle `AeadParameters`
  only inside the internal parameters factory. GCM-only; rejected for other modes.
- **`BlockCipherService`** — internal `(Func<IBlockCipher>, bufferSize)` ctor; streaming encrypt/decrypt
  via `CipherStream` + `ArrayPool<byte>` (buffer cleared on return); per-call mode/padding wiring; full
  argument validation; GCM/CBC/ECB/CTR support.
- **`BlockCipherServiceFactory`** — the twelve `Create<Algo>Service(bufferSize)` members, each binding the
  matching engine constructor into a service.
- **`GcmMacSize`, `BlockCipherMode`** — already frozen correctly; unchanged.

### Internal seams re-introduced (all `internal`, invisible to the public surface)
- `IBlockCipherEngineFactory` + `BlockCipherEngineFactory` — algorithm → BouncyCastle `IBlockCipher`
  engine (CAST-128 → `Cast5Engine`, 3DES → `DesEdeEngine`).
- `IBlockCipherPaddingFactory` + `BlockCipherPaddingFactory` — `PaddingScheme` → BouncyCastle
  `IBlockCipherPadding` (ISO 10126-2 seeded with `SecureRandom`; X9.23 left zero-filling).
- `IBlockCipherParametersFactory` + `BlockCipherParametersFactory` — key/IV/mode/tag/**AAD** →
  `KeyParameter` / `ParametersWithIV` / `AeadParameters`.
- `NonDisposingStreamWrapper` — see *Adversarial review* below.

### Settled behaviours
- **CTR == SIC:** `BlockCipherMode.Ctr` wires BouncyCastle `SicBlockCipher` and reproduces the old
  `*-ctr.csv` (formerly `*SicTests`) vectors exactly.
- **GCM auth failure** and all other BouncyCastle cipher exceptions are wrapped in
  `System.Security.Cryptography.CryptographicException`; no BouncyCastle exception escapes (see review).
- **64-bit-block rejection:** GCM on a 64-bit-block algorithm (DES/3DES/Blowfish/CAST-128/IDEA) and a
  block-incompatible (over-length) CTR IV throw a clear `ArgumentException`.
- **Validation:** null key/stream; missing IV for CBC/CTR/GCM; wrong-length CBC IV; empty GCM nonce;
  `gcmMacSizeBits` via `GcmMacSize.IsValid`; AAD outside GCM rejected.
- **Padding:** ignored for CTR/GCM (test-proven byte-identical output); PKCS#7 is the ergonomic default;
  KAT uses `PaddingScheme.None` to reproduce block-aligned vectors.

## Files / modules touched

### Modified — library (`src/Enigma.Core/Symmetric/BlockCiphers/`)
- `IBlockCipherService.cs` — **amended** with the `associatedData` AAD parameter (+ docs).
- `BlockCipherService.cs` — implemented (streaming, validation, mode wiring, exception wrapping).
- `BlockCipherServiceFactory.cs` — implemented the twelve `Create<Algo>Service` members.

### Created — library (`src/Enigma.Core/Symmetric/BlockCiphers/`, all internal)
- `IBlockCipherEngineFactory.cs`, `BlockCipherEngineFactory.cs`
- `IBlockCipherPaddingFactory.cs`, `BlockCipherPaddingFactory.cs`
- `IBlockCipherParametersFactory.cs`, `BlockCipherParametersFactory.cs`
- `NonDisposingStreamWrapper.cs`

### Created — tests (`tests/Enigma.Core.UnitTests/BlockCiphers/`)
- `BlockCipherKat.cs` (shared KAT helper), `AesKatTests`, `DesKatTests`, `TripleDesKatTests`,
  `BlowfishKatTests` (CBC/ECB/CTR, `PaddingScheme.None`).
- `AesGcmTests` — GCM KAT + tamper + AAD round-trip + AAD-mismatch + missing-AAD.
- `AdditionalEngineTests` — round-trip for the eight non-KAT engines (default PKCS#7, `RandomNumberGenerator`).
- `BlockCipherModeCompatibilityTests` — GCM/CTR 64-bit rejection, invalid tag size.
- `BlockCipherValidationTests` — null/short IV, null key/stream, AAD-outside-GCM.
- `BlockCipherPaddingBehaviorTests` — PKCS#7 non-block-aligned round-trip; padding-ignored for CTR/GCM.
- `BlockCipherProgressAndCancellationTests` — progress reporting + pre-cancelled token.
- `BlockCipherServiceFactoryTests` — 12 services, fresh-per-call, bufferSize guard.
- `SymmetricBlockCipherBouncyCastleIsolationTests` — namespace-scoped principle-1 reflection guard.
- **Added after the adversarial review:** `BlockCipherErrorHandlingTests` (no-BC-exception-escape on
  corrupt/truncated/unaligned data, empty GCM nonce), `BlockCipherStreamLifetimeTests` (caller streams
  left open), `BlockCipherLargeStreamTests` (multi-buffer round-trip for CBC/CTR/GCM).

### Created — test vectors (`tests/Enigma.Core.UnitTests/BlockCiphers/`)
- `aes-{cbc,ecb,ctr,gcm}.csv`, `des-{cbc,ecb,ctr}.csv`, `tripledes-{cbc,ecb,ctr}.csv`,
  `blowfish-{cbc,ecb,ctr}.csv` — 13 files, ported verbatim (20 rows each); auto-copied by the test
  project's existing `**/*.csv` glob.

## Adversarial review & fixes
After the implementation was green, a multi-agent adversarial review (5 dimensions × independent
refute-by-default verification, 19 agents) audited what the KAT suite cannot prove. It produced 14 raw
findings → 10 confirmed / 4 refuted (refuted: AAD-parameter placement, `InnerException` reachability,
empty-plaintext coverage, and the 12×4 matrix coverage — all correctly dismissed). The confirmed
findings deduplicate to three real issues, all fixed in this dev:

1. **BouncyCastle exception leak (high).** `DecryptAsync` caught only `InvalidCipherTextException`, but
   `DataLengthException`/`OutputLengthException` are *siblings* under `CryptoException` — so a
   corrupt/truncated or non-block-aligned ciphertext leaked a raw BouncyCastle exception; `EncryptAsync`
   had no BouncyCastle catch at all (`PaddingScheme.None` + unaligned input leaked `DataLengthException`).
   **Fix:** both paths now `catch (CryptoException)` (the common BouncyCastle base) and rethrow
   `CryptographicException`. Regression-covered by `BlockCipherErrorHandlingTests`.
2. **Caller stream disposed (high/low).** BouncyCastle 2.6.2 `CipherStream.Dispose()` disposes the stream
   it wraps (no `leaveOpen`), so the service silently closed the caller's output (encrypt) / input
   (decrypt) stream. **Fix:** wrap the caller stream in the new internal `NonDisposingStreamWrapper`, so
   the final block/tag still flushes through but the caller's stream is never closed. Regression-covered
   by `BlockCipherStreamLifetimeTests`.
3. **Test-coverage gaps (low).** No >4 KB multi-buffer round-trip; empty-GCM-nonce and CBC/ECB
   corrupt-padding→`CryptographicException` unasserted. **Fix:** added `BlockCipherLargeStreamTests` and
   the error-handling cases above.

## Deviations & follow-ups
- **Public `Func<IBufferedCipher>` / JCA-string constructors dropped** (design, per the frozen redesign):
  reintroduced only as the internal `Func<IBlockCipher>` engine ctor; the JCA escape hatch stays out of
  the public API (it would leak BouncyCastle/JCA naming).
- **Improvements over the verbatim v5.0.0 port** (both make the public contract well-behaved without
  changing cryptographic behaviour): (a) all BouncyCastle cipher exceptions wrapped in
  `CryptographicException` — v5.0.0 let them escape; (b) caller streams are no longer disposed — v5.0.0
  (like this code before the review fix) disposed them via `CipherStream`. Both are noted here as
  deliberate, tested divergences.
- **Padding seam duplicated intentionally:** `BlockCipherPaddingFactory` (this phase) repeats the small
  `PaddingScheme`→BouncyCastle-padder switch that `PaddingService` (PHASE01) keeps private. The plan
  assigns the block-cipher padding factory to this phase's `Symmetric/BlockCiphers/` folder; unifying the
  two internal seams is a possible future cleanup with no public-surface impact.
- **Line endings:** no CRLF/line-ending anomalies observed in the touched files (all LF); no action taken
  (recommendation-only per workflow).

## Build / test evidence
- **Build:** `dotnet build -c Release` → **Build succeeded, 0 Warning(s), 0 Error(s)** across all three
  library TFMs (`netstandard2.0;net8.0;net10.0`) under `TreatWarningsAsErrors` +
  `GenerateDocumentationFile` + `EnforceCodeStyleInBuild`.
- **Tests:** `dotnet test` → **2632 passed, 0 failed, 0 skipped** across both test TFMs (`net8.0`,
  `net10.0`); +1164 over PHASE01's 1468. The BlockCiphers namespace contributes 582 tests per TFM,
  confirmed to execute via `--filter-namespace Enigma.Core.UnitTests.BlockCiphers`.
- **Acceptance criteria (PHASE02):** all met — AES/DES/3DES/Blowfish CBC/ECB/CTR KAT and AES-GCM KAT
  (ciphertext+tag) pass (20 rows/file); CTR reproduces the old SIC vectors; all 12 algorithms round-trip;
  AAD round-trip passes and AAD-mismatch throws `CryptographicException`; GCM tamper throws
  `CryptographicException` (never a raw BouncyCastle type); GCM/over-length-CTR on 64-bit-block algorithms
  rejected with a clear `ArgumentException`; `gcmMacSizeBits` validated; padding ignored for CTR/GCM
  (test-proven); null/short/empty IV rejected; namespace-scoped + assembly-wide BouncyCastle reflection
  guards green; every service/factory member no longer throws `NotImplementedException`; XML docs on every
  public member.

## Remaining
- **PHASE03** (`TODO`) — StreamCiphers (`StreamCipherService` + `StreamCipherServiceFactory`;
  ChaCha20 / ChaCha20-RFC7539 / Salsa20 KAT).
