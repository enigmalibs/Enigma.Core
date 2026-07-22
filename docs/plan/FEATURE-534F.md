# FEATURE-534F — Symmetric implementation (Block + Stream ciphers) + Padding

- **Status:** IN PROGRESS (PHASE01 done; PHASE02 next)
- **Type:** FEATURE (multi-phase — 3 phases)
- **Depends on:** FEATURE-61D1 (foundation — stream Extensions + package ref + harness)
- **Suggested branch (at build):** `feature/feature-534f-phaseNN-symmetric` (one branch per phase)
- **Basis:** ported from Enigma.Cryptography v5.0.0 (`/home/jo/Dev/Enigma.Cryptography`); redesign decisions validated by user 2026-07-21.

## Objective
Port the working symmetric-cipher and padding implementations from Enigma.Cryptography v5.0.0 into Enigma.Core behind the FEATURE-4442 frozen, BouncyCastle-free contracts, at **maximum fidelity** to v5.0.0. Fill the `BlockCipherService`/`BlockCipherServiceFactory`, `StreamCipherService`/`StreamCipherServiceFactory`, and `PaddingService`/`NoPaddingService`/`PaddingServiceFactory` stubs so every member works, keeping every BouncyCastle type strictly **internal** (never in a public signature, base type, thrown-type-in-signature, or public support member). Re-introduce, as **internal** types, the low-level engine/padding/parameters wiring that FEATURE-4442 dropped from the public API — the implementation still needs those seams. Restore the one dropped capability that touches the public surface — GCM associated data (AAD) — by amending the frozen contract.

## Basis — port from Enigma.Cryptography v5.0.0
Cited from the spec `oldToNewMapping`:
- `BlockCiphers/IBlockCipherService.cs`, `BlockCiphers/BlockCipherService.cs`
- `BlockCiphers/IBlockCipherServiceFactory.cs`, `BlockCiphers/BlockCipherServiceFactory.cs`
- `BlockCiphers/GcmMacSize.cs`
- `BlockCiphers/IBlockCipherEngineFactory.cs` + `BlockCipherEngineFactory.cs` (→ INTERNAL)
- `BlockCiphers/IBlockCipherPaddingFactory.cs` + `BlockCipherPaddingFactory.cs` (→ INTERNAL)
- `BlockCiphers/IBlockCipherParametersFactory.cs` + `BlockCipherParametersFactory.cs` (→ INTERNAL)
- `StreamCiphers/IStreamCipherService.cs`, `StreamCiphers/StreamCipherService.cs`, `StreamCiphers/IStreamCipherServiceFactory.cs`, `StreamCiphers/StreamCipherServiceFactory.cs`
- `Padding/IPaddingService.cs`, `Padding/PaddingService.cs`, `Padding/NoPaddingService.cs`, `Padding/IPaddingServiceFactory.cs`, `Padding/PaddingServiceFactory.cs`
- `Utils/RandomUtils.cs` (internal random source only)
- Tests + CSV vectors under `UnitTests/BlockCiphers`, `UnitTests/StreamCiphers`, `UnitTests/Padding`, and `UnitTests/Infrastructure/{CsvData.cs, ProgressAndCancellationTests.cs}`

## Scope & mapping
| Old | New home | Disposition | Note |
|-----|----------|-------------|------|
| `BlockCiphers/IBlockCipherService.cs` | `Symmetric/BlockCiphers/IBlockCipherService.cs` | Port (frozen + amended) | `ICipherParameters` → `byte[] key, byte[]? iv, BlockCipherMode, PaddingScheme=Pkcs7, int gcmMacSizeBits=GcmMacSize.MaxBits`; **amended** with trailing optional `byte[]? associatedData=null` (AAD restore) |
| `BlockCiphers/BlockCipherService.cs` | `Symmetric/BlockCiphers/BlockCipherService.cs` | Port (impl) | Public BC ctors gone; CipherStream/ArrayPool loop ported behind parameterless sealed class + internal ctor |
| `BlockCiphers/IBlockCipherServiceFactory.cs` | `Symmetric/BlockCiphers/IBlockCipherServiceFactory.cs` | Port (frozen) | 12 per-algorithm `Create<Algo>Service(int bufferSize)` |
| `BlockCiphers/BlockCipherServiceFactory.cs` | `Symmetric/BlockCiphers/BlockCipherServiceFactory.cs` | Port (impl) | Mode-wiring moves INTERNAL (selected by `BlockCipherMode`) |
| `BlockCiphers/GcmMacSize.cs` | `Symmetric/BlockCiphers/GcmMacSize.cs` | Port verbatim | Doc scrubbed of BC phrasing |
| `IBlockCipherEngineFactory` + impl | `Symmetric/BlockCiphers/` internal | INTERNAL (re-introduce) | Returns BC `IBlockCipher`; internal engine seam per algorithm |
| `IBlockCipherPaddingFactory` + impl | `Symmetric/BlockCiphers/` internal | INTERNAL (re-introduce) | Returns BC `IBlockCipherPadding`; keyed by `PaddingScheme` |
| `IBlockCipherParametersFactory` + impl | `Symmetric/BlockCiphers/` internal | INTERNAL (re-introduce) | Translates key/iv/mode/gcmMacSizeBits/**AAD** → BC `KeyParameter`/`ParametersWithIV`/`AeadParameters` |
| `StreamCiphers/IStreamCipherService.cs` | `Symmetric/StreamCiphers/IStreamCipherService.cs` | Port verbatim | Already BC-free |
| `StreamCiphers/StreamCipherService.cs` | `Symmetric/StreamCiphers/StreamCipherService.cs` | Port (impl) | Public BC ctor gone; internal `Func<IBufferedCipher>` wiring |
| `StreamCiphers/IStreamCipherServiceFactory.cs` | `Symmetric/StreamCiphers/IStreamCipherServiceFactory.cs` | Port verbatim | ChaCha7539 / ChaCha20 / Salsa20 |
| `StreamCiphers/StreamCipherServiceFactory.cs` | `Symmetric/StreamCiphers/StreamCipherServiceFactory.cs` | Port (impl) | Internal engine wiring |
| `Padding/IPaddingService.cs` | `Padding/IPaddingService.cs` | Port verbatim | `Pad`/`Unpad(byte[],int)` |
| `Padding/PaddingService.cs` | `Padding/PaddingService.cs` | Port (impl) | `Func<IBlockCipherPadding>` ctor → internal ctor taking `PaddingScheme` |
| `Padding/NoPaddingService.cs` | `Padding/NoPaddingService.cs` | Port verbatim | `PaddingScheme.None` |
| `Padding/IPaddingServiceFactory.cs` | `Padding/IPaddingServiceFactory.cs` | Port verbatim | 5 `Create*` methods |
| `Padding/PaddingServiceFactory.cs` | `Padding/PaddingServiceFactory.cs` | Port (impl) | BC padding types behind `PaddingScheme`; internal RNG for ISO10126/X923 |
| `Utils/RandomUtils.cs` | internal helper / test-only | Un-defer (internal) | Internal secure-random source; public BC-`SecureRandom`-based type NOT exposed |

## Contract amendments to the frozen skeleton (FEATURE-4442)
**Approved by user 2026-07-21.**

Every amendment below is added **first as a throwing stub** (the member is declared with its final BC-free signature and throws `NotImplementedException`), then implemented in its phase. Each amendment keeps **principle 1** intact — no BouncyCastle type appears in the signature (`associatedData` is a plain `byte[]?`); AAD is translated to BC `AeadParameters` only inside the internal parameters factory.

| Member | Signature (BC-free) | Restores (old member/test) | Notes |
|--------|---------------------|----------------------------|-------|
| `IBlockCipherService.EncryptAsync` | `Task EncryptAsync(Stream input, Stream output, byte[] key, byte[]? iv, BlockCipherMode mode, PaddingScheme padding = Pkcs7, int gcmMacSizeBits = GcmMacSize.MaxBits, byte[]? associatedData = null, IProgress<int>? progress = null, CancellationToken cancellationToken = default)` | Old `BlockCipherParametersFactory.CreateGcmParameters(key, nonce, associatedText, macSize)` AAD path | Trailing optional `byte[]? associatedData = null` inserted after `gcmMacSizeBits`, before the `progress`/`cancellationToken` tail. Used **only** for `BlockCipherMode.Gcm`; ignored (and must be null/empty or validated) for Ecb/Cbc/Ctr |
| `IBlockCipherService.DecryptAsync` | `Task DecryptAsync(Stream input, Stream output, byte[] key, byte[]? iv, BlockCipherMode mode, PaddingScheme padding = Pkcs7, int gcmMacSizeBits = GcmMacSize.MaxBits, byte[]? associatedData = null, IProgress<int>? progress = null, CancellationToken cancellationToken = default)` | same | The AAD supplied on decrypt must match the AAD used on encrypt or GCM authentication fails (wrapped exception per impl decision below) |

No factory or `GcmMacSize`/`PaddingScheme`/`BlockCipherMode` amendments are needed — AAD is a per-call service parameter only.

## BouncyCastle usage (internal only)
- **Engines:** `AesEngine, SerpentEngine, CamelliaEngine, TwofishEngine, BlowfishEngine, DesEngine, DesEdeEngine, Cast5Engine, IdeaEngine, SeedEngine, AriaEngine, SM4Engine`
- **Modes:** `EcbBlockCipher, CbcBlockCipher, SicBlockCipher` (== CTR), `GcmBlockCipher`
- **Buffered:** `BufferedBlockCipher, PaddedBufferedBlockCipher, BufferedAeadBlockCipher, BufferedStreamCipher`, and `IBufferedCipher`
- **Parameters:** `ICipherParameters, KeyParameter, ParametersWithIV, AeadParameters` (AeadParameters carries the AAD)
- **Paddings:** `IBlockCipherPadding, Pkcs7Padding, ISO7816d4Padding, ISO10126d2Padding, X923Padding`
- **Stream engines:** `ChaCha7539Engine, ChaChaEngine, Salsa20Engine`
- **Support:** `Org.BouncyCastle.Crypto.IO.CipherStream`, `Org.BouncyCastle.Security.CipherUtilities`, `Org.BouncyCastle.Security.SecureRandom` (ISO10126/X923 random padding), `Org.BouncyCastle.Crypto.InvalidCipherTextException` (GCM auth failure — caught and wrapped, never rethrown to callers).

None of these may appear in any public signature, base type, or public support-type member.

## Redesign decisions
### Already frozen (FEATURE-4442)
- `ICipherParameters` replaced by `byte[] key + byte[]? iv + BlockCipherMode + PaddingScheme=Pkcs7 + int gcmMacSizeBits=MaxBits` on Encrypt/DecryptAsync.
- `BlockCipherMode { Ecb, Cbc, Ctr, Gcm }` uses standard **Ctr** (not BC **SIC**).
- Factory redesigned per-mode → per-algorithm: 12 `Create<Algo>Service(int bufferSize)`; mode/padding/tag are per-call. CAST5 renamed to CAST-128 (`CreateCast128Service`).
- Low-level engine/padding/parameters factories dropped from the public API (principle 3).
- `PaddingScheme { None, Pkcs7, Iso7816, Iso10126, X923 }` is the single source of truth shared by the Padding module and the block-cipher `padding` param.
- `GcmMacSize` ported verbatim (Min 32 / Max 128 / IsValid); `MaxBits` is the `gcmMacSizeBits` default.
- StreamCiphers & Padding public contracts kept as-is (already BC-free); only their BC ctors/internals change.
- Service + Factory pattern, async-Stream + `IProgress<int>` + `CancellationToken`, and `bufferSize` (`CryptoDefaults.StreamBufferSize`) retained.

### Restored per user validation (2026-07-21)
- **GCM AAD (`gcmAad`) — RESTORED.** Optional `byte[]? associatedData` added to `EncryptAsync`/`DecryptAsync` (contract amendment above). Rationale: maximum-fidelity directive restores the old `CreateGcmParameters(..., associatedText, ...)` capability; a trailing optional param is a non-breaking append and keeps BC hidden (AAD → `AeadParameters` internally). Ported with a GCM+AAD round-trip test and an AAD-mismatch tamper test.

### Settled implementation decisions (orchestrator_impl_choices — no user question needed)
- **GCM auth-failure exception:** catch BC `InvalidCipherTextException` at the service boundary and wrap it in `System.Security.Cryptography.CryptographicException`. No BC exception escapes; the ported tamper test asserts the BCL type (`CryptographicException`), not the BC type.
- **GCM (and CTR where IV-incompatible) on 64-bit-block ciphers** (DES/3DES/Blowfish/CAST-128/IDEA): throw `ArgumentException`/`NotSupportedException` from the internal wiring; covered by a compatibility-matrix test.
- **BC engines/modes/parameters/padding wiring reintroduced as internal classes;** `BouncyCastle.Cryptography` + `System.Buffers` package references are added by the foundation feature.
- **Default padding vs KAT:** `Pkcs7` stays the ergonomic default; ECB/CBC KAT tests pass `PaddingScheme.None` explicitly to reproduce block-aligned vectors (test-porting rule).
- **Padding ignored for Ctr/Gcm:** the impl never wraps Ctr/Gcm in `PaddedBufferedBlockCipher`; a non-default padding value has no effect (test-proven).
- **ISO10126/X923 random source:** internal `SecureRandom`/`RandomNumberGenerator` supplied to the padders; X923 zero-fill-vs-random behavior preserved to match `x923.csv`; ISO10126 gets a round-trip test.
- **`PaddingService` scheme wiring:** internal ctor taking `PaddingScheme`; public surface stays parameterless; Pad/Unpad block-size (1..255) and padded-length validation preserved.
- **Dropped public service ctors** (`Func<IBufferedCipher>`, JCA `string` algorithm): reintroduced as internal ctors used only by the internal factory; the JCA-string escape hatch stays out of the public API (would leak BC/JCA naming).
- **IV/nonce validation:** explicit guard/`ArgumentException` for null iv on Cbc/Ctr/Gcm and wrong-length iv, on top of BC's own Init validation.
- **Multi-TFM:** impl compiles on netstandard2.0 via the `System.Buffers` `ArrayPool` and array-based `ReadAsync`/`WriteAsync`/`FlushAsync` overloads.

### Open for PR
None — every divergence in the spec is resolved by a validated decision or a settled implementation choice above.

## Test plan
- **Vectors + harness:** Copy all CSV resources into `Enigma.Core.UnitTests` under `BlockCiphers/`, `StreamCiphers/`, `Padding/` with `<None Update ... CopyToOutputDirectory="PreserveNewest"/>`. Port `CsvData` + `SyncProgress<T>` (to foundation per orchestrator choice); decode hex with `System.Convert.FromHexString` (no dependency on the Encoding feature). Add `coverlet.collector` for coverage.
- **Block KAT (ported, rewritten to frozen API):** AES/DES/3DES/Blowfish × CBC/ECB/CTR against `aes-cbc.csv, aes-ecb.csv, aes-ctr.csv, blowfish-{cbc,ecb,ctr}.csv, des-{cbc,ecb,ctr}.csv, tripledes-{cbc,ecb,ctr}.csv` (20 rows each) — call `Create<Algo>Service()` then `EncryptAsync(..., mode, PaddingScheme.None, ...)`. AES-GCM ciphertext+tag against `aes-gcm.csv` (20 rows).
- **SIC→Ctr:** rename `*SicTests` → `*CtrTests`, run `BlockCipherMode.Ctr` against the existing `*-ctr.csv`, confirming SIC==Ctr.
- **CAST5→CAST-128:** rename round-trips to `CreateCast128Service`.
- **`AdditionalEngineTests`:** round-trip Twofish, Serpent, Camellia, CAST-128, IDEA, SEED, ARIA, SM4 using `RandomNumberGenerator` (not `RandomUtils`); keep default `Pkcs7` there to also exercise padded round-trips — completing all 12 algorithms.
- **Stream KAT (ported, shape unchanged):** ChaCha20 (`chacha20.csv`), ChaCha20-RFC7539 (`chacha20rfc7539.csv`), Salsa20 (`salsa20.csv`).
- **Padding KAT (ported, API unchanged):** PKCS#7 (`pkcs7.csv`, 50 rows), ISO 7816-4 (`iso7816.csv`), X9.23 (`x923.csv`).
- **Progress/cancellation:** port `ProgressAndCancellationTests` to the new block API (progress reported; pre-cancelled token → `OperationCanceledException`).
- **New tests warranted by the redesign:**
  - (a) **Reflection guard** — asserts NO `Org.BouncyCastle` type appears in any public signature, base type, or public support member of the Symmetric/Padding surface (locks principle 1).
  - (b) **GCM tamper** — modified ciphertext → `System.Security.Cryptography.CryptographicException`.
  - (c) **GCM + AAD round-trip** (restored member) and **AAD-mismatch** → `CryptographicException`.
  - (d) **GCM/CTR on 64-bit-block algorithm rejection** (compatibility matrix).
  - (e) **Padding ignored for Ctr/Gcm** — non-default padding has no effect on output.
  - (f) **Pkcs7 non-block-aligned round-trip** for ECB/CBC.
  - (g) **Null/short IV validation.**
  - (h) **ISO 10126-2 round-trip** (random padding; Unpad recovers data — no KAT).
- No vector regeneration is required for this feature (all CSVs port as-is; SHA3/Argon2/PQC regeneration belongs to other features).

## Dependencies
- **foundation (FEATURE-61D1)** — must land first. It adds the `BouncyCastle.Cryptography` and `System.Buffers` package references (kept unreferenced during FEATURE-4442), provides `CryptoDefaults` (`StreamBufferSize`), and hosts the ported `CsvData` + `SyncProgress<T>` test harness and the BC-free `ArgumentValidationTests` scaffold. Without it the impl cannot reference BouncyCastle or `ArrayPool`.

No other feature is required; symmetric (FEATURE-534F) has no dependency on encoding (FEATURE-0399) because the test harness uses `Convert.FromHexString` rather than the Encoding feature.

## Phases
### Phase A — Padding
- **Status:** DONE (see docs/done/FEATURE-534F-PHASE01.md)
- **Scope:** Implement the Padding module first (it is the dependency of the block-cipher padded path). Re-introduce the internal `PaddingScheme` → BC-padding seam (`Pkcs7Padding`/`ISO7816d4Padding`/`ISO10126d2Padding`/`X923Padding`); implement `PaddingService` (internal ctor taking `PaddingScheme`), `NoPaddingService`, `PaddingServiceFactory`; supply an internal `SecureRandom`/RNG for ISO10126/X923; preserve Pad/Unpad validation (block size 1..255, padded-length checks).
- **Members/tests:** `IPaddingService`, `PaddingService`, `NoPaddingService`, `IPaddingServiceFactory`, `PaddingServiceFactory`; PKCS#7 / ISO 7816-4 / X9.23 KAT + ISO 10126-2 round-trip; padding progress/cancellation where applicable.
- **Acceptance:** padding KAT vectors pass; ISO10126 round-trip passes; no BC type in the public padding surface.

### Phase B — BlockCiphers (12 algorithms, 4 modes incl. GCM + AAD)
- **Scope:** Re-introduce internal engine factory (`AesEngine`..`SM4Engine`), internal mode wiring (`EcbBlockCipher`/`CbcBlockCipher`/`SicBlockCipher`/`GcmBlockCipher` + `BufferedBlockCipher`/`PaddedBufferedBlockCipher`/`BufferedAeadBlockCipher`), and internal parameters factory (`KeyParameter`/`ParametersWithIV`/`AeadParameters`, **including AAD**). Implement `BlockCipherService` (CipherStream + ArrayPool streaming) and `BlockCipherServiceFactory` (12 `Create<Algo>Service`). Enforce mode/algorithm compatibility (GCM/CTR 128-bit only), IV validation, `GcmMacSize` validation, wrap GCM auth failure in `CryptographicException`. **Restored member:** implement the `byte[]? associatedData` AAD path (added as a throwing stub at the start of this phase, then implemented).
- **Members/tests:** `IBlockCipherService` (+ AAD amendment), `BlockCipherService`, `IBlockCipherServiceFactory`, `BlockCipherServiceFactory`, `GcmMacSize`; AES/DES/3DES/Blowfish CBC+ECB+CTR KAT (`PaddingScheme.None`), AES-GCM KAT + tamper test, **GCM+AAD round-trip + AAD-mismatch test**, GCM/CTR-on-64-bit-block rejection, padding-ignored-on-Ctr/Gcm, Pkcs7 non-block-aligned round-trip, null/short IV validation, `AdditionalEngineTests` (8 remaining engines), progress/cancellation, and the no-BouncyCastle-in-public-API reflection guard.
- **Acceptance:** all block KAT pass; Ctr reproduces old SIC vectors; 12-algorithm round-trips pass; AAD round-trip passes; tamper/AAD-mismatch throw `CryptographicException`; 64-bit-block GCM/CTR rejected; reflection guard passes.

### Phase C — StreamCiphers
- **Scope:** Implement `StreamCipherService` (internal `BufferedStreamCipher` + `ParametersWithIV` wiring) and `StreamCipherServiceFactory` (`ChaCha7539Engine`/`ChaChaEngine`/`Salsa20Engine`). Public shape already matches.
- **Members/tests:** `IStreamCipherService`, `StreamCipherService`, `IStreamCipherServiceFactory`, `StreamCipherServiceFactory`; ChaCha20 / ChaCha20-RFC7539 / Salsa20 KAT.
- **Acceptance:** all stream KAT vectors pass; no BC type in the public stream surface.

## Acceptance criteria
- Enigma.Core builds clean with **zero warnings** across `netstandard2.0;net8.0;net10.0` under `TreatWarningsAsErrors` + `GenerateDocumentationFile` (no CS1591).
- No `Org.BouncyCastle` type appears in any public signature, base type, or public support member of the Symmetric/Padding surface; the reflection-based test enforces this and passes.
- The dropped low-level factories (engine/padding/parameters) exist only as internal types.
- All ported KAT vectors pass: AES/DES/3DES/Blowfish CBC, ECB and CTR (using `PaddingScheme.None`), and AES-GCM (ciphertext+tag) — 20 rows per file.
- `BlockCipherMode.Ctr` reproduces the old `*-ctr.csv` (formerly `*SicTests`) vectors exactly, confirming the SIC==Ctr mapping.
- Round-trip encrypt/decrypt succeeds for all 12 algorithms (AES, DES, 3DES, Blowfish, Twofish, Serpent, Camellia, CAST-128, IDEA, SEED, ARIA, SM4).
- **Restored AAD member implemented + tested:** GCM+AAD round-trip succeeds; AAD mismatch throws `System.Security.Cryptography.CryptographicException`.
- GCM tamper detection: decrypting modified ciphertext throws `CryptographicException` (never a raw BouncyCastle `InvalidCipherTextException`).
- Requesting `BlockCipherMode.Gcm` (or IV-incompatible `Ctr`) on a 64-bit-block algorithm (DES/3DES/Blowfish/CAST-128/IDEA) throws a clear, documented `ArgumentException`/`NotSupportedException`.
- `gcmMacSizeBits` validated via `GcmMacSize.IsValid` (invalid → `ArgumentException`); padding ignored for Ctr/Gcm (test-proven); null/short IV rejected with clear messages.
- Padding KAT vectors pass for PKCS#7, ISO 7816-4 and X9.23; ISO 10126-2 passes a Pad/Unpad round-trip.
- Stream cipher KAT vectors pass for ChaCha20, ChaCha20-RFC7539 and Salsa20.
- Progress reported and a pre-cancelled `CancellationToken` throws `OperationCanceledException` for block, stream and (where applicable) padding operations.
- All implemented service/factory members no longer throw `NotImplementedException`; XML docs present on every public member.
- Roadmap (`docs/roadmap.md`) and this plan's status updated; completion records written to `docs/done/FEATURE-534F-PHASE01.md` (Padding), `docs/done/FEATURE-534F-PHASE02.md` (BlockCiphers), `docs/done/FEATURE-534F-PHASE03.md` (StreamCiphers).
