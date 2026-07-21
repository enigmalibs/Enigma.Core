# FEATURE-4442-PHASE02 — Symmetric + Padding (DONE)

## Summary
Second phase of the abstraction skeleton: scaffolded the **Symmetric** (block ciphers, stream ciphers)
and **Padding** modules as redesigned, BouncyCastle-free public contracts with empty (`throw new
NotImplementedException()`) implementations. No algorithm logic — later features fill the stubs behind
these stable interfaces. The block-cipher API is the substantive redesign; stream-cipher and padding
public surfaces were already BouncyCastle-free in the source and were ported faithfully.

## Files/modules touched

### Created — `Enigma.Core.Symmetric.BlockCiphers` (`src/Enigma.Core/Symmetric/BlockCiphers/`)
- `BlockCipherMode.cs` — **new** enum `{ Ecb, Cbc, Ctr, Gcm }`. Uses the standard name `Ctr` rather
  than BouncyCastle's "SIC" (principle 1).
- `GcmMacSize.cs` — ported verbatim (pure validation: `MinBits`, `MaxBits`, `RangeDescription`,
  `IsValid`); public doc scrubbed of the "underlying BouncyCastle GCM mode" phrasing (principles 6/7).
- `IBlockCipherService.cs` — interface. `EncryptAsync`/`DecryptAsync(Stream, Stream, byte[] key,
  byte[]? iv, BlockCipherMode mode, PaddingScheme padding = Pkcs7, int gcmMacSizeBits =
  GcmMacSize.MaxBits, IProgress<int>?, CancellationToken)`. Replaces BouncyCastle `ICipherParameters`.
- `BlockCipherService.cs` — sealed stub implementing the interface (both methods throw).
- `IBlockCipherServiceFactory.cs` — interface with 12 per-algorithm `Create<Algo>Service(int bufferSize
  = CryptoDefaults.StreamBufferSize)` methods: AES, DES, TripleDes, Blowfish, Twofish, Serpent,
  Camellia, Cast128, Idea, Seed, Aria, Sm4. The BouncyCastle `Func<IBlockCipher>` /
  `Func<IBlockCipherPadding>` engine/padding-factory params are dropped (principle 3).
- `BlockCipherServiceFactory.cs` — sealed stub (all 12 methods throw).

### Created — `Enigma.Core.Symmetric.StreamCiphers` (`src/Enigma.Core/Symmetric/StreamCiphers/`)
- `IStreamCipherService.cs` — interface (`EncryptAsync`/`DecryptAsync(Stream, Stream, byte[] key,
  byte[] nonce, IProgress<int>?, CancellationToken)`); ported faithfully (source was already BC-free).
- `IStreamCipherServiceFactory.cs` — interface (`CreateChaCha7539Service`, `CreateChaCha20Service`,
  `CreateSalsa20Service`); ported faithfully.
- `StreamCipherService.cs`, `StreamCipherServiceFactory.cs` — sealed stubs (all members throw). Only
  the impls were BouncyCastle-coupled in the source.

### Created — `Enigma.Core.Padding` (`src/Enigma.Core/Padding/`)
- `PaddingScheme.cs` — **new** enum `{ None, Pkcs7, Iso7816, Iso10126, X923 }`. Replaces BouncyCastle
  `IBlockCipherPadding` types; referenced by both the Padding module and the block-cipher service's
  `padding` parameter (single source of truth).
- `IPaddingService.cs` — interface (`byte[] Pad/Unpad(byte[], int)`); ported verbatim (already BC-free).
- `IPaddingServiceFactory.cs` — interface (`CreateNoPaddingService`, `CreatePkcs7Service`,
  `CreateIso7816Service`, `CreateIso10126Service`, `CreateX923Service`); ported verbatim.
- `PaddingService.cs`, `NoPaddingService.cs`, `PaddingServiceFactory.cs` — sealed stubs (all members
  throw). The only source leak was `PaddingService`'s `Func<IBlockCipherPadding>` constructor, removed
  here; `NoPaddingService` kept as its own class per the plan; factory docs scrubbed of BouncyCastle.

### Dropped (principle 3, not ported)
- `IBlockCipherEngineFactory`, `IBlockCipherPaddingFactory`, `IBlockCipherParametersFactory` (+ impls) —
  low-level BouncyCastle factories, intentionally not part of the public API.

### Modified — workflow tracking
- `docs/roadmap.md` — PHASE02 `TODO` → `IN PROGRESS` → `DONE` (base FEATURE-4442 stays `IN PROGRESS`).
- `docs/plan/FEATURE-4442.md` — PHASE02 status flips; recorded the full build-time signature design in
  the PHASE02 section (per principle 8).

## Design decisions (recorded for downstream phases)
- **Block-cipher factory selects the algorithm; the service call selects mode/key/iv/padding/tag size.**
  The old factory created services per *mode* with a BouncyCastle engine delegate; the redesign flips to
  per-*algorithm* factory methods (the plan's explicit shape) with `BlockCipherMode` as a service-call
  parameter (the plan's explicit "byte[] key/byte[] iv + mode enum" replacement of `ICipherParameters`).
- **Padding and GCM tag size are optional service-call parameters**, preserving the configurability the
  old `Create*Service(paddingFactory)` overloads and GCM MAC size afforded — without any BouncyCastle
  type. `iv` is nullable (ECB uses none). GCM tag size is validated via the ported `GcmMacSize` helper by
  the later implementation.
- **New enums live in their owning module, not root** (consistent with PHASE01): `BlockCipherMode` in
  Symmetric.BlockCiphers, `PaddingScheme` in Padding. `PaddingScheme` is shared with the block-cipher
  service by cross-namespace reference (`using Enigma.Core.Padding;`), not by promotion to root — it is
  conceptually a padding-module type.
- **StreamCiphers kept per-algorithm factory methods, no enum.** The plan's "primitives + enums" note is
  satisfied by primitives (`byte[] key/nonce`) + the existing (already BouncyCastle-free) per-algorithm
  factory methods. Introducing a stream-cipher enum would gratuitously churn an already-clean contract
  and diverge from the block/stream factory pattern. Deviation from the literal wording, recorded here.
- **All factory `Create*` members throw too** (principle 5 / acceptance 3), so no concrete stub needs
  constructor parameters — this avoids unused-field/unread-parameter errors under `TreatWarningsAsErrors`.

## Deviations & follow-ups
- **"primitives + enums" (stream ciphers):** implemented as primitives + per-algorithm factory methods,
  no enum — see the design note above. Faithful to intent, not to the literal word "enums".
- **Padding on the block-cipher service:** the plan lists Padding as a separate module and does not
  explicitly place a `padding` param on the block-cipher service; I added it (optional) because the old
  block cipher owned padding selection (via the dropped BC padding factory) and dropping it would be a
  capability regression for streaming encryption. Recorded for PR review.
- **Line endings (CRLF):** none observed — all new files are LF, consistent with `.gitattributes`
  `* text=auto eol=lf`. No action taken (recommendation-only per `dev-workflow`).
- **No new unit tests** (acceptance criterion 5): stubs throw, nothing meaningful to assert; real tests
  arrive with the implementation features.

## Build/test evidence
- **Build:** `dotnet build Enigma.Core.slnx -warnaserror` → `Build succeeded. 0 Warning(s) 0 Error(s)`,
  producing `Enigma.Core.dll` for `netstandard2.0`, `net8.0`, and `net10.0` under `TreatWarningsAsErrors`
  + `GenerateDocumentationFile` (so all-public-members XML docs, CS1591, are enforced as errors).
- **Test:** `dotnet test --solution Enigma.Core.slnx` (MTP) → `Passed! total: 1, failed: 0, succeeded: 1,
  skipped: 0`. Definition-of-Done criterion 2 satisfied by the existing smoke test staying green.
- **No BouncyCastle exposure:** `grep -rniE "bouncy|org\.bouncycastle|ICipherParameters|IPasswordFinder"`
  over the new Symmetric/Padding source returns no matches (only substring hits on Enigma's own
  `IBlockCipherService`/`IBlockCipherServiceFactory`); `BouncyCastle.Cryptography` remains unreferenced
  by the project, so the clean build proves zero coupling.

## Acceptance criteria (per-phase list) — all met
1. ✅ Build clean (zero warnings) across `netstandard2.0`, `net8.0`, `net10.0` under `TreatWarningsAsErrors`.
2. ✅ No BouncyCastle types in any public signature, base type, or support-type member.
3. ✅ Every service/factory is a `sealed` class implementing its interface with `throw new
   NotImplementedException()` bodies.
4. ✅ XML docs on all public types/members (enforced by CS1591-as-error).
5. ✅ No new unit tests; existing smoke test passes green.
6. ✅ Roadmap + plan PHASE02 status updated; this completion doc written.
