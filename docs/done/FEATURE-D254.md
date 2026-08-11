# FEATURE-D254 — Checksum module (CRC-16 & CRC-32) — DONE

**Branch:** `feature/feature-d254-checksum-crc` (cut from `feature/feature-57a9-certificates-rsakey` @ `55fcd50`)
**Plan:** `docs/plan/FEATURE-D254.md` · single-phase

## Summary

Added a new top-level **`Enigma.Core.Checksum`** category exposing `IChecksumService` +
`IChecksumServiceFactory` in the house service + factory shape, backed by one hand-written,
table-driven CRC engine and offering **seven named variants** — five CRC-16 and two CRC-32.

The module is **purely additive**: no existing type, member or behaviour changed. It references
BouncyCastle nowhere at all (BouncyCastle 2.7.0 ships no usable CRC-16 or CRC-32 — see the plan's
*Planning-time evidence*), and adds no package to either project.

Design points carried through as planned:

- **Its own namespace, not `Hashing/`.** A CRC must never be substitutable for a cryptographic
  digest, so `IChecksumService` deliberately does not implement or extend `IHashService`. The
  separation is structural.
- **Both result shapes.** `byte[]` (big-endian, for framing) and `uint` (for comparison), each sync
  for buffers and async for streams, so neither a `MemoryStream` round-trip nor a hand-rolled unpack
  is ever forced on the caller.
- **Explicit variant names.** There is no `CreateCrc16Service()` / `CreateCrc32Service()`; each of
  the seven methods names its variant, with the familiar aliases and the published check value in the
  XML docs and the guide.
- **Pure managed, one code path on all three TFMs.** No `#if`, no `System.Runtime.Intrinsics`.

## Files created

**Product — `src/Enigma.Core/Checksum/` (6 files, all new)**

| File | Role |
|---|---|
| `IChecksumService.cs` | The service interface: `ChecksumSize` + the four compute members; carries the "not a security primitive" remark. |
| `IChecksumServiceFactory.cs` | The seven `Create…Service` methods, each documenting its aliases and check value. |
| `ChecksumServiceFactory.cs` | `public sealed`, parameterless, `new`-able; seven one-line methods, fresh instance per call. |
| `Crc16Service.cs` | `public sealed`, `internal` ctor, `ChecksumSize == 2`, big-endian 2-byte formatting. |
| `Crc32Service.cs` | `public sealed`, `internal` ctor, `ChecksumSize == 4`, big-endian 4-byte formatting. |
| `CrcParameters.cs` | `internal`; one static instance per variant — the single source of truth for the seven parameter sets. |
| `CrcTable.cs` | `internal`; table generation (reflected + MSB-first), the byte-fold loops, and the shared stream-read loop. |

**Tests — `tests/Enigma.Core.UnitTests/Checksum/` (7 files, all new)**

| File | Role |
|---|---|
| `BitwiseCrcOracle.cs` | Independent bit-by-bit reference CRC (no table, normal polynomial, explicit reflection) + the `ChecksumVariants` registry used by every theory. |
| `Crc16Tests.cs` | Five variants: check value, empty input, single byte, `ChecksumSize`, big-endian order, high-16-bits-zero, sync/async agreement. |
| `Crc32Tests.cs` | Two variants: same contract, plus a guard that ISO-HDLC and CRC-32C differ. |
| `ChecksumFuzzTests.cs` | Engine vs oracle and one-shot vs streamed over 7 variants × 9 lengths, plus a short-read stream and small `bufferSize`; also pins the oracle to the seven published check values. |
| `ChecksumProgressAndCancellationTests.cs` | Progress sums to the input length with >1 report; pre-cancelled token throws from both async members. |
| `ChecksumArgumentTests.cs` | Null `data` / null `input` with `ParamName`; `bufferSize` 0 and −1 on all seven factory methods. |
| `ChecksumServiceFactoryTests.cs` | Concrete type, working check value, and a fresh instance per call for each of the seven. |
| `ChecksumBouncyCastleIsolationTests.cs` | Namespace-filtered BouncyCastle guard + an assertion that `CrcParameters`/`CrcTable` are not exported and neither service has a public constructor. |

**Documentation modified**

| File | Change |
|---|---|
| `docs/guides/checksum.md` | **new** — the guide, in the established shape. |
| `docs/guides/README.md` | "Checksums" entry under *Data & helpers*. |
| `README.md` | `**Checksums**` bullet in the Features list; *Asynchronous, cancellable, observable* now names checksums among the streaming operations (doc-freshness sweep). |
| `CLAUDE.md` | `Checksum/` line in the project-layout block; *What this is* and the *Async / progress / cancellation* bullet now mention checksums (doc-freshness sweep). |
| `docs/roadmap.md`, `docs/plan/FEATURE-D254.md` | Status → `DONE`. |

## Build/test evidence

- **Build:** `dotnet build Enigma.Core.slnx -c Release` → **Build succeeded, 0 Warning(s), 0 Error(s)**
  across all three TFMs (`netstandard2.0`, `net8.0`, `net10.0`).
- **Tests:** `dotnet test --solution Enigma.Core.slnx -c Release` → **total 3902, failed 0,
  succeeded 3902, skipped 0**, green on both `net8.0` and `net10.0`.
- **Test count: 3644 → 3902** (+258 = **129 net-new test cases × 2 test TFMs**), all in `Checksum`.
- **Seven check values confirmed** over the ASCII bytes of `"123456789"`, asserted through the public
  surface *and* independently reproduced by `BitwiseCrcOracle`:
  ARC `0xBB3D` · CCITT-FALSE `0x29B1` · XMODEM `0x31C3` · MODBUS `0x4B37` · KERMIT `0x2189` ·
  ISO-HDLC `0xCBF43926` · CRC-32C `0xE3069283`.
- **Oracle parity holds** for all seven variants across lengths `{0, 1, 7, 255, 4095, 4096, 4097,
  8192, 12289}` of random data, and one-shot equals streamed for the same set — including through a
  stream that returns at most 3 bytes per read and with `bufferSize` of 1, 7 and 64.
- **Guide snippets compile-checked and executed** against the shipped assembly in a scratch
  `net10.0` console project (not committed); the two concrete values printed in the guide
  (`414FA339` for CRC-32 over the pangram, `CDC5` for the Modbus frame) are the program's real
  output.
- **Exported surface verified by reflection:** exactly `IChecksumService`, `IChecksumServiceFactory`,
  `ChecksumServiceFactory`, `Crc16Service`, `Crc32Service` in `Enigma.Core.Checksum`;
  `Crc16Service`/`Crc32Service` sealed with **0 public constructors**; `CrcParameters` and `CrcTable`
  not exported.
- **Isolation:** `Org.BouncyCastle` appears nowhere under `src/Enigma.Core/Checksum/` (grep clean,
  not even a `using`); `Api/BouncyCastleIsolationTests` and the new
  `ChecksumBouncyCastleIsolationTests` both green.
- **No package churn:** `Directory.Packages.props`, `Directory.Build.props` and both `.csproj` files
  are byte-identical to `HEAD`.
- **No collateral edits:** `src/Enigma.Core/Encoding/`, `src/Enigma.Core/Extensions/`,
  `src/Enigma.Core/Hashing/` and `docs/guides/encoding.md` are untouched (verified with
  `git status --porcelain`).

## Acceptance criteria

| # | Criterion | Evidence |
|---|---|---|
| 1 | Public surface is exactly the five planned types, XML-documented, factory parameterless | Reflection dump above; zero-warning build with `GenerateDocumentationFile=true` |
| 2 | Services `sealed` with `internal` ctors | `publicCtors=0` on both; `ChecksumInternals_AreNotExported` |
| 3 | Seven factory methods, exact names, `bufferSize` default, published check values | `Crc16Tests` / `Crc32Tests` / `ChecksumServiceFactoryTests` |
| 4 | No variant-ambiguous name; no checksum extension method | Reflection dump; `Extensions/` untouched and grep-clean |
| 5 | Big-endian bytes of `ChecksumSize` length, agreeing with the `uint`; CRC-16 high bits zero | `ComputeChecksum_IsBigEndianAndAgreesWithValue`, `ComputeChecksumValue_HighSixteenBitsAreZero` |
| 6 | Sync == async, one-shot == streamed, incl. short reads and a small `bufferSize` | `Async_AgreesWithSync`, `Streamed_…`, `ShortReadStream_…`, `SmallBufferSize_…` |
| 7 | Fuzz parity vs the bitwise oracle; oracle reproduces all seven check values | `TableEngine_MatchesBitwiseOracle_AcrossLengths`, `Oracle_ReproducesPublishedCheckValue` |
| 8 | Progress sums to input length with >1 report; pre-cancelled token throws from both async members | `ChecksumProgressAndCancellationTests` (4 theories) |
| 9 | Exception contract with the documented `ParamName`; `bufferSize <= 0` throws **at creation** | `ChecksumArgumentTests`, incl. `CreateService_ZeroBufferSize_ThrowsBeforeAnyComputation` |
| 10 | Fresh instance of the expected concrete type per call | `ChecksumServiceFactoryTests` |
| 11 | Both isolation guards green; no `Org.BouncyCastle` under `Checksum/` | Test run + grep |
| 12 | No new `PackageReference` / `Directory.Packages.props` entry | `git diff` empty for all four project/props files |
| 13 | No `#if` and no `System.Runtime.Intrinsics` under `Checksum/` | grep clean |
| 14 | `Encoding/`, `Extensions/`, `Hashing/`, `docs/guides/encoding.md` unmodified | `git status --porcelain` empty for those paths |
| 15 | Guide in the established shape, all seven variants with parameters and check values, security warning, compiling snippets; three indexes updated | `docs/guides/checksum.md` + scratch-project compile-and-run |
| 16 | Zero-warning Release build on three TFMs; suite green on net8.0 and net10.0 | Build/test output above |
| 17 | This completion doc records files, counts, check-value/oracle confirmation and the deliberate omissions | This document |
| 18 | Roadmap row flipped to `DONE` | `docs/roadmap.md` |

## Deviations & follow-ups

**Deviations from the plan**

1. **The compute core lives on `CrcTable`, not duplicated into each service.** The plan's design step 3
   described a private `ComputeCore` / `ComputeCoreAsync` pair *per service class*. Written literally
   that would put two near-identical `ArrayPool` read loops in `Crc16Service` and `Crc32Service` — the
   exact drift the plan's own "the read loop exists once" note exists to prevent. Instead
   `CrcTable.Compute` / `CrcTable.ComputeAsync` hold the single seeded-fold-finalise path (matching
   the plan's file-table description of `CrcTable.cs` as "table generation + the two update loops"),
   and the four public members on each service are thin wrappers doing the null guard and the
   big-endian formatting. Same public behaviour; the read loop now exists once for the whole module
   rather than once per class.
2. **Tables are cached per distinct (polynomial, reflected, width) key in a `ConcurrentDictionary`,
   built on first use, rather than in a static initializer.** This delivers the planned sharing (ARC
   and MODBUS share one table; differing `Init` does not affect the table) without a hand-maintained
   registry of the seven parameter sets, so "adding a variant is one `CrcParameters` line plus one
   factory method" holds literally. The build function is a pure function of the key, so a race can
   only ever produce identical candidates.
3. **`ChecksumVariants` (the variant-key registry used by the theories) shares
   `BitwiseCrcOracle.cs`** rather than getting its own file, keeping the test file list exactly as
   planned. It is a test-only type; the oracle's independence from the product engine is unaffected.
4. **The non-reflected fold is written generically over the width** rather than hard-coded to 16 bits.
   Both non-reflected variants shipped here are CRC-16, but a width-specific loop would be a silent
   trap for a future width-32 non-reflected variant. Costs one extra shift constant.

**Deliberate omissions — settled at interview, please do not re-litigate**

- **Base16 was requested and is deliberately NOT added.** `Enigma.Core.Encoding.HexService` already
  *is* RFC 4648 base-16 (`CreateHexService()`, `ToHexString()`/`FromHexString()`, `HexServiceTests`,
  a section in `docs/guides/encoding.md`). A `Base16Service` would be a second name for shipped
  behaviour. `Encoding/` and `docs/guides/encoding.md` were not touched.
- **No extension methods.** `bytes.ToCrc32()` would have to pick ISO-HDLC over CRC-32C behind the
  caller's back — the same ambiguity the explicit factory names remove. `EncodingExtensions` is
  untouched and no `ChecksumExtensions` exists.
- **No hardware intrinsics** (`Sse42` / `Arm.Crc32` for CRC-32C) and no slicing-by-N. One managed,
  table-driven code path on all three TFMs: one thing to test, and line-rate CRC is not this
  library's job. Revisitable later behind the same interface, provided both paths are proven to agree
  on every vector.
- **No other checksum families** (Adler-32, Fletcher, CRC-8, CRC-24, CRC-64, xxHash) and **no
  incremental `Update`/`Final` state** on the public interface. Both fit this interface additively;
  neither is planned. The internal engine already separates seed / fold / finalise, so incremental
  state could be added without reshaping it.

**Follow-ups**

- **FEATURE-19C7 (Release v2.0.0)** already depends on this item and covers the Checksum module in
  *New Features* and in the package `<Description>` / `<PackageTags>`. Nothing to do here beyond
  keeping that true; no version bump, release notes, tag or pack was performed by this item.
- **Line endings:** none to report. `.gitattributes` enforces `* text=auto eol=lf` and every new file
  is LF — no CRLF churn observed in this dev's diff.
