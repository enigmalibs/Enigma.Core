# FEATURE-D254 — Checksum module (CRC-16 & CRC-32)

**Status:** TODO (single-phase)
**Type:** FEATURE
**Branch (at build time):** `feature/feature-d254-checksum-crc` — cut from current `HEAD`.

## Objective

Add a **Checksum** module to the library: a new top-level category `Enigma.Core.Checksum` exposing
`IChecksumService` + `IChecksumServiceFactory` in the house service + factory shape, backed by a single
hand-written table-driven CRC engine, and offering **seven named variants** — five CRC-16 and two
CRC-32.

The module is **purely additive**: no existing type, member or behaviour changes. It ships as part of
**2.0.0** (see FEATURE-19C7, amended by this planning pass).

**Base16 was requested and is deliberately NOT added.** `Enigma.Core.Encoding.HexService` already *is*
RFC 4648 base-16 (`CreateHexService()`, `ToHexString()`/`FromHexString()`, `HexServiceTests`, a section
in `docs/guides/encoding.md`). A `Base16Service` would be a second name for shipped behaviour, so the
option was rejected at interview in favour of no redundant surface. Do not re-open it inside this item.

## Context & constraints

- **Evolution of an existing, published codebase.** Enigma.Core 1.1.0 is on nuget.org. This item is
  additive and ships inside **2.0.0** alongside FEATURE-5413 / FEATURE-6852 / FEATURE-57A9. The MAJOR
  bump is driven by those items, **not** by this one.
- **Load-bearing invariant** — no `Org.BouncyCastle.*` type on any exported type or member
  (`tests/Enigma.Core.UnitTests/Api/BouncyCastleIsolationTests.cs` plus the per-category guards). This
  module references BouncyCastle **not at all**, so the guard is trivially satisfied today; the
  per-category test is still added (see design step 7) because every other category has one and it
  pins the property against future edits.
- Multi-targets `netstandard2.0;net8.0;net10.0`; `TreatWarningsAsErrors=true`,
  `EnforceCodeStyleInBuild=true`, `Nullable=enable`, `ImplicitUsings=disable`, `LangVersion=14`.
- Central Package Management — **no new packages**, product or test. The test oracle is written by
  hand in the test project precisely so `System.IO.Hashing` is not pulled in (rejected at interview:
  it would cover 1 of the 7 variants).
- Tests are MTP-native (`xunit.v3` + `coverlet.collector`), test TFMs `net8.0;net10.0`. Cancellation
  tokens in tests come from `TestContext.Current.CancellationToken` (existing convention).
- **The solution has no `InternalsVisibleTo` anywhere.** `CrcParameters` and `CrcTable` are therefore
  not directly testable; every assertion goes through the public surface. The bitwise oracle in the
  test project is an independent reimplementation, not a peek at internals.
- `.gitattributes` enforces `eol=lf` — **no line-ending recommendation to make**.
- `CryptoDefaults` lives in the root namespace `Enigma.Core` (`src/Enigma.Core/CryptoDefaults.cs`), so
  `CryptoDefaults.StreamBufferSize` resolves unqualified from `Enigma.Core.Checksum` with no `using`.
- Shared test scaffolding already exists and must be reused: `Infrastructure/SyncProgress.cs`
  (deterministic inline `IProgress<T>`) and `Enigma.Core.Utils.RandomUtils.GenerateRandomBytes`.

## Planning-time evidence (measured — do not re-derive)

Probed during the interview by reflecting over the **shipped** BouncyCastle.Cryptography 2.7.0
assemblies in the local NuGet cache (`lib/net461` and `lib/net6.0`, 2827 types); the repository was not
modified.

| Probe | Result |
|---|---|
| Types matching `Crc`/`CRC`/`Checksum`/`Adler`/`Fletcher` | exactly three: `Org.BouncyCastle.Utilities.Zlib.Adler32`, `Org.BouncyCastle.Utilities.Bzip2.CRC`, `Org.BouncyCastle.Bcpg.Crc24` |
| `Utilities.Zlib.Adler32` | **internal**; Adler-32, not a CRC |
| `Utilities.Bzip2.CRC` | **internal** — unreachable from outside the assembly — and it is the CRC-32/BZIP2 variant (non-reflected), not the standard CRC-32 |
| `Bcpg.Crc24` | public, but CRC-**24** for OpenPGP radix-64 armor; neither width is on offer |
| `Utilities.Encoders` namespace | `Base64`, `Hex`, `UrlBase64` and their encoders — no CRC entry point of any kind |
| **Conclusion** | BouncyCastle 2.7.0 offers **no usable CRC-16 and no usable CRC-32**. The engine must be written in-repo. |

**Precedent:** `src/Enigma.Core/Encoding/Base32Service.cs` is hand-rolled for exactly this reason
(BouncyCastle has no Base32). Follow its style — self-contained, table/lookup driven, no new dependency.

## Design decisions (from the interview)

1. **New top-level `Checksum/` category** — not `Hashing/Checksum/`, and **not** new methods on
   `IHashServiceFactory`. A CRC must never be substitutable for a cryptographic digest: if
   `CreateCrc32Service()` returned an `IHashService`, any consumer accepting an `IHashService` could be
   handed a 4-byte error-detection code and silently lose every security property. The separation is
   structural, not a documentation footnote.
2. **`IChecksumService` returns both shapes** — `byte[]` (big-endian, for framing) *and* `uint` (for
   comparison), each sync and async. CRC is overwhelmingly used on small in-memory buffers, so a
   stream-only API in the style of `IHashService` would force a `MemoryStream` + `await` for a 9-byte
   input; and a `byte[]`-only API would make every "compare a number" caller write its own unpack.
3. **Pure managed, table-driven, identical on all three TFMs.** No `System.Runtime.Intrinsics`, no
   `#if` branches. One code path means one thing to test, and hardware CRC only matters at line rate,
   which is not this library's job. Recorded as a deliberate trade-off — revisitable in a later item.
4. **Explicit variant name on every factory method.** No bare `CreateCrc16Service()` /
   `CreateCrc32Service()`, not even as documented aliases: a generic name silently binding to one of
   several incompatible parameter sets is precisely the failure this library exists to avoid. The
   familiar aliases live in the XML docs and the guide table instead.
5. **No extension methods.** `bytes.ToCrc32()` would have to pick ISO-HDLC over CRC-32C behind the
   caller's back — the same ambiguity decision 4 removes. `EncodingExtensions` stays untouched.
6. **Two public service classes**, `Crc16Service` and `Crc32Service`, `sealed` with **`internal`
   constructors** so only `ChecksumServiceFactory` can build them — mirroring `HashService` /
   `StreamCipherService`. Split by width (not one class) so `ChecksumSize` and the output length are a
   property of the type, and so the factory tests can assert the concrete type as the Encoding factory
   tests do.
7. **Variant parameters and lookup tables are internal and centralised** — one `CrcParameters` value
   per variant, one 256-entry `uint[]` table per variant built once in a static initializer. Adding a
   variant later means one `CrcParameters` line plus one factory method, and nothing else.
8. **Base16 dropped** (see *Objective*). `docs/guides/encoding.md` is **not** edited by this item — the
   optional "hex is RFC 4648 Base16" note was offered at interview and declined.

## Public surface added by this item

All in the new namespace `Enigma.Core.Checksum`.

```csharp
/// <summary>
/// Computes a cyclic-redundancy-check (CRC) checksum over data, using the variant selected by the
/// factory. NOT a cryptographic primitive: a CRC detects accidental corruption only and is trivially
/// forgeable — use IHmacService when integrity must hold against an adversary.
/// </summary>
public interface IChecksumService
{
    /// <summary>Length, in bytes, of the checksum this service produces (2 for CRC-16, 4 for CRC-32).</summary>
    int ChecksumSize { get; }

    byte[] ComputeChecksum(byte[] data);

    uint ComputeChecksumValue(byte[] data);

    Task<byte[]> ComputeChecksumAsync(
        Stream input,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);

    Task<uint> ComputeChecksumValueAsync(
        Stream input,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);
}

public interface IChecksumServiceFactory
{
    IChecksumService CreateCrc16ArcService(int bufferSize = CryptoDefaults.StreamBufferSize);
    IChecksumService CreateCrc16CcittFalseService(int bufferSize = CryptoDefaults.StreamBufferSize);
    IChecksumService CreateCrc16XmodemService(int bufferSize = CryptoDefaults.StreamBufferSize);
    IChecksumService CreateCrc16ModbusService(int bufferSize = CryptoDefaults.StreamBufferSize);
    IChecksumService CreateCrc16KermitService(int bufferSize = CryptoDefaults.StreamBufferSize);
    IChecksumService CreateCrc32IsoHdlcService(int bufferSize = CryptoDefaults.StreamBufferSize);
    IChecksumService CreateCrc32CService(int bufferSize = CryptoDefaults.StreamBufferSize);
}

public sealed class ChecksumServiceFactory : IChecksumServiceFactory;   // parameterless, `new`-able

public sealed class Crc16Service : IChecksumService { internal Crc16Service(/* …, int bufferSize */); }
public sealed class Crc32Service : IChecksumService { internal Crc32Service(/* …, int bufferSize */); }
```

Contract notes:

- `ComputeChecksum` returns **big-endian** (most-significant byte first) bytes of length
  `ChecksumSize` — network/frame order, and the order in which digests read.
- `ComputeChecksumValue` returns the same value as a `uint`; for CRC-16 it sits in the **low 16 bits**
  and the high 16 bits are **zero**.
- `ComputeChecksum(data)` and `ComputeChecksumValue(data)` always agree, as do the sync and async pairs
  for the same input.
- Services are **stateless per call** and the lookup tables immutable, so a single instance is safe to
  share across threads. XML-document this (it is the one behavioural guarantee a consumer would
  otherwise have to guess at).
- `bufferSize` controls the async read buffer only; it cannot change the result.
- Every XML doc comment on a factory method names the variant's familiar aliases and its published
  check value, and every one of the seven carries the "not for security" warning by reference to the
  interface remark.

## CRC variant parameters (authoritative — implement exactly this)

`check` is the CRC of the ASCII bytes of `"123456789"` and is the published catalogue value; it is what
the tests assert.

| Factory method | Variant (catalogue name) | Width | Poly (normal) | Poly (reflected form to table) | Init | Ref in/out | XorOut | **Check** |
|---|---|---|---|---|---|---|---|---|
| `CreateCrc16ArcService` | CRC-16/ARC (IBM, LHA, ZMODEM) | 16 | 0x8005 | 0xA001 | 0x0000 | true | 0x0000 | **0xBB3D** |
| `CreateCrc16CcittFalseService` | CRC-16/IBM-3740 ("CCITT-FALSE") | 16 | 0x1021 | — (MSB-first) | 0xFFFF | false | 0x0000 | **0x29B1** |
| `CreateCrc16XmodemService` | CRC-16/XMODEM | 16 | 0x1021 | — (MSB-first) | 0x0000 | false | 0x0000 | **0x31C3** |
| `CreateCrc16ModbusService` | CRC-16/MODBUS | 16 | 0x8005 | 0xA001 | 0xFFFF | true | 0x0000 | **0x4B37** |
| `CreateCrc16KermitService` | CRC-16/KERMIT | 16 | 0x1021 | 0x8408 | 0x0000 | true | 0x0000 | **0x2189** |
| `CreateCrc32IsoHdlcService` | CRC-32/ISO-HDLC (zip, gzip, PNG, Ethernet) | 32 | 0x04C11DB7 | 0xEDB88320 | 0xFFFFFFFF | true | 0xFFFFFFFF | **0xCBF43926** |
| `CreateCrc32CService` | CRC-32C / Castagnoli (iSCSI, SCTP) | 32 | 0x1EDC6F41 | 0x82F63B78 | 0xFFFFFFFF | true | 0xFFFFFFFF | **0xE3069283** |

## Exception contract

| Condition | Exception | `ParamName` |
|---|---|---|
| `ComputeChecksum` / `ComputeChecksumValue` with `data == null` | `ArgumentNullException` | `data` |
| `ComputeChecksumAsync` / `ComputeChecksumValueAsync` with `input == null` | `ArgumentNullException` | `input` |
| any factory method with `bufferSize <= 0` | `ArgumentOutOfRangeException` **at creation** | `bufferSize` |
| cancellation requested (before or during the read loop) | `OperationCanceledException` | — |

No new exception type is introduced. Null guards run **before** any work. The non-positive-buffer guard
throws at creation for the same reason `HashService` does: a non-positive buffer would make the read
loop exit before consuming the stream, and the service would silently return the CRC of the empty
message (see `HashService.cs:29-31` and the comment at `HashingArgumentTests.cs:59-61`).

## Scope

**In scope**

| File | Change |
|---|---|
| `src/Enigma.Core/Checksum/IChecksumService.cs` | **new** — the interface above |
| `src/Enigma.Core/Checksum/IChecksumServiceFactory.cs` | **new** — the seven `Create…Service` methods |
| `src/Enigma.Core/Checksum/ChecksumServiceFactory.cs` | **new** — `public sealed`, parameterless |
| `src/Enigma.Core/Checksum/Crc16Service.cs` | **new** — `public sealed`, `internal` ctor, `ChecksumSize == 2` |
| `src/Enigma.Core/Checksum/Crc32Service.cs` | **new** — `public sealed`, `internal` ctor, `ChecksumSize == 4` |
| `src/Enigma.Core/Checksum/CrcParameters.cs` | **new** — `internal`; one static instance per variant |
| `src/Enigma.Core/Checksum/CrcTable.cs` | **new** — `internal`; table generation + the two update loops |
| `tests/Enigma.Core.UnitTests/Checksum/BitwiseCrcOracle.cs` | **new** — independent bit-by-bit reference implementation (test-only) |
| `tests/Enigma.Core.UnitTests/Checksum/Crc16Tests.cs` | **new** — check values + contract, five variants |
| `tests/Enigma.Core.UnitTests/Checksum/Crc32Tests.cs` | **new** — check values + contract, two variants |
| `tests/Enigma.Core.UnitTests/Checksum/ChecksumFuzzTests.cs` | **new** — table engine vs oracle, random lengths, chunk boundaries |
| `tests/Enigma.Core.UnitTests/Checksum/ChecksumProgressAndCancellationTests.cs` | **new** |
| `tests/Enigma.Core.UnitTests/Checksum/ChecksumArgumentTests.cs` | **new** |
| `tests/Enigma.Core.UnitTests/Checksum/ChecksumServiceFactoryTests.cs` | **new** |
| `tests/Enigma.Core.UnitTests/Checksum/ChecksumBouncyCastleIsolationTests.cs` | **new** — namespace-filtered guard, shaped like `Encoding/EncodingBouncyCastleIsolationTests.cs` |
| `docs/guides/checksum.md` | **new** — guide in the established shape |
| `docs/guides/README.md` | **new** "Checksums" entry under *Data & helpers* |
| `README.md` | **new** `**Checksums**` bullet in the Features list |
| `CLAUDE.md` | **new** `Checksum/` line in the project-layout block |

**Out of scope**

- **Base16 / any change to `Encoding/`** — including `docs/guides/encoding.md` (decision 8).
- **Extension methods** — `EncodingExtensions` is not touched, and no `ChecksumExtensions` is created
  (decision 5).
- **`IHashService` / `IHashServiceFactory` / `Hashing/`** — not touched, not extended (decision 1).
- Hardware intrinsics, slicing-by-N tables, or any per-TFM code path (decision 3).
- Other checksum families — Adler-32, Fletcher, CRC-8, CRC-24, CRC-64, xxHash. Not planned; a future
  item can add them behind the same interface.
- Incremental/resumable state (`Update` … `Final`) on the public interface. Not planned; the internal
  engine is written so it could be added additively later.
- Any release action: version bump, `RELEASENOTES.md`, tagging, packing — all belong to FEATURE-19C7.
- `Directory.Packages.props` / `Directory.Build.props` — no new package, no new build property.

## Design / approach

1. **`CrcParameters`** — `internal sealed class` (or `readonly record struct`; either is fine as long as
   it stays internal) holding `Width`, `Polynomial` (already in the form the table generator wants),
   `Init`, `Reflected`, `XorOut`, and the variant's display name for use in exception/debug text. One
   `internal static readonly` instance per row of the parameter table above, named after the variant
   (`Crc16Arc`, `Crc16CcittFalse`, `Crc16Xmodem`, `Crc16Modbus`, `Crc16Kermit`, `Crc32IsoHdlc`,
   `Crc32C`). This type is the single source of truth for the seven parameter sets.

2. **`CrcTable`** — `internal` table generation and the two update loops. All arithmetic in `uint`.

   - **Reflected variants** (ARC, MODBUS, KERMIT, ISO-HDLC, CRC-32C), table built from the reflected
     polynomial:
     ```
     for i in 0..255:
         crc = i
         repeat 8: crc = (crc & 1) != 0 ? (crc >> 1) ^ reflectedPoly : crc >> 1
         table[i] = crc                      // for width 16, mask each step with 0xFFFF
     update:  crc = (crc >> 8) ^ table[(crc ^ b) & 0xFF]
     ```
   - **Non-reflected variants** (CCITT-FALSE, XMODEM), MSB-first, width 16:
     ```
     for i in 0..255:
         crc = i << 8
         repeat 8: crc = (crc & 0x8000) != 0 ? ((crc << 1) ^ poly) & 0xFFFF : (crc << 1) & 0xFFFF
         table[i] = crc
     update:  crc = ((crc << 8) & 0xFFFF) ^ table[((crc >> 8) ^ b) & 0xFF]
     ```
   - **Seeding:** the register starts at `Init` **directly**. This is correct only because every
     shipped variant's `Init` is reflection-symmetric (`0x0000`, `0xFFFF`, `0xFFFFFFFF`). Add a comment
     stating that a future variant with an asymmetric `Init` on the reflected path must have its `Init`
     bit-reflected before seeding — this is the classic silent-wrong-answer trap in CRC code.
   - **Finalisation:** `crc ^= XorOut`, then mask to the width (`0xFFFF` for CRC-16).
   - Tables are `static readonly uint[]` built once per variant in a static initializer, keyed so each
     parameter set has exactly one table (two variants that share a polynomial and reflection — ARC and
     MODBUS — may share one table; differing `Init` does not affect the table). Sharing is an
     optimisation, not a requirement: correctness first.
   - No `unsafe`, no `Span`-only APIs that are unavailable on netstandard2.0.

3. **`Crc16Service` / `Crc32Service`** — `public sealed`, `internal` constructor taking the
   `CrcParameters` and `bufferSize`, validating `bufferSize > 0` (`ArgumentOutOfRangeException`).
   `ChecksumSize` returns 2 / 4 respectively. Structure:

   - one private `uint ComputeCore(byte[] data)` and one private
     `Task<uint> ComputeCoreAsync(Stream, IProgress<int>?, CancellationToken)`;
   - the four public members are thin wrappers — the `byte[]` ones format the `uint` big-endian, the
     value ones return it as-is. **The read loop exists once**, so the two async members cannot drift.
   - The async loop mirrors `HashService.ComputeHashAsync` exactly: null guard, then
     `cancellationToken.ThrowIfCancellationRequested()`, rent from `ArrayPool<byte>.Shared`, `while
     ((bytesRead = await input.ReadAsync(buffer, 0, _bufferSize, cancellationToken)
     .ConfigureAwait(false)) > 0)`, per-iteration `ThrowIfCancellationRequested()`, fold the chunk,
     `progress?.Report(bytesRead)`, and `finally` return the buffer with `clearArray: true`. Use the
     `(byte[], int, int, CancellationToken)` `ReadAsync` overload — it is available on every target
     framework.
   - Big-endian formatting: CRC-16 → `[(byte)(v >> 8), (byte)v]`; CRC-32 → four bytes MSB first.

4. **`ChecksumServiceFactory`** — seven one-line methods, each `=> new Crc16Service(CrcParameters.X,
   bufferSize)` / `new Crc32Service(...)`, in the same terse style as `EncodingServiceFactory` and
   `HashServiceFactory`. Each call returns a **fresh** instance (no caching), matching every other
   factory in the library.

5. **XML docs** on every public type and member (`GenerateDocumentationFile=true`, warnings are
   errors). The interface remark carries the "detects accidental corruption only — never for integrity
   against an adversary; use `IHmacService`" warning; each factory method names the variant's aliases
   and its check value; `ComputeChecksum` documents big-endian order; `ComputeChecksumValue` documents
   that CRC-16 occupies the low 16 bits; the service classes document thread-safety.

6. **`docs/guides/checksum.md`** — the established guide shape: intro → *Supported variants* table
   (variant, factory method, polynomial/init/xor-out, aliases, check value) → *Key types* table → the
   security warning as its own short section → copy-pasteable samples (a CRC-32 over UTF-8 text via
   `ComputeChecksumValue`; a streaming CRC over a `FileStream` with `IProgress<int>`; a MODBUS frame
   check showing the byte order). Every snippet must compile against the real API. Then a "Checksums"
   entry under *Data & helpers* in `docs/guides/README.md`, a `**Checksums**` bullet in `README.md`'s
   Features list, and a `Checksum/` line in `CLAUDE.md`'s project-layout block.

7. **Tests.** Reuse `Infrastructure/SyncProgress.cs` and `RandomUtils.GenerateRandomBytes`; cancellation
   tokens from `TestContext.Current.CancellationToken`.

   - **`BitwiseCrcOracle`** — a test-only, independently written bit-by-bit CRC (8 shifts per byte, no
     lookup table), parameterised by poly/init/reflection/xor-out and taking the **normal** polynomial
     with explicit input/output bit reflection. Deliberately *not* structured like the product engine:
     its value is that a wrong table or a wrong reflection order in the product code cannot be mirrored
     by it. Sanity-check the oracle itself against the seven published check values so a broken oracle
     cannot silently bless a broken engine.
   - **`Crc16Tests` / `Crc32Tests`** — per variant: the check value over `"123456789"`; empty input
     (the CRC of zero bytes is `Init ^ XorOut`, masked — assert the concrete value, not the formula);
     a single byte; big-endian byte order asserted against the `uint`; `ComputeChecksum` vs
     `ComputeChecksumValue` agreement; sync vs async agreement; `ChecksumSize`; and for CRC-16 that
     the high 16 bits of the returned `uint` are zero.
   - **`ChecksumFuzzTests`** — `[Theory]` over all seven variants × input lengths
     `{0, 1, 7, 255, 4095, 4096, 4097, 8192, 12289}` of random data: table engine == oracle, and
     one-shot == streamed. Include a chunked stream that returns short reads (a small `Stream` wrapper
     or an explicit small `bufferSize`) so a chunk-boundary bug in the fold cannot hide behind a single
     4096-byte read.
   - **`ChecksumProgressAndCancellationTests`** — reported values sum to the input length and arrive in
     more than one report for a multi-buffer stream; a pre-cancelled token throws
     `OperationCanceledException` for both async members. Shaped after
     `Hashing/ProgressAndCancellationTests.cs`.
   - **`ChecksumArgumentTests`** — null `data` / null `input` with `ParamName` asserted for all four
     compute members; `bufferSize` of `0` and `-1` on all seven factory methods. Shaped after
     `Hashing/HashingArgumentTests.cs`.
   - **`ChecksumServiceFactoryTests`** — each of the seven methods returns the expected concrete type
     (`Assert.IsType<Crc16Service>` / `<Crc32Service>`) and a working service (assert its check value),
     and each call returns a fresh instance (`Assert.NotSame`).
   - **`ChecksumBouncyCastleIsolationTests`** — a copy of `EncodingBouncyCastleIsolationTests` filtered
     on namespace `Enigma.Core.Checksum`, with the sanity assertion listing `Crc16Service`,
     `Crc32Service` and `ChecksumServiceFactory` so the reflection scope cannot silently find nothing.

## Definition of Done

Standard `dev-workflow` DoD:

1. `dotnet build Enigma.Core.slnx -c Release` succeeds with **zero warnings** across all three TFMs.
2. `dotnet test --solution Enigma.Core.slnx -c Release` passes in full on **net8.0 and net10.0**.
3. Every acceptance criterion below is met.
4. Roadmap row + this plan file's status updated to `DONE`.
5. `docs/done/FEATURE-D254.md` written.

## Acceptance criteria

1. The public surface added is exactly `IChecksumService`, `IChecksumServiceFactory`,
   `ChecksumServiceFactory`, `Crc16Service`, `Crc32Service` in namespace `Enigma.Core.Checksum`,
   with the signatures given in *Public surface added by this item*, every member XML-documented, and
   the factory parameterless and `new`-constructible. `CrcParameters` and `CrcTable` are **not**
   exported.
2. `Crc16Service` and `Crc32Service` are `sealed` with `internal` constructors — a consumer cannot
   construct a checksum service except through `ChecksumServiceFactory`.
3. All **seven** factory methods exist under the exact names in the parameter table, each accepting
   `int bufferSize = CryptoDefaults.StreamBufferSize`, and each produces its **published check value**
   over the ASCII bytes of `"123456789"`: ARC 0xBB3D · CCITT-FALSE 0x29B1 · XMODEM 0x31C3 · MODBUS
   0x4B37 · KERMIT 0x2189 · ISO-HDLC 0xCBF43926 · CRC-32C 0xE3069283.
4. There is **no** `CreateCrc16Service()` / `CreateCrc32Service()` (no variant-ambiguous name) on the
   surface, and no checksum extension method anywhere in `Enigma.Core.Extensions`.
5. `ComputeChecksum` returns big-endian bytes of length `ChecksumSize` (2 for CRC-16, 4 for CRC-32),
   agrees with `ComputeChecksumValue` for every variant, and for CRC-16 the returned `uint`'s high 16
   bits are zero.
6. Sync and async agree for every variant, and one-shot and streamed agree — including for a stream
   that returns short reads and for a `bufferSize` smaller than the input.
7. **Fuzz parity holds**: for all seven variants across the specified lengths (including 0, 1, and the
   4095/4096/4097 boundary trio), the table engine's result equals the independent bitwise oracle's,
   and the oracle itself reproduces all seven published check values.
8. Progress reports sum to the input length with more than one report for a multi-buffer stream;
   cancellation is honoured, with a pre-cancelled token throwing `OperationCanceledException` from both
   async members.
9. The exception contract holds exactly as tabulated, with the documented `ParamName` on each — in
   particular `bufferSize <= 0` throws `ArgumentOutOfRangeException` **at creation**, not at first use.
10. Each factory method returns a fresh instance of the expected concrete type per call.
11. `Api/BouncyCastleIsolationTests` and the new `Checksum/ChecksumBouncyCastleIsolationTests` are
    green, and `Org.BouncyCastle` appears **nowhere** in `src/Enigma.Core/Checksum/` — not even in a
    `using`.
12. No new `PackageReference` and no `Directory.Packages.props` entry was added, in either project.
13. `src/Enigma.Core/Checksum/` contains no `#if` conditional-compilation directive and no
    `System.Runtime.Intrinsics` reference — one code path on all three TFMs.
14. `Encoding/`, `Extensions/`, `Hashing/` and `docs/guides/encoding.md` are **unmodified** by this
    item (verify with the diff).
15. `docs/guides/checksum.md` exists in the established guide shape, documents all seven variants with
    their parameters and check values, carries the "not a security primitive" warning, and **every
    snippet compiles against the shipped API**; `docs/guides/README.md`, `README.md` (Features) and
    `CLAUDE.md` (project layout) all list the Checksum module.
16. Release build clean with **zero warnings** across all three TFMs; the full suite green on net8.0
    and net10.0.
17. `docs/done/FEATURE-D254.md` records the files created, the build/test counts, the confirmation that
    the seven check values and the oracle parity hold, and the deliberate omissions (Base16, extension
    methods, intrinsics) so a later reader does not re-litigate them.
18. The item's roadmap row flips to `DONE`.

## Follow-ups recorded (not planned here)

- **FEATURE-19C7 (Release v2.0.0)** was amended in the same planning pass as this item — it now
  depends on FEATURE-D254 and covers the Checksum module in *New Features* and in the package
  `<Description>`/`<PackageTags>`. No further action needed here beyond keeping that true.
- **Hardware-accelerated CRC-32C** (`Sse42`/`Arm.Crc32` on net8.0+) — declined in decision 3; a future
  item could add it behind the same interface with the managed engine as fallback, provided both paths
  are proven to agree on every vector.
- **More checksum families** (Adler-32, Fletcher, CRC-8, CRC-64/xxHash) and **incremental
  `Update`/`Final` state** — both fit this interface additively; neither is planned.
