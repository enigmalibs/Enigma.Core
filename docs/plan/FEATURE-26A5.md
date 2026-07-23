# FEATURE-26A5 — Hashing implementation (Hash + HMAC)

- **Status:** DONE
- **Type:** FEATURE (single-phase)
- **Depends on:** FEATURE-61D1 (foundation — stream Extensions + package ref + harness)
- **Suggested branch (at build):** `feature/feature-26a5-hashing`
- **Basis:** ported from Enigma.Cryptography v5.0.0 (`/home/jo/Dev/Enigma.Cryptography`); redesign decisions validated by user 2026-07-21.

## Objective
Implement the Enigma.Core Hashing module (Hash + HMAC) behind the API frozen by FEATURE-4442 PHASE03, porting the working behaviour and BouncyCastle wiring from Enigma.Cryptography v5.0.0 at MAXIMUM FIDELITY. Hash is async-stream-only returning `byte[]`; HMAC offers a sync `byte[]` variant plus an async `Stream` variant. Per the user-validated 2026-07-21 decision, the dropped configurable SHA-3 output size {224,256,384,512} is RESTORED (default 256). Every BouncyCastle type stays strictly internal — never in a public signature, base type, or public support member (principle 1).

## Basis — port from Enigma.Cryptography v5.0.0
Exact old source files (from the spec `oldToNewMapping`):
- `src/Enigma.Cryptography/Hash/IHashService.cs`
- `src/Enigma.Cryptography/Hash/HashService.cs`
- `src/Enigma.Cryptography/Hash/IHashServiceFactory.cs`
- `src/Enigma.Cryptography/Hash/HashServiceFactory.cs`
- `src/Enigma.Cryptography/Hmac/IHmacService.cs`
- `src/Enigma.Cryptography/Hmac/HmacService.cs`
- `src/Enigma.Cryptography/Hmac/IHmacServiceFactory.cs`
- `src/Enigma.Cryptography/Hmac/HmacServiceFactory.cs`
- `src/Enigma.Cryptography/CryptoDefaults.cs` (already ported verbatim to root `Enigma.Core` in FEATURE-4442 PHASE01; `StreamBufferSize = 4096` — consume only, no action)
- Tests: `src/UnitTests/Hash/*Tests.cs` + `*.csv`, `src/UnitTests/Hmac/*Tests.cs` + `*.csv`, `src/UnitTests/Infrastructure/CsvData.cs`, `src/UnitTests/Infrastructure/ProgressAndCancellationTests.cs`

## Scope & mapping
| Old file / member | New home | Disposition | Note |
|-----|-----|-----|-----|
| `Hash/IHashService.HashAsync` | `Hashing/Hash/IHashService.ComputeHashAsync` | port (renamed) | frozen method name; same `(Stream, IProgress<int>?, CancellationToken) → Task<byte[]>` shape |
| `Hash/HashService(Func<IDigest>, int)` | `Hashing/Hash/HashService` | port body, DROP public ctor | port ArrayPool read-loop + `BlockUpdate/DoFinal`; public `Func<IDigest>` ctor removed → INTERNAL wiring |
| `Hash/IHashServiceFactory.CreateSha3Service(int bitLength=512,int)` | `Hashing/Hash/IHashServiceFactory.CreateSha3Service(int bitLength=256, int bufferSize)` | un-defer / AMEND | configurable bitLength RESTORED (see amendments), default now 256 |
| `Hash/IHashServiceFactory` (Md5/Sha1/Sha256/Sha512) | `Hashing/Hash/IHashServiceFactory` | port verbatim | names unchanged, `(int bufferSize = CryptoDefaults.StreamBufferSize)` |
| `Hash/HashServiceFactory` | `Hashing/Hash/HashServiceFactory` | port | MD5/Sha1/Sha256/Sha512 digests verbatim; SHA-3 now `new Sha3Digest(bitLength)` |
| `Hmac/IHmacService.ComputeHmac(data)` / `ComputeHmacAsync(Stream,...)` | `Hashing/Hmac/IHmacService.ComputeHmac(data,key)` / `ComputeHmacAsync(Stream,key,...)` | port (reshaped) | key moves to per-call parameter (frozen) |
| `Hmac/HmacService(Func<IDigest>, key, int)` | `Hashing/Hmac/HmacService` | port body, DROP public ctor | stateless w.r.t. key; INTERNAL wiring; public `Func<IDigest>` ctor removed |
| `Hmac/IHmacServiceFactory.CreateHmacShaN(byte[] key,int)` | `Hashing/Hmac/IHmacServiceFactory.CreateHmacShaN(int bufferSize)` | port (reshaped) | key parameter removed (frozen) |
| `Hmac/HmacServiceFactory` | `Hashing/Hmac/HmacServiceFactory` | port | Sha1/Sha256/Sha512 digests verbatim; no captured key |
| `CryptoDefaults.cs` | `Enigma.Core/CryptoDefaults.cs` | already ported (PHASE01) | reference only |
| `Infrastructure/CsvData.cs`, `ProgressAndCancellationTests.cs` | foundation test harness + mirrored test folders | port/adapt | CsvData + `SyncProgress<T>` ported to foundation (orchestrator choice) |

## Contract amendments to the frozen skeleton (FEATURE-4442)
**Approved by user 2026-07-21.** Each amendment is added FIRST as a throwing stub (`throw new NotImplementedException()`) into the frozen sealed types, then implemented in this feature. Every amendment keeps principle-1 BC-hiding (the parameter is a plain `int`; no BouncyCastle type appears).

| Member | Signature (BC-free) | Restores (old member/test) | Notes |
|-----|-----|-----|-----|
| `IHashServiceFactory.CreateSha3Service` | `IHashService CreateSha3Service(int bitLength = 256, int bufferSize = CryptoDefaults.StreamBufferSize)` | old `CreateSha3Service(int bitLength = 512, int bufferSize)`; Sha3Tests 224/256/384/512 | Restores configurable output size {224,256,384,512}. Default changed 512→**256** per decision (keeps the modern skeleton default). `bitLength` validated: values outside {224,256,384,512} throw `ArgumentException(nameof(bitLength))`. |
| `HashServiceFactory.CreateSha3Service` | same signature on the concrete sealed factory | same | wires `new Sha3Digest(bitLength)` internally |

No other public member changes: the Hash method rename (`ComputeHashAsync`), the HMAC per-call key, and the removal of the public `Func<IDigest>` constructors are all already frozen and are implemented as-is (not amendments).

## BouncyCastle usage (internal only)
Behind the contract, used only in internal wiring / factory bodies:
- `Org.BouncyCastle.Crypto.IDigest` — was in the old PUBLIC `Func<IDigest>` constructors; must NEVER reappear in any public signature. Digest selection flows through an INTERNAL constructor (an internal digest-factory delegate or an internal algorithm enum) invoked only by the factory.
- `Org.BouncyCastle.Crypto.Digests.MD5Digest`, `Sha1Digest`, `Sha256Digest`, `Sha512Digest`
- `Org.BouncyCastle.Crypto.Digests.Sha3Digest` — constructed `new Sha3Digest(bitLength)` with bitLength ∈ {224,256,384,512}
- `Org.BouncyCastle.Crypto.Macs.HMac`
- `Org.BouncyCastle.Crypto.Parameters.KeyParameter` — wraps the per-call HMAC key
- Members: `IDigest.BlockUpdate / DoFinal / GetDigestSize`; `HMac.Init / BlockUpdate / DoFinal / GetMacSize`
- `System.Buffers.ArrayPool<byte>.Shared` (not BouncyCastle, but a foundation package dependency on netstandard2.0)

## Redesign decisions
### Already frozen (FEATURE-4442)
- Hash is async-stream-only: `IHashService` exposes only `ComputeHashAsync(Stream, IProgress<int>?, CancellationToken) → Task<byte[]>`; no sync overload.
- Hash method renamed `HashAsync` → `ComputeHashAsync`.
- Hash factory has exactly 5 methods: `CreateMd5/Sha1/Sha256/Sha512/Sha3Service`.
- HMAC keeps both variants: sync `ComputeHmac(byte[] data, byte[] key)` + async `ComputeHmacAsync(Stream input, byte[] key, IProgress<int>?, CancellationToken)`; key is a per-call parameter (data/input first, key second).
- HMAC factory methods `CreateHmacSha1/256/512Service(int bufferSize)` — no key parameter.
- Namespaces re-homed: `Enigma.Core.Hashing.Hash` / `Enigma.Core.Hashing.Hmac`.
- BouncyCastle-free public surface: the old public `Func<IDigest>` constructors are gone from the frozen sealed stubs; only the factory constructs services.

### Restored per user validation (2026-07-21)
- **Configurable SHA-3 output size {224,256,384,512}** — restored via the `CreateSha3Service(int bitLength = 256, int bufferSize = …)` amendment above. Rationale: the decision `trims_restore.sha3` mandates MAXIMUM FIDELITY to the old library's configurable SHA-3; the skeleton's fixed-256 trim is reverted. Default stays 256 (modern skeleton default), not the old 512. Consequence: sha3 vectors must be regenerated **per size** (see Test plan).

### Open for PR
- None. Every hashing divergence in the spec is resolved by a frozen decision, the SHA-3 restoration, or a settled implementation choice. The remaining spec divergences below are settled implementation decisions (no user question):
  - **HMAC key location / stateless service** (settled): each call builds a fresh `HMac(digest)` + `Init(new KeyParameter(key))`, matching the old private `CreateMac()` which already re-initialised per call — behaviour preserved. The old "key is caller-owned, never cleared" doc note migrates to the per-call key.
  - **Internal wiring for the dropped `Func<IDigest>` ctors** (settled): internal ctor (delegate or enum) used only by the factory; `IDigest` never public.
  - **HMAC null-key validation moves per-call** (settled): `ArgumentNullException(nameof(key))` at the top of both HMAC methods, alongside the existing `nameof(data)` / `nameof(input)` checks.
  - **BC auth/decrypt failure wrapping**: N/A for hashing (no decrypt path).

## Test plan
Port the old suite to the new project under mirrored `Hashing/Hash` + `Hashing/Hmac` folders; xUnit v3 `[Theory]` + `[MemberData]`, CSVs copied with `CopyToOutputDirectory=PreserveNewest`.
- **Harness**: consume `CsvData` (Hex decode via `System.Convert` or an internal helper — not `HexService`, so no encoding dependency) and `SyncProgress<T>` from the foundation test harness (orchestrator choice). Rebuild any per-feature validation helper BC-free.
- **Ported hash vectors** (`ComputeHashAsync` against a `MemoryStream`, 2-column data,hash, 20 rows each): `md5.csv`, `sha1.csv`, `sha256.csv`, `sha512.csv` — standard FIPS short-message KATs, reusable verbatim.
- **REGENERATE `sha3.csv` PER SIZE**: the existing `sha3.csv` is SHA3-512 only (128-hex) and is invalid for the restored configurable service. Produce NIST FIPS 202 / CAVP short-message KATs for **each** of SHA3-224, SHA3-256, SHA3-384, SHA3-512 (either four files `sha3-224/256/384/512.csv` or one file with a bitLength column). Sha3Tests parameterised over bitLength; assert digest byte-length = bitLength/8.
- **Ported HMAC vectors** (3-column key,data,hmac, 6–7 rows): `hmac-sha1.csv` (RFC 2202), `hmac-sha256.csv` / `hmac-sha512.csv` (RFC 4231). Key now passed per call; keep the triple assertion `ComputeHmac(data,key) == ComputeHmacAsync(input,key) == expected`.
- **Rewrite `ProgressAndCancellationTests` (Hash cases)** to obtain the service via `new HashServiceFactory().CreateSha256Service()` — the public `Func<IDigest>` ctor is gone. Assert progress is reported for multi-buffer streams and a pre-cancelled `CancellationToken` throws `OperationCanceledException` (for both `ComputeHashAsync` and `ComputeHmacAsync`).
- **New tests warranted by the redesign**:
  - (a) **Reflection test** proving NO `Org.BouncyCastle.*` type appears in any public member, parameter, return type, or base type of the `Enigma.Core.Hashing.Hash` and `Enigma.Core.Hashing.Hmac` namespaces.
  - (b) **Null-argument tests**: null input on `ComputeHashAsync`; null data/key on `ComputeHmac`; null input/key on `ComputeHmacAsync` → `ArgumentNullException`.
  - (c) **SHA-3 bitLength validation test**: an unsupported bitLength (e.g. 100) throws `ArgumentException`; each supported size returns the correct digest length.
  - (d) Confirm tests build and run across all three TFMs.
- Add `coverlet.collector` to the test project (matches the old suite).

## Dependencies
- **foundation = FEATURE-61D1** — must land first. It adds the `BouncyCastle.Cryptography` package reference (removed during the skeleton per FEATURE-4442 principle 9) and the `System.Buffers` package (netstandard2.0) for `ArrayPool<byte>`, and ports the shared test harness (`CsvData`, `SyncProgress<T>`). `CryptoDefaults` is already present from PHASE01.

No other feature is required: the hash/HMAC streaming loops read the stream directly via `input.ReadAsync(buffer,0,size,ct)` and do not use `StreamExtensions`/`StreamReadHelpers`, so no Utils/Extensions un-deferring is needed. CsvData Hex is decoded via `System.Convert`/internal helper, so the encoding feature (FEATURE-0399) is NOT a dependency.

## Acceptance criteria
1. Enigma.Core builds clean with **zero warnings** across `netstandard2.0`, `net8.0`, `net10.0` under `TreatWarningsAsErrors` + `GenerateDocumentationFile` (no CS1591).
2. MD5, SHA-1, SHA-256, SHA-512 KATs (20 rows each) pass via `ComputeHashAsync`.
3. SHA-3 passes against the regenerated NIST FIPS 202 vectors for **all four** sizes {224,256,384,512}; each service returns a digest of exactly bitLength/8 bytes; default `CreateSha3Service()` is SHA3-256 (32 bytes); an unsupported bitLength throws `ArgumentException`.
4. HMAC-SHA1 (RFC 2202) and HMAC-SHA256/512 (RFC 4231) vectors pass on BOTH the sync `ComputeHmac(data,key)` and async `ComputeHmacAsync(input,key)` paths, and the two agree.
5. No `Org.BouncyCastle.*` type appears in any public signature, base type, or public member of `Enigma.Core.Hashing.Hash` / `.Hmac` — enforced by the reflection test.
6. Public surface matches the frozen contract + the approved amendment exactly: `CreateSha3Service(int bitLength = 256, int bufferSize)`; HMAC factory methods take no key; HMAC key is a method argument; no public `Func<IDigest>` constructor exists.
7. Progress is reported for multi-buffer streams; a pre-cancelled `CancellationToken` causes `ComputeHashAsync` / `ComputeHmacAsync` to throw `OperationCanceledException`.
8. Null input (hash), null data/key (HMAC sync), and null input/key (HMAC async) throw `ArgumentNullException`.
9. Rented `ArrayPool` buffers are returned with `clearArray: true` in a `finally` block (no key/plaintext residue).
10. The SHA-3 amendment was added as a throwing stub into the frozen skeleton first, then implemented (verifiable in history).
11. `docs/roadmap.md` and `docs/plan/FEATURE-26A5.md` status updated; completion record `docs/done/FEATURE-26A5.md` written.
