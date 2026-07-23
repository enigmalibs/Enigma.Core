# FEATURE-26A5 — Hashing implementation (Hash + HMAC)

- **Status:** DONE
- **Type:** FEATURE (single-phase)
- **Branch:** `feature/feature-26a5-hashing` (cut from `feature/feature-0399-encoding` @ `b13440f`)
- **Basis:** ported from Enigma.Cryptography v5.0.0 (`/home/jo/Dev/Enigma.Cryptography`), `Hash` + `Hmac` modules.

## Summary
Implemented the Hashing module behind the API frozen by FEATURE-4442 PHASE03, porting the working
behaviour and BouncyCastle wiring from v5.0.0 at maximum fidelity, plus the one approved contract
amendment (configurable SHA-3 output size).

1. **`HashService`** — async-stream-only `ComputeHashAsync(Stream, IProgress<int>?, CancellationToken)`.
   ArrayPool read-loop → `IDigest.BlockUpdate`/`DoFinal`. The old public `HashService(Func<IDigest>, int)`
   constructor is replaced by an **internal** constructor (only the factory constructs services), so no
   BouncyCastle type appears on the public surface.
2. **`HashServiceFactory`** — MD5 / SHA-1 / SHA-256 / SHA-512 wired verbatim; **SHA-3 amendment**:
   `CreateSha3Service(int bitLength = 256, int bufferSize = CryptoDefaults.StreamBufferSize)` restores the
   configurable output size {224,256,384,512}, default 256, with `ArgumentException(nameof(bitLength))`
   for unsupported sizes.
3. **`HmacService`** — sync `ComputeHmac(byte[] data, byte[] key)` + async
   `ComputeHmacAsync(Stream, byte[] key, IProgress<int>?, CancellationToken)`. Key is a **per-call**
   argument (data/input first, key second); a fresh `HMac` is created and `Init`-ed with
   `KeyParameter(key)` on every call. Internal constructor as with `HashService`.
4. **`HmacServiceFactory`** — SHA-1 / SHA-256 / SHA-512 HMAC services; factory methods take **no key**.

Every BouncyCastle type (`IDigest`, `MD5/Sha1/Sha256/Sha512/Sha3Digest`, `HMac`, `KeyParameter`) is used
only in internal constructors, factory bodies and private fields — never on the public surface.

## Files / modules touched

### Modified — library (`src/Enigma.Core/Hashing/`)
- `Hash/HashService.cs` — implemented; internal `(Func<IDigest>, int bufferSize)` ctor; ArrayPool loop
  returned with `clearArray: true`; **`bufferSize > 0` guard** (see Deviations).
- `Hash/HashServiceFactory.cs` — implemented all 5 methods; SHA-3 `bitLength` validation.
- `Hash/IHashServiceFactory.cs` — **amended** `CreateSha3Service` signature (bitLength restored, default 256).
- `Hmac/HmacService.cs` — implemented; per-call key; internal ctor; ArrayPool loop cleared; `bufferSize` guard.
- `Hmac/HmacServiceFactory.cs` — implemented all 3 methods (no key parameter).

(`IHashService`, `IHmacService`, `IHmacServiceFactory` were already frozen correctly — no change.)

### Created — tests (`tests/Enigma.Core.UnitTests/Hashing/`)
- `Hash/Md5Tests.cs`, `Sha1Tests.cs`, `Sha256Tests.cs`, `Sha512Tests.cs` — ported FIPS KAT theories
  (20 rows each) via `ComputeHashAsync`.
- `Hash/Sha3Tests.cs` — parameterised over `bitLength` from the regenerated `sha3.csv`; asserts digest =
  `bitLength/8` bytes; default = SHA3-256; unsupported `bitLength` throws `ArgumentException`.
- `Hmac/HmacSha1Tests.cs` (RFC 2202), `HmacSha256Tests.cs` / `HmacSha512Tests.cs` (RFC 4231) — triple
  assertion `ComputeHmac(data,key) == ComputeHmacAsync(input,key) == expected`.
- `ProgressAndCancellationTests.cs` — Hash + HMAC: multi-buffer progress (count ≥ 2, sum = length) and
  pre-cancelled-token → `OperationCanceledException`.
- `HashingArgumentTests.cs` — null-argument guards (hash input; HMAC data/key sync + async) and the
  non-positive-`bufferSize` guard for both factories.
- `HashingBouncyCastleIsolationTests.cs` — reflection guard scoped to `Enigma.Core.Hashing.Hash` / `.Hmac`.

### Created — test vectors (`tests/Enigma.Core.UnitTests/Hashing/`)
- Ported verbatim: `Hash/md5.csv`, `sha1.csv`, `sha256.csv`, `sha512.csv`; `Hmac/hmac-sha1.csv`,
  `hmac-sha256.csv`, `hmac-sha512.csv`.
- **Regenerated `Hash/sha3.csv`** (`bitLength,data,hash`, 80 rows = 20 short messages × {224,256,384,512}).
  The old file was SHA3-512-only (invalid for the configurable service). Vectors generated with an
  **independent FIPS 202 oracle** (Python `hashlib`), not BouncyCastle; the SHA3-512 empty-message value
  matches the old library, cross-validating the oracle.

## Deviations & follow-ups
- **Added a `bufferSize > 0` guard (not in the plan).** An adversarial verification pass found that an
  unvalidated `bufferSize = 0` made the streaming read loop terminate before consuming the stream, so the
  service silently returned the empty-message digest — and for `ComputeHmacAsync`, an HMAC tag over zero
  bytes (arbitrary data left unauthenticated, no exception). This was faithfully inherited from the v5.0.0
  port (which never validated `bufferSize`). Because it is a silent, security-relevant wrong result and
  the module already validates the SHA-3 `bitLength`, both service constructors now throw
  `ArgumentOutOfRangeException(nameof(bufferSize))` for a non-positive buffer. The public contract
  (signatures/defaults) is unchanged; behaviour changes only for previously-broken invalid input. Covered
  by `HashingArgumentTests.CreateHashService/CreateHmacService_NonPositiveBufferSize_Throws`.
- **Acceptance criterion 10 (stub-first, "verifiable in history").** The plan wanted the SHA-3 amendment
  added as a throwing stub first and then implemented in separate history. Under this workflow all commits
  are the user's (one commit per dev) and I never commit, so the stub-first sub-step collapses into the
  single dev commit; the amendment lands fully implemented. No separate stub commit exists. (Signature +
  behaviour of the amendment are correct and tested.)
- **`coverlet.collector`** was already added to the test project by the foundation (FEATURE-61D1); the
  plan's "add coverlet.collector" item needed no action.
- **Line endings:** no CRLF/line-ending anomalies observed in the touched files; no action taken
  (recommendation-only per workflow).
- Verification also ran clean on BouncyCastle isolation, test-vector integrity (independently recomputed),
  resource cleanup/cancellation, and public-contract fidelity — no other findings.

## Build / test evidence
- **Build:** `dotnet build -c Release` → **Build succeeded, 0 Warning(s), 0 Error(s)** across all three
  library TFMs (`netstandard2.0;net8.0;net10.0`) under `TreatWarningsAsErrors` + `GenerateDocumentationFile`.
- **Tests:** `dotnet test -c Release` → **596 passed, 0 failed, 0 skipped** across both test TFMs
  (`net8.0`, `net10.0`).
- **Acceptance criteria 1–9, 11:** all met (KATs for MD5/SHA-1/256/512; SHA-3 all four sizes + default +
  invalid-size; HMAC RFC 2202/4231 on both paths; reflection guard green; contract + amendment exact;
  progress + pre-cancel; null-arg guards; ArrayPool cleared). Criterion 10 collapsed as noted above.
- **Adversarial verification:** 6-dimension workflow (BC-isolation, crypto-correctness, vector-integrity,
  resource/cancellation, contract-fidelity, coverage/plan); 4 dimensions clean, 1 confirmed defect fixed
  (bufferSize), 1 "finding" was the pending completion closeout itself.
