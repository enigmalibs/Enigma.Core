# FEATURE-4442-PHASE03 — Hashing + KeyDerivation (DONE)

## Summary
Third phase of the abstraction skeleton: scaffolded the **Hashing** (`Hash`, `Hmac`) and
**KeyDerivation** (PBKDF2, Argon2) modules as redesigned, BouncyCastle-free public contracts with empty
(`throw new NotImplementedException()`) implementations. No algorithm logic — later features fill the
stubs behind these stable interfaces. All hashing/HMAC surfaces preserve the async-`Stream` +
`IProgress<int>` + `CancellationToken` shape (HMAC also gets the sync `byte[]` variant); the KDFs are
in-memory sync `byte[]` APIs. The three ported enums (`Pbkdf2Prf`, `Argon2Variant`, `Argon2Version`)
carry docs scrubbed of BouncyCastle references.

## Files/modules touched

### Created — `Enigma.Core.Hashing.Hash` (`src/Enigma.Core/Hashing/Hash/`)
- `IHashService.cs` — interface. `ComputeHashAsync(Stream input, IProgress<int>? progress = null,
  CancellationToken cancellationToken = default) : Task<byte[]>` (async-stream; returns the digest).
- `HashService.cs` — sealed stub (method throws).
- `IHashServiceFactory.cs` — interface: `CreateMd5Service`, `CreateSha1Service`, `CreateSha256Service`,
  `CreateSha512Service`, `CreateSha3Service`, each `(int bufferSize = CryptoDefaults.StreamBufferSize)`.
- `HashServiceFactory.cs` — sealed stub (all 5 methods throw).

### Created — `Enigma.Core.Hashing.Hmac` (`src/Enigma.Core/Hashing/Hmac/`)
- `IHmacService.cs` — interface: `ComputeHmac(byte[] data, byte[] key) : byte[]` (sync) +
  `ComputeHmacAsync(Stream input, byte[] key, IProgress<int>? progress = null, CancellationToken
  cancellationToken = default) : Task<byte[]>` (async stream).
- `HmacService.cs` — sealed stub (both methods throw).
- `IHmacServiceFactory.cs` — interface: `CreateHmacSha1Service`, `CreateHmacSha256Service`,
  `CreateHmacSha512Service`, each `(int bufferSize = CryptoDefaults.StreamBufferSize)`.
- `HmacServiceFactory.cs` — sealed stub (all 3 methods throw).

### Created — `Enigma.Core.KeyDerivation` (`src/Enigma.Core/KeyDerivation/`)
- `Pbkdf2Prf.cs` — ported enum `{ HmacSha1, HmacSha256, HmacSha512 }` (pure; BouncyCastle mentions
  scrubbed).
- `Argon2Variant.cs` — ported enum `{ Argon2d, Argon2i, Argon2id }` (pure; RFC 9106).
- `Argon2Version.cs` — ported enum `{ Version10, Version13 }` (pure; 0x10 / 0x13, RFC 9106).
- `IPbkdf2Service.cs` — interface: `DeriveKey(byte[] password, byte[] salt, int iterations, int
  keySizeBytes, Pbkdf2Prf prf = Pbkdf2Prf.HmacSha256) : byte[]`.
- `Pbkdf2Service.cs` — sealed stub (method throws).
- `IPbkdf2ServiceFactory.cs` — interface: `CreatePbkdf2Service()`.
- `Pbkdf2ServiceFactory.cs` — sealed stub (method throws).
- `IArgon2Service.cs` — interface: `DeriveKey(byte[] password, byte[] salt, int iterations, int
  memorySizeKb, int degreeOfParallelism, int keySizeBytes, Argon2Variant variant =
  Argon2Variant.Argon2id, Argon2Version version = Argon2Version.Version13) : byte[]`.
- `Argon2Service.cs` — sealed stub (method throws).
- `IArgon2ServiceFactory.cs` — interface: `CreateArgon2Service()`.
- `Argon2ServiceFactory.cs` — sealed stub (method throws).

### Modified — workflow tracking
- `docs/roadmap.md` — PHASE03 `TODO` → `IN PROGRESS` → `DONE` (base FEATURE-4442 stays `IN PROGRESS`;
  PHASE04–06 remain `TODO`).
- `docs/plan/FEATURE-4442.md` — PHASE03 status flips; recorded the full build-time signature design in
  the PHASE03 section (per principle 8), including the source-parity note.

## Design decisions (recorded for downstream phases)
- **Hash = async-stream only; HMAC = sync `byte[]` + async-stream.** Faithful to the plan's deliberate
  per-module distinction. Hashing returns the digest as `byte[]` (small output) rather than writing to an
  output stream (contrast the block cipher, whose ciphertext is large).
- **Stream-based factories take `bufferSize`; in-memory KDF factories do not.** Hash/HMAC factory methods
  carry `int bufferSize = CryptoDefaults.StreamBufferSize` (PHASE02 stream/block convention); PBKDF2 and
  Argon2 are in-memory, so their factories are parameterless single-`Create*` methods.
- **Algorithm-variant enums are service-call parameters, factories are single-method.** `Pbkdf2Prf`,
  `Argon2Variant`, `Argon2Version` are passed to `DeriveKey` (mirroring `BlockCipherMode` on the
  block-cipher service), so `IPbkdf2ServiceFactory`/`IArgon2ServiceFactory` expose one create method each
  rather than fanning out per variant — the coherent reading of the plan, which lists the enums as
  ported support types and the factories as single stubs.
- **HMAC factory names the produced primitive (`CreateHmacSha256Service`).** "HMAC-SHA256" is itself the
  RFC-named primitive (like "ChaCha20" or "SHA-256"), so the method names it directly; this also removes
  any ambiguity with the plain `IHashServiceFactory`'s `CreateSha256Service`.
- **`password` stays `byte[]`.** Consistent with the byte-oriented library; the plan flags password
  redesign only for PHASE05's `PemPasswordFinder`, not for the KDFs.
- **All factory `Create*` members throw too** (principle 5 / acceptance 3), so no concrete stub needs
  constructor parameters — avoids unused-field/unread-parameter errors under `TreatWarningsAsErrors`.

## Deviations & follow-ups
- **Source-parity (no source library in the repo).** As in PHASE01/02, the original library isn't present,
  so signatures were designed at build time per principle 8. Two items to verify against source at PR:
  (1) the exact member set of `Pbkdf2Prf` — chose `{HmacSha1, HmacSha256, HmacSha512}` to match this
  library's HMAC support; (2) whether the source `Argon2Service` exposed optional `secret` /
  `associatedData` parameters, deliberately omitted here to avoid inventing surface. Both are adjustable
  later without disturbing the skeleton (stubs throw).
- **SHA-3 digest size.** `CreateSha3Service` is documented as SHA3-256; if the source intended a different
  SHA-3 width (or multiple widths), confirm at PR. Single-width chosen to match the plan's single
  `Create...Sha3Service` mapping entry.
- **Line endings (CRLF):** none observed — all new files are LF, consistent with `.gitattributes`
  `* text=auto eol=lf`. No action taken (recommendation-only per `dev-workflow`).
- **No new unit tests** (acceptance criterion 5): stubs throw, nothing meaningful to assert; real tests
  arrive with the hashing/key-derivation implementation features.

## Build/test evidence
- **Build:** `dotnet build Enigma.Core.slnx -warnaserror` → `Build succeeded. 0 Warning(s) 0 Error(s)`,
  producing `Enigma.Core.dll` for `netstandard2.0`, `net8.0`, and `net10.0` under `TreatWarningsAsErrors`
  + `GenerateDocumentationFile` (so all-public-members XML docs, CS1591, are enforced as errors).
- **Test:** `dotnet test --solution Enigma.Core.slnx` (MTP) → `Passed! total: 1, failed: 0, succeeded: 1,
  skipped: 0`. Definition-of-Done criterion 2 satisfied by the existing smoke test staying green (no new
  tests this phase, per acceptance criterion 5).
- **No BouncyCastle exposure:** `grep -rniE "bouncy|org\.bouncycastle|ICipherParameters|IPasswordFinder|
  IDigest|SecureRandom"` over `src/Enigma.Core/Hashing` and `src/Enigma.Core/KeyDerivation` returns no
  matches; `BouncyCastle.Cryptography` remains unreferenced by the project, so the clean build proves
  zero coupling.

## Acceptance criteria (per-phase list) — all met
1. ✅ Build clean (zero warnings) across `netstandard2.0`, `net8.0`, `net10.0` under `TreatWarningsAsErrors`.
2. ✅ No BouncyCastle types in any public signature, base type, or support-type member.
3. ✅ Every service/factory is a `sealed` class implementing its interface with `throw new
   NotImplementedException()` bodies (8 stub classes, 15 members).
4. ✅ XML docs on all public types/members (enforced by CS1591-as-error).
5. ✅ No new unit tests; existing smoke test passes green.
6. ✅ Roadmap + plan PHASE03 status updated; this completion doc written.
