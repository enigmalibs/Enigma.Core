# FEATURE-4442 — Abstraction skeleton (interfaces + empty implementations)

- **Status:** IN PROGRESS
- **Type:** FEATURE (multi-phase — 6 phases)
- **Depends on:** FEATURE-56AA (repo/solution must exist first)
- **Suggested branch per phase (at build):** `feature/feature-4442-phaseNN-<slug>` (one branch per phase)

## Objective
Establish the full public shape of Enigma.Core: for all **11 service modules**, create the
**redesigned** interfaces (`IXxxService`, `IXxxServiceFactory`) and their **empty implementations**
(`sealed` classes whose members `throw new NotImplementedException()`), plus the ported support types.
No algorithm logic — later features fill the implementations behind these stable contracts.

## Redesign principles (apply to every interface)
1. **Hide BouncyCastle from the public API.** No BouncyCastle types (`ICipherParameters`, `IDigest`,
   `IPasswordFinder`, `Org.BouncyCastle.Math.BigInteger`, `SecureRandom`, key/certificate types, …)
   in any public signature, base type, or public support-type member.
2. **Parameters = primitives + Enigma enums.** Services accept `byte[]` keys/IVs/nonces; algorithm and
   mode are chosen via factory `Create*Service(...)` methods and Enigma-owned enums.
3. **Drop the low-level BouncyCastle factories** (`IBlockCipherEngineFactory`,
   `IBlockCipherPaddingFactory`, `IBlockCipherParametersFactory` + impls) from the public API — do not
   port them (make internal only if a later implementation genuinely needs the seam).
4. **Keep** the `Service` + `Factory` pattern; the **async-`Stream` vs sync-`byte[]`** split;
   `IProgress<int>` progress + `CancellationToken` on async stream APIs.
5. **Empty impls:** `public sealed class XxxService : IXxxService` (etc.), every member body
   `throw new NotImplementedException();`.
6. **Support types:** port the pure enums/DTOs/constants verbatim (renamespaced); **redesign** any
   support type that itself exposes BouncyCastle (flagged per-phase below).
7. **XML docs required** on all public types/members — CS1591 is a build error under
   `TreatWarningsAsErrors` + `GenerateDocumentationFile`. Port/adapt the source's doc comments, but
   scrub doc text that references BouncyCastle internals where it would mislead a consumer of the new
   BouncyCastle-free API.
8. **Exact redesigned signatures are designed at build time** for each phase, recorded in that phase's
   section, and reviewed at PR. The mappings below define the scaffolding *scope*, not frozen signatures.
9. **BouncyCastle stays unreferenced** by `Enigma.Core` throughout this feature (stubs throw). The
   `BouncyCastle.Cryptography` / `System.Buffers` package references are added by the later
   implementation features, not here.

## Namespace taxonomy (folder = namespace)
```
src/Enigma.Core/
├─ Symmetric/{BlockCiphers, StreamCiphers}
├─ Asymmetric/{PublicKey, Pqc}
├─ Hashing/{Hash, Hmac}
├─ KeyDerivation/        (PBKDF2, Argon2)
├─ Otp/                  (HOTP, TOTP)
├─ Encoding/             (Base64, Hex, Base32)
├─ Certificates/         (X.509)
├─ Padding/
└─ (root)                CryptoDefaults, SignatureAlgorithms, shared enums
```

## Support-type triage (from reading the source)
| Support type | Verdict | Reason |
|--------------|---------|--------|
| `CryptoDefaults` | port verbatim → root `Enigma.Core` | pure constant |
| `SignatureAlgorithms` | **decide representation in PHASE01** → root | JCA-style string names ("SHA256withRSA") leak the BouncyCastle/JCA naming convention. Fix the public shape once, in PHASE01, before PHASE05/06 consume it — avoid a mid-feature string→enum reshape. **Recommended:** an Enigma enum (e.g. `RsaSignatureAlgorithm`) mapped to JCA names internally by the implementation. |
| `GcmMacSize` | port verbatim → Symmetric.BlockCiphers | pure static validation |
| `Argon2Variant`, `Argon2Version` | port verbatim → KeyDerivation | pure enums (scrub "match BouncyCastle constants" from public docs) |
| `Pbkdf2Prf` | port verbatim → KeyDerivation | pure enum |
| `OtpHashAlgorithm` | port verbatim → Otp | pure enum; referenced by the HOTP/TOTP factories |
| `OtpAuthParameters` | **defer** (with `OtpProvisioning`) → Otp | pure DTO, but referenced ONLY by the deferred `OtpProvisioning` — no service/factory interface uses it, so it fails the same "referenced by an interface signature" test that defers the helper. Pull into PHASE04 only if a redesigned OTP service/factory surfaces it. |
| `RsaOaepHash` | port verbatim → Asymmetric.PublicKey | pure enum |
| `PemPasswordFinder` | **redesign / drop** → Asymmetric.PublicKey | implements BouncyCastle `IPasswordFinder`; replace with `char[]`/`string` password params on the service, or make internal |
| `CertificateInfo` | **redesign** → Certificates | exposes `Org.BouncyCastle.Math.BigInteger SerialNumber`; replace with `System.Numerics.BigInteger` / `string` / `byte[]` |
| `OtpProvisioning`, `Utils/*`, `Extensions/*` | **defer** | logic/static helpers, not referenced by any interface signature; land with their implementation features |

## Phases

### PHASE01 — Shared foundation
- **Status:** DONE
- **Scope:** root shared types + redesign baseline; no services.

**Build-time signature design (recorded per principle 8):**
- **`CryptoDefaults`** (root namespace `Enigma.Core`, file `src/Enigma.Core/CryptoDefaults.cs`) — ported
  verbatim. `public static class CryptoDefaults { public const int StreamBufferSize = 4096; }`.
- **Signature-algorithm representation — DECIDED: the recommended Enigma enum.** The old
  `SignatureAlgorithms` public JCA-style string constants (`"SHA256withRSA"`, …) are **replaced** by a
  root enum `public enum RsaSignatureAlgorithm { Sha1WithRsa, Sha256WithRsa, Sha384WithRsa, Sha512WithRsa }`
  (root namespace `Enigma.Core`, file `src/Enigma.Core/RsaSignatureAlgorithm.cs`). This removes the
  JCA/BouncyCastle naming leak (principle 1); the later implementation maps each member to its JCA name
  internally. Verified against source usage: the only *choosable* signing algorithms across both
  consumers — RSA signing (`PublicKeyServiceFactory`, PHASE05) and certificate signing
  (`X509CertificateServiceFactory`, PHASE06) — are exactly these four RSA variants (default
  `Sha256WithRsa`); `X509Utils` only ever *reads back* an existing cert's `SigAlgName`, it never selects
  one. Hence the `Rsa…` name is correct and not too narrow. **PHASE05/06 consume this enum; they do not
  revisit the representation.**
- **No other shared root type introduced.** A symmetric cipher-mode enum is single-module (Symmetric —
  PHASE02) so it lands in its owning module, not root. No unified hash-algorithm enum is created because
  the plan deliberately keeps per-module hash enums (`OtpHashAlgorithm`, `RsaOaepHash`, `Pbkdf2Prf`,
  ported verbatim in later phases) — unifying them would contradict the support-type triage.
- Create root `Enigma.Core` types: `CryptoDefaults`; the shared **signature-algorithm** type (see next
  bullet); and any cross-cutting enums the redesign introduces (e.g. a shared symmetric cipher-mode enum,
  a shared hash-algorithm enum) — define here only if shared by ≥2 modules; otherwise define in the
  owning module.
- **Decide the signature-algorithm representation here, once.** The old library exposes
  `SignatureAlgorithms` as public JCA-style string constants ("SHA256withRSA"), shared by RSA signing
  (PHASE05) and certificate signing (PHASE06). Because both later phases consume it, fix its public
  shape now to avoid a mid-feature reshape. **Recommended:** replace the string constants with an Enigma
  enum (e.g. `RsaSignatureAlgorithm { Sha1WithRsa, Sha256WithRsa, Sha384WithRsa, Sha512WithRsa }`) that
  the implementation maps to JCA names internally — this also removes the JCA/BouncyCastle naming leak
  (principle 1). If string constants are kept instead, record that decision here so PHASE05/06 don't
  revisit it.
- De-risks later phases by fixing the shared vocabulary first.
- **Acceptance:** compiles clean across all 3 TFMs; XML docs present; no BouncyCastle exposure.

### PHASE02 — Symmetric + Padding
- **Status:** DONE

**Build-time signature design (recorded per principle 8):**
- **New Enigma enums** (owning-module, not root — consistent with PHASE01's decision that single-module
  enums live in their module):
  - `Enigma.Core.Symmetric.BlockCiphers.BlockCipherMode { Ecb, Cbc, Ctr, Gcm }` — replaces the old
    per-mode factory methods. Uses the standard name **`Ctr`** (not BouncyCastle's "SIC") to avoid
    leaking BouncyCastle terminology (principle 1).
  - `Enigma.Core.Padding.PaddingScheme { None, Pkcs7, Iso7816, Iso10126, X923 }` — the Enigma
    padding-scheme enum replacing BouncyCastle `IBlockCipherPadding` types. Referenced by both the
    Padding module and the block-cipher service's `padding` parameter (single source of truth).
- **`IBlockCipherService`** (namespace `Enigma.Core.Symmetric.BlockCiphers`): the BouncyCastle
  `ICipherParameters` parameter on `EncryptAsync`/`DecryptAsync` is replaced by
  `byte[] key, byte[]? iv, BlockCipherMode mode` plus optional `PaddingScheme padding = Pkcs7` and
  `int gcmMacSizeBits = GcmMacSize.MaxBits`; async-`Stream` + `IProgress<int>` + `CancellationToken`
  kept (principle 4). `iv` is nullable (ECB uses none). Padding and GCM tag size are optional params so
  the redesign preserves the configurability the old `Create*Service(paddingFactory)` overloads gave,
  without any BouncyCastle type. GCM tag size is validated via the ported `GcmMacSize` helper by the
  later implementation.
- **`IBlockCipherServiceFactory`**: one `Create<Algo>Service(int bufferSize = CryptoDefaults.StreamBufferSize)`
  per algorithm — `CreateAesService`, `CreateDesService`, `CreateTripleDesService`, `CreateBlowfishService`,
  `CreateTwofishService`, `CreateSerpentService`, `CreateCamelliaService`, `CreateCast128Service`,
  `CreateIdeaService`, `CreateSeedService`, `CreateAriaService`, `CreateSm4Service` (12). The BouncyCastle
  `Func<IBlockCipher>`/`Func<IBlockCipherPadding>` engine/padding factory params are dropped (principle 3).
- **`GcmMacSize`** ported verbatim to `Enigma.Core.Symmetric.BlockCiphers` (pure validation); public doc
  scrubbed of the "underlying BouncyCastle GCM mode" phrasing (principles 6/7).
- **StreamCiphers** — the source's public API was **already BouncyCastle-free** (`byte[] key, byte[] nonce`;
  per-algorithm factory methods `CreateChaCha7539Service`/`CreateChaCha20Service`/`CreateSalsa20Service`).
  Ported faithfully; the plan's "primitives + enums" note is satisfied by primitives + the existing
  per-algorithm factory methods (no enum introduced — it would be a gratuitous change to an
  already-clean, already-BouncyCastle-free contract, and it keeps the block/stream factory patterns
  consistent). Only the impls (`StreamCipherService`, `StreamCipherServiceFactory`) were BouncyCastle-coupled → stubbed.
- **Padding** — `IPaddingService` (`byte[] Pad/Unpad(byte[], int)`) and `IPaddingServiceFactory`
  (`CreateNoPaddingService`/`CreatePkcs7Service`/`CreateIso7816Service`/`CreateIso10126Service`/`CreateX923Service`)
  were already BouncyCastle-free → ported verbatim. The only leak was `PaddingService`'s
  `Func<IBlockCipherPadding>` constructor → the redesigned stub carries no BouncyCastle (scheme is
  represented by `PaddingScheme`); `NoPaddingService` kept as its own class per the plan.
- **All service/factory members throw `NotImplementedException`** (principle 5 / acceptance 3), including
  the factory `Create*` methods — so no concrete stub needs constructor parameters (avoids unused-field
  errors under `TreatWarningsAsErrors`).

- **Modules & mapping (old → new namespace → scaffold → redesign flags):**
  - `BlockCiphers/IBlockCipherService, BlockCipherService` → `Enigma.Core.Symmetric.BlockCiphers` → interface + sealed stub → replace BouncyCastle `ICipherParameters` param with `byte[] key`/`byte[] iv` + mode enum.
  - `BlockCiphers/IBlockCipherServiceFactory, BlockCipherServiceFactory` → same → interface + sealed stub → `Create*Service()` per algorithm (AES, DES, 3DES, Blowfish, Twofish, Serpent, Camellia, CAST-128, IDEA, SEED, ARIA, SM4); GCM MAC size via `GcmMacSize`.
  - `BlockCiphers/GcmMacSize` → same → port verbatim (pure).
  - `BlockCiphers/{IBlockCipherEngineFactory, IBlockCipherPaddingFactory, IBlockCipherParametersFactory}` (+ impls) → **DROP** (principle 3) — not ported.
  - `StreamCiphers/IStreamCipherService, StreamCipherService` → `Enigma.Core.Symmetric.StreamCiphers` → interface + sealed stub → primitives + enums (ChaCha20 / ChaCha20-RFC7539 / Salsa20).
  - `StreamCiphers/IStreamCipherServiceFactory, StreamCipherServiceFactory` → same → interface + sealed stub.
  - `Padding/IPaddingService, PaddingService, NoPaddingService` → `Enigma.Core.Padding` → interfaces + sealed stubs → Enigma padding-scheme enum instead of BouncyCastle padding types (PKCS7, ISO 7816-4, ISO 10126, X9.23, None).
  - `Padding/IPaddingServiceFactory, PaddingServiceFactory` → same → interface + sealed stub.
- **Acceptance:** per-phase criteria (below); all block/stream/padding services throw `NotImplementedException`, no BouncyCastle in signatures.

### PHASE03 — Hashing + KeyDerivation
- **Status:** DONE
- **Mapping:**
  - `Hash/IHashService, HashService` → `Enigma.Core.Hashing.Hash` → interface + sealed stub → keep async `Stream` + `IProgress<int>` + `CancellationToken`; factory `Create{Md5,Sha1,Sha256,Sha512,Sha3}Service`.
  - `Hash/IHashServiceFactory, HashServiceFactory` → same → interface + sealed stub.
  - `Hmac/IHmacService, HmacService` → `Enigma.Core.Hashing.Hmac` → interface + sealed stub → sync `byte[]` + async `Stream` variants (HMAC-SHA1/256/512).
  - `Hmac/IHmacServiceFactory, HmacServiceFactory` → same → interface + sealed stub.
  - `KDF/IPbkdf2Service, Pbkdf2Service` → `Enigma.Core.KeyDerivation` → interface + sealed stub.
  - `KDF/IPbkdf2ServiceFactory, Pbkdf2ServiceFactory` → same → interface + sealed stub.
  - `KDF/Pbkdf2Prf` → same → port verbatim (pure).
  - `KDF/IArgon2Service, Argon2Service` → same → interface + sealed stub.
  - `KDF/IArgon2ServiceFactory, Argon2ServiceFactory` → same → interface + sealed stub.
  - `KDF/Argon2Variant, Argon2Version` → same → port verbatim (pure; scrub BouncyCastle mentions from public docs).

**Build-time signature design (recorded per principle 8):**
- **Hashing.Hash** (`Enigma.Core.Hashing.Hash`):
  - `IHashService.ComputeHashAsync(Stream input, IProgress<int>? progress = null, CancellationToken cancellationToken = default) : Task<byte[]>`. Async-stream only (per the plan's explicit "keep async Stream + IProgress + CancellationToken" for Hash) — returns the digest as `byte[]` rather than writing to an output stream, since a digest is small (unlike block-cipher ciphertext). **No sync `byte[]` overload** on Hash: the plan lists sync `byte[]` for HMAC only, a deliberate Hash-vs-HMAC distinction honored here.
  - `IHashServiceFactory` — `CreateMd5Service`, `CreateSha1Service`, `CreateSha256Service`, `CreateSha512Service`, `CreateSha3Service` (SHA-3 = 256-bit), each `(int bufferSize = CryptoDefaults.StreamBufferSize)`. `bufferSize` param follows the PHASE02 stream/block factory convention (hashing is stream-based); the plan didn't spell it out but the established convention governs.
- **Hashing.Hmac** (`Enigma.Core.Hashing.Hmac`):
  - `IHmacService.ComputeHmac(byte[] data, byte[] key) : byte[]` (sync) **and** `ComputeHmacAsync(Stream input, byte[] key, IProgress<int>? progress = null, CancellationToken cancellationToken = default) : Task<byte[]>` (async stream) — the plan's explicit "sync `byte[]` + async `Stream` variants". Param order mirrors the block cipher: input/data first, `key` second.
  - `IHmacServiceFactory` — `CreateHmacSha1Service`, `CreateHmacSha256Service`, `CreateHmacSha512Service`, each `(int bufferSize = CryptoDefaults.StreamBufferSize)`. **Naming rule = name the produced primitive:** "HMAC-SHA256" (RFC 2104 + SHA-256) is the primitive, hence the `Hmac` prefix — consistent with the Hash factory naming its primitive (`CreateSha256Service`). Chosen over bare `CreateSha256Service` on the HMAC factory to avoid reader ambiguity with plain hashing.
- **KeyDerivation** (`Enigma.Core.KeyDerivation`) — both KDFs are in-memory (no streaming), so **sync `byte[]`** APIs and **no `bufferSize`** on their factories:
  - Enums (ported verbatim, pure; BouncyCastle mentions scrubbed from docs): `Pbkdf2Prf { HmacSha1, HmacSha256, HmacSha512 }` (aligned with the HMAC service's algorithm set — a PBKDF2 PRF *is* an HMAC); `Argon2Variant { Argon2d, Argon2i, Argon2id }` (RFC 9106); `Argon2Version { Version10, Version13 }` (0x10 / 0x13, RFC 9106).
  - `IPbkdf2Service.DeriveKey(byte[] password, byte[] salt, int iterations, int keySizeBytes, Pbkdf2Prf prf = Pbkdf2Prf.HmacSha256) : byte[]`. `IPbkdf2ServiceFactory.CreatePbkdf2Service()` — single create method; the PRF is a service-call enum parameter (same shape as `BlockCipherMode` on the block-cipher service), which is why the factory doesn't fan out per-PRF.
  - `IArgon2Service.DeriveKey(byte[] password, byte[] salt, int iterations, int memorySizeKb, int degreeOfParallelism, int keySizeBytes, Argon2Variant variant = Argon2Variant.Argon2id, Argon2Version version = Argon2Version.Version13) : byte[]`. `IArgon2ServiceFactory.CreateArgon2Service()` — single create method; variant/version are service-call enum parameters.
  - **`password` kept as `byte[]`** (not `char[]`/`string`): consistent with the byte-oriented library and not flagged for redesign by the plan (unlike PHASE05's `PemPasswordFinder`).
- **Source-parity note (no source lib in repo, per principle 8 designed at build & reviewed at PR):** the exact *member set* of the ported enums (`Pbkdf2Prf`) and the exact *parameter set* of `IArgon2Service.DeriveKey` (e.g. whether the source also exposed optional `secret`/`associatedData`) should be verified against the original library at PR. Chosen sets are the standard, internally-consistent minimum; adjusting them later does not disturb the skeleton (stubs throw).

### PHASE04 — Otp + Encoding
- **Status:** TODO
- **Mapping:**
  - `Otp/IHotpService, HotpService` → `Enigma.Core.Otp` → interface + sealed stub.
  - `Otp/IHotpServiceFactory, HotpServiceFactory` → same → interface + sealed stub.
  - `Otp/ITotpService, TotpService` → same → interface + sealed stub.
  - `Otp/ITotpServiceFactory, TotpServiceFactory` → same → interface + sealed stub.
  - `Otp/OtpHashAlgorithm` → same → port verbatim (pure; referenced by the HOTP/TOTP service factories).
  - `Otp/OtpProvisioning` **and** `Otp/OtpAuthParameters` → **defer together** to the OTP implementation feature: `OtpProvisioning` is a provisioning logic helper (depends on Encoding + secure random), and `OtpAuthParameters` is referenced ONLY by `OtpProvisioning` — no service/factory interface uses it, so it fails the skeleton's "referenced by an interface signature" test. Pull `OtpAuthParameters` into this phase only if the redesigned OTP service/factory ends up surfacing it.
  - `DataEncoding/IEncodingService` (+ `Base64Service`, `Base32Service`, `HexService`) → `Enigma.Core.Encoding` → interface + three sealed stubs.
  - `DataEncoding/IEncodingServiceFactory, EncodingServiceFactory` → same → interface + sealed stub.

### PHASE05 — Asymmetric
- **Status:** TODO
- **Mapping:**
  - `PublicKey/IPublicKeyService, PublicKeyService` → `Enigma.Core.Asymmetric.PublicKey` → interface + sealed stub → RSA encrypt (PKCS#1 v1.5 + OAEP) & sign.
  - `PublicKey/IPublicKeyServiceFactory, PublicKeyServiceFactory` → same → interface + sealed stub.
  - `PublicKey/RsaOaepHash` → same → port verbatim (pure enum).
  - `PublicKey/PemPasswordFinder` → **redesign / drop from public API** — replace with `char[]`/`string` password params on the service, or make internal (it currently implements BouncyCastle `IPasswordFinder`).
  - `PQC/IMLDsaService, MLDsaService` → `Enigma.Core.Asymmetric.Pqc` → interface + sealed stub (ML-DSA / CRYSTALS-Dilithium).
  - `PQC/IMLDsaServiceFactory, MLDsaServiceFactory` → same → interface + sealed stub.
  - `PQC/IMLKemService, MLKemService` → same → interface + sealed stub (ML-KEM / CRYSTALS-Kyber).
  - `PQC/IMLKemServiceFactory, MLKemServiceFactory` → same → interface + sealed stub.
- **Flag:** the redesigned RSA/PQC APIs must expose key material as PEM/DER `string`/`byte[]`, not
  BouncyCastle `AsymmetricKeyParameter`/key-pair types (verify source signatures at build).

### PHASE06 — Certificates
- **Status:** TODO
- **Mapping:**
  - `X509/IX509CertificateService, X509CertificateService` → `Enigma.Core.Certificates` → interface + sealed stub (self-signed generation, CSR/PKCS#10, issuance, chain + CRL validation).
  - `X509/IX509CertificateServiceFactory, X509CertificateServiceFactory` → same → interface + sealed stub.
  - `X509/CertificateInfo` → same → **redesign**: replace `Org.BouncyCastle.Math.BigInteger SerialNumber` with `System.Numerics.BigInteger` / `string` / `byte[]`; keep the other members.
- **Flag:** certificate/CSR/chain APIs must take/return PEM/DER `string`/`byte[]`, not BouncyCastle
  `X509Certificate`/`Pkcs10CertificationRequest` (verify at build).

## Deferred (NOT part of this skeleton; land with their implementation features)
- `Extensions/*` — `StreamExtensions`, `EncodingExtensions`, `StreamReadHelpers` (pure helpers; no interface depends on them).
- `Utils/*` — `PemUtils`, `X509Utils`, `RandomUtils` (static helpers; also BouncyCastle-coupled — redesign when their consumers are implemented).
- `Otp/OtpProvisioning` + `Otp/OtpAuthParameters` — provisioning logic helper and its result DTO (the DTO is referenced only by the helper; land both with the OTP implementation feature).

## Per-phase acceptance criteria (all phases)
1. Build clean (**zero warnings**) across `netstandard2.0`, `net8.0`, `net10.0` under `TreatWarningsAsErrors`.
2. **No BouncyCastle types** in any public signature, base type, or public support-type member.
3. Every service/factory is a `sealed` class implementing its interface with `throw new NotImplementedException()` bodies.
4. XML docs on all public types/members.
5. **No new unit tests** (stubs throw — nothing meaningful to assert); the existing smoke test still
   passes. Real tests arrive with the implementation features. Definition-of-Done criterion 2 is
   satisfied by the existing suite staying green — state this explicitly in each phase's completion doc.
6. Roadmap + this plan's phase status updated; completion doc `docs/done/FEATURE-4442-PHASENN.md` written.

## Notes
- Exact redesigned signatures are designed within each phase's build and recorded in that phase's
  section at that time (principle 8).
- Where a redesign flag requires a new Enigma type (cipher-mode enum, padding-scheme enum, serial-number
  representation, key-material format), define it in the owning module — or in PHASE01 root if shared.
- Phase grouping is deliberately coarse (~2 modules/phase) to keep each dev reviewable; it can be split
  finer at build time without changing this plan's scope.
