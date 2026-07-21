# FEATURE-2E3E — Asymmetric.PublicKey implementation (RSA)

- **Status:** TODO
- **Type:** FEATURE (single-phase)
- **Depends on:** FEATURE-61D1 (foundation — package ref + harness; PemUtils un-deferred here)
- **Suggested branch (at build):** `feature/feature-2e3e-publickey-rsa`
- **Basis:** ported from Enigma.Cryptography v5.0.0 (`/home/jo/Dev/Enigma.Cryptography`); redesign decisions validated by user 2026-07-21.

## Objective

Implement the RSA public-key feature behind the FROZEN `Enigma.Core.Asymmetric.PublicKey` contract, porting the working behavior and tests of Enigma.Cryptography v5.0.0 at MAXIMUM FIDELITY while keeping BouncyCastle entirely internal (never in a public signature, base type, thrown-type-in-signature, or public support member). Deliver working `EncryptPkcs1`/`DecryptPkcs1`, `EncryptOaep`/`DecryptOaep(RsaOaepHash)`, `Sign`/`Verify(RsaSignatureAlgorithm)` over PEM-string keys with a clearable `char[]?` passphrase, the parameterless `CreatePublicKeyService()` factory, and — per user validation 2026-07-21 — the RESTORED `GenerateRsaKeyPair` returning PEM strings.

## Basis — port from Enigma.Cryptography v5.0.0

Exact old source files (from `oldToNewMapping`):
- `src/Enigma.Cryptography/PublicKey/IPublicKeyService.cs`
- `src/Enigma.Cryptography/PublicKey/PublicKeyService.cs`
- `src/Enigma.Cryptography/PublicKey/IPublicKeyServiceFactory.cs`
- `src/Enigma.Cryptography/PublicKey/PublicKeyServiceFactory.cs`
- `src/Enigma.Cryptography/PublicKey/RsaOaepHash.cs`
- `src/Enigma.Cryptography/PublicKey/PemPasswordFinder.cs`
- `src/Enigma.Cryptography/SignatureAlgorithms.cs`
- `src/Enigma.Cryptography/Utils/PemUtils.cs`
- `src/Enigma.Cryptography/Utils/RandomUtils.cs` (SecureRandom source for key generation)
- Test basis: `src/UnitTests/PublicKey/{RsaEncryptDecryptTests,RsaOaepTests,RsaServiceTests}.cs`, `src/UnitTests/SignatureAlgorithmsTests.cs`, `src/UnitTests/Utils/PemUtilsTests.cs`, `src/UnitTests/Validation/{ArgumentValidationTests,CryptoKeyPairFixture}.cs`, fixtures `src/UnitTests/PublicKey/{pk_key1.pem,pub_key1.pem}`.

## Scope & mapping

| Old file | New home / disposition | Note |
|----------|------------------------|------|
| `PublicKey/IPublicKeyService.cs` | `Asymmetric/PublicKey/IPublicKeyService.cs` — FROZEN + AMENDED | 6 frozen members implemented; `GenerateRsaKeyPair` restored as a contract amendment (see below). PEM-string keys; padding as method pairs; `RsaSignatureAlgorithm` enum; `char[]?` password. |
| `PublicKey/PublicKeyService.cs` | `Asymmetric/PublicKey/PublicKeyService.cs` | Implement the members; 3 constructor-injected `Func` factories → INTERNAL per-call BC wiring. |
| `PublicKey/IPublicKeyServiceFactory.cs` | `Asymmetric/PublicKey/IPublicKeyServiceFactory.cs` — FROZEN | `CreateRsaService`/`CreateRsaOaepService` → single parameterless `CreatePublicKeyService()`. No factory signature change from the restoration (generation lives on the service). |
| `PublicKey/PublicKeyServiceFactory.cs` | `Asymmetric/PublicKey/PublicKeyServiceFactory.cs` | Implement `CreatePublicKeyService()` → `new PublicKeyService()`. |
| `PublicKey/RsaOaepHash.cs` | `Asymmetric/PublicKey/RsaOaepHash.cs` | Ported verbatim; already in the frozen skeleton. Enum→`IDigest` mapping is internal. |
| `PublicKey/PemPasswordFinder.cs` | DROP (no public type) | Clearable-`char[]` `IPasswordFinder` behavior folds into INTERNAL PemUtils, used only when `password != null`. |
| `SignatureAlgorithms.cs` | root `RsaSignatureAlgorithm` (frozen PHASE01) | JCA strings → enum; internal `ToJcaName` mapping. |
| `Utils/PemUtils.cs` | INTERNAL helper (un-defer) → `Asymmetric/PublicKey/` | Stream + `AsymmetricKeyParameter` + public static → string-based, INTERNAL. Parse (public/private) AND write path retained (needed by restored key-gen). |
| `Utils/RandomUtils.cs` | INTERNAL `new SecureRandom()` at key-gen call site | Full RandomUtils stays deferred to its own feature; only the SecureRandom source is used here. |
| `UnitTests/PublicKey/pk_key1.pem`, `pub_key1.pem` | Enigma.Core test project `PublicKey/` fixtures (`CopyToOutputDirectory`) | Encrypted PKCS#8 (passphrase `test1234`) + SubjectPublicKeyInfo; reused as PEM-string inputs. |

## Contract amendments to the frozen skeleton (FEATURE-4442)

Approved by user 2026-07-21.

| Member | Signature (BC-free) | Restores (old member/test) | Notes |
|--------|---------------------|----------------------------|-------|
| `IPublicKeyService.GenerateRsaKeyPair` | `(string publicKeyPem, string privateKeyPem) GenerateRsaKeyPair(int keySizeBits = 2048, char[]? password = null)` | `AsymmetricCipherKeyPair GenerateKeyPair(int keySize)`; `RsaEncryptDecryptTests`/`RsaOaepTests` ephemeral-key generation; `CryptoKeyPairFixture`; `ArgumentValidationTests` non-positive-keySize `ArgumentException` | Added FIRST as a throwing stub (`throw new NotImplementedException()`) on the interface + `PublicKeyService`, then implemented. Output is PEM strings only — never `AsymmetricCipherKeyPair`/`AsymmetricKeyParameter` — so principle-1 BC-hiding is preserved. `password == null` → unencrypted PKCS#8 `PRIVATE KEY` PEM; non-null → encrypted `ENCRYPTED PRIVATE KEY` PEM (AES-256-CBC default). Validates `keySizeBits > 0` with `ArgumentException` (parity with old guard). |

All other frozen members are implemented as-is; the only public-surface addition is `GenerateRsaKeyPair`.

## BouncyCastle usage (internal only)

Behind the contract, hidden from every public member:
- `Org.BouncyCastle.Crypto.Engines.RsaEngine` — raw RSA primitive.
- `Org.BouncyCastle.Crypto.Encodings.Pkcs1Encoding` — PKCS#1 v1.5 padding (`EncryptPkcs1`/`DecryptPkcs1`).
- `Org.BouncyCastle.Crypto.Encodings.OaepEncoding` — RSAES-OAEP + MGF1, digest selected by `RsaOaepHash`.
- `Org.BouncyCastle.Crypto.Digests.{Sha1,Sha256,Sha384,Sha512}Digest` — OAEP/MGF1 digest.
- `Org.BouncyCastle.Crypto.ISigner` via `Org.BouncyCastle.Security.SignerUtilities.GetSigner(jcaName)` — RSASSA-PKCS1-v1_5, JCA name from internal `ToJcaName(RsaSignatureAlgorithm)`.
- `Org.BouncyCastle.Crypto.AsymmetricKeyParameter` / `AsymmetricCipherKeyPair` — parsed/generated key material, internal only.
- `Org.BouncyCastle.Crypto.Generators.RsaKeyPairGenerator` + `KeyGenerationParameters` + `Org.BouncyCastle.Security.SecureRandom` — restored key generation.
- `Org.BouncyCastle.OpenSsl.PemReader` / `PemWriter` — PEM string parse/serialize inside internal PemUtils.
- `Org.BouncyCastle.OpenSsl.IPasswordFinder` — internal shim wrapping `char[]?` for `PemReader` when a password is supplied.
- `Org.BouncyCastle.Crypto.InvalidCipherTextException` — caught internally and re-thrown as `System.Security.Cryptography.CryptographicException` at the service boundary (no BC exception escapes).

## Redesign decisions

### Already frozen (FEATURE-4442)
- Key material crosses the API as PEM string (`publicKeyPem`/`privateKeyPem`), never `AsymmetricKeyParameter`/`AsymmetricCipherKeyPair`.
- `char[]? password = null` replaces `PemPasswordFinder`; `null` = the PEM is not encrypted.
- Signature algorithm via root `RsaSignatureAlgorithm` enum (default `Sha256WithRsa`); JCA mapping internal.
- Two padding schemes as explicit method pairs `EncryptPkcs1`/`DecryptPkcs1` and `EncryptOaep`/`DecryptOaep(RsaOaepHash)`.
- `RsaOaepHash` ported verbatim (`Sha1/Sha256/Sha384/Sha512`, default `Sha256`).
- Single parameterless `IPublicKeyServiceFactory.CreatePublicKeyService()`.
- All members synchronous `byte[]`, in-memory (no streams, no bufferSize).

### Restored per user validation (2026-07-21)
- **RSA key-pair generation (`certRsaCore`)** — `GenerateRsaKeyPair` re-added returning PEM strings (see amendment). Rationale: the old library and its entire test suite depend on ephemeral-key generation; restoring it BC-free (PEM output) removes the reliance on only two static fixtures and re-enables the `CryptoKeyPairFixture`-style round-trips at multiple key sizes.
- **Internal-per-call BC wiring (`orchestrator_impl_choices`)** — settled, no user question: the old 3-`Func`-delegate DI seam is not restored; the correct cipher/signer is built internally per call (`EncryptPkcs1`→`Pkcs1Encoding(new RsaEngine())`; `EncryptOaep`→`OaepEncoding(new RsaEngine(), digest(hash))`; `Sign`/`Verify`→`SignerUtilities.GetSigner(ToJcaName(algorithm))`). The null-factory-constructor guard test is dropped (surface removed).
- **OAEP/bad-ciphertext exception policy (`orchestrator_impl_choices`)** — settled: BC `InvalidCipherTextException` (and any BC auth/decrypt failure) is wrapped in `System.Security.Cryptography.CryptographicException` at the service boundary; no BC exception escapes. Ported mismatched-hash / bad-ciphertext tests assert the BCL `CryptographicException`.
- **Internal PemUtils (`orchestrator_impl_choices`)** — settled: PemUtils becomes an INTERNAL detail behind `IPublicKeyService` (string-based parse + write). No public `PemUtils`/`PemPasswordFinder` type. The write path uses AES-256-CBC as the encrypted-PEM default (matches old `SavePrivateKey`), exercised only by encrypted `GenerateRsaKeyPair` output.
- **Passphrase `char[]?`** — settled: keep `char[]?` (clearable, matches `IPasswordFinder.GetPassword()`); internal PEM helper branches `null` → parse unencrypted PEM vs non-null → wrap in the internal `IPasswordFinder` shim.

### Open for PR
- **DER `byte[]` key overloads** — recommended default: OUT OF SCOPE. The old PublicKey module had no DER byte[] key I/O (PEM-only via `PemUtils`); parity is preserved. (Binary→`byte[]` is only the documented PFX exception, which lives in Certificates, not here.)
- **`GenerateRsaKeyPair` encrypted-PEM algorithm choice** — recommended default: no public knob; hardcode AES-256-CBC internally (old default). Revisit only if a caller needs a selectable cipher.

## Test plan

Ported vectors / adapted old test files (rewritten to the PEM-string API in the Enigma.Core test project, 3 TFMs, fixtures copied with `CopyToOutputDirectory`):
- `RsaEncryptDecryptTests` → PKCS#1 encrypt→decrypt and sign→verify round-trips; ephemeral keys now via restored `GenerateRsaKeyPair` (and the static fixtures).
- `RsaOaepTests` → `[Theory]` round-trips all four `RsaOaepHash` values on one shared generated pair; default hash = SHA-256 (encrypt default, decrypt SHA-256 succeeds, SHA-512 throws); mismatched-hash throws — asserting `System.Security.Cryptography.CryptographicException` (per settled wrap policy), not a BC type.
- `RsaServiceTests` → load real encrypted PEM (`pk_key1.pem`, `"test1234".ToCharArray()`) + `pub_key1.pem`; sign/verify true, wrong-message false.
- `SignatureAlgorithmsTests` → REPLACED with a `[Theory]` over the four `RsaSignatureAlgorithm` members that signs+verifies (behavioral proof the internal enum→JCA mapping `SHA1withRSA`/`SHA256withRSA`/`SHA384withRSA`/`SHA512withRSA` resolves), since the raw JCA strings are now internal.
- Passphrase paths: encrypted PEM with correct `char[]` succeeds; unencrypted PEM with `password = null` succeeds; wrong password fails (`CryptographicException`).
- Argument validation (rebuilt BC-free from `ArgumentValidationTests`): null/empty/invalid PEM string; null data/signature; `GenerateRsaKeyPair` non-positive `keySizeBits` → `ArgumentException`.

New tests warranted by the redesign:
- **Reflection test**: enumerate every public type/member in `Enigma.Core.Asymmetric.PublicKey` (and `RsaSignatureAlgorithm`) and assert NO `Org.BouncyCastle.*` type appears in any signature, return type, parameter, base type, or public support-type member (proves principle 1).
- **Mapping exhaustiveness guards**: `RsaSignatureAlgorithm`→JCA and `RsaOaepHash`→`IDigest` switches throw `ArgumentOutOfRangeException` on an undefined enum value.
- **Internal round-trip** (via `InternalsVisibleTo`): `GenerateRsaKeyPair` encrypted output re-parses with its password (covers the retained internal write path).

Dropped: public `PemUtils` tests and the null-factory-constructor test (surfaces removed). No CSV/KAT vector files — RSA is empirical round-trip + real-fixture based (RFC 8017 / PKCS#1 v2.2, RSAES-PKCS1-v1_5 / RSAES-OAEP / RSASSA-PKCS1-v1_5); no vectors to regenerate.

## Dependencies

- **FEATURE-61D1 (foundation)** — must land first. Provides the Enigma.Core test project (netstandard2.0;net8.0;net10.0) + shared test harness (CsvData/SyncProgress port, per-feature BC-free `CryptoKeyPairFixture`/`ArgumentValidationTests`), copies the PEM fixtures, un-defers the shared `Utils` home, adds the `BouncyCastle.Cryptography` + `System.Buffers` package references (unreferenced during the skeleton per principle 9), wires PolySharp for netstandard2.0, and adds `coverlet.collector`.

## Acceptance criteria

- Enigma.Core builds clean with ZERO warnings across `netstandard2.0;net8.0;net10.0` under `GenerateDocumentationFile` (no CS1591) and `TreatWarningsAsErrors`.
- All 6 `IPublicKeyService` members, `IPublicKeyServiceFactory.CreatePublicKeyService()`, and the restored `GenerateRsaKeyPair` are implemented — no remaining `NotImplementedException` in `Asymmetric/PublicKey`.
- Reflection test proves no `Org.BouncyCastle.*` type appears in any public signature/return/parameter/base type/public support member of `Enigma.Core.Asymmetric.PublicKey`.
- PKCS#1 v1.5 encrypt/decrypt round-trips on the `pub_key1.pem`/`pk_key1.pem` fixtures (private key decrypted with `"test1234"` as `char[]`).
- OAEP encrypt/decrypt round-trips for all four `RsaOaepHash` values; default is SHA-256; a mismatched hash / bad ciphertext fails with `System.Security.Cryptography.CryptographicException` (BC `InvalidCipherTextException` wrapped, never escaping).
- Sign/Verify round-trips for all four `RsaSignatureAlgorithm` members (proving the enum→JCA mapping); Verify returns false for a tampered message.
- `GenerateRsaKeyPair` produces a valid PEM pair that round-trips through the encrypt/sign methods; `password = null` yields an unencrypted private-key PEM, a non-null password yields an AES-256-CBC-encrypted PEM that re-parses; non-positive `keySizeBits` throws `ArgumentException`.
- Encrypted private-key PEM works with the correct `char[]` password; unencrypted PEM works with `password = null`; a wrong password fails.
- `char[]?` passphrase and PEM-string keys are the only key/secret inputs; no public `PemUtils` or `PemPasswordFinder` type exists (PEM handling internal).
- `BouncyCastle.Cryptography` (and `System.Buffers`) resolve on all three TFMs; PolySharp keeps netstandard2.0 compiling; all ported PublicKey tests pass on net8.0 and net10.0 (and netstandard2.0 via a host TFM).
- Roadmap (`docs/roadmap.md`) and this plan's status updated; completion record `docs/done/FEATURE-2E3E.md` written.

