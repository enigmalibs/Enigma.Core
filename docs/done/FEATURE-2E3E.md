# FEATURE-2E3E — Asymmetric.PublicKey implementation (RSA) — DONE

## Summary

Implemented the RSA public-key feature behind the frozen `Enigma.Core.Asymmetric.PublicKey` contract,
porting the behavior and tests while keeping BouncyCastle entirely internal
(no BC type on any public signature, return, parameter, base type or exposed member — proven by a reflection
guard). Delivered `EncryptPkcs1`/`DecryptPkcs1`, `EncryptOaep`/`DecryptOaep(RsaOaepHash)`,
`Sign`/`Verify(RsaSignatureAlgorithm)` over PEM-string keys with a clearable `char[]?` passphrase, the
parameterless `CreatePublicKeyService()` factory, and the restored `GenerateRsaKeyPair` returning PEM strings.

The old 3-`Func`-delegate DI seam was dropped in favor of internal per-call BC wiring
(`EncryptPkcs1`→`Pkcs1Encoding(new RsaEngine())`; `EncryptOaep`→`OaepEncoding(new RsaEngine(), digest(hash))`;
`Sign`/`Verify`→`SignerUtilities.GetSigner(ToJcaName(algorithm))`). PEM handling lives in an **internal**
`PemUtils` (parse + write), with an internal `IPasswordFinder` shim wrapping the `char[]?` passphrase — no
public `PemUtils`/`PemPasswordFinder` type. BouncyCastle decryption/authentication failures are wrapped in
`System.Security.Cryptography.CryptographicException` at the service boundary; malformed PEM input surfaces as
`ArgumentException`.

## Files/modules touched

**Created**
- `src/Enigma.Core/Asymmetric/PublicKey/PemUtils.cs` — internal PEM parse/write + `char[]` password-finder shim.
- `tests/Enigma.Core.UnitTests/PublicKey/RsaKeyFixture.cs` — generate-once RSA-2048 collection fixture.
- `tests/Enigma.Core.UnitTests/PublicKey/RsaEncryptDecryptTests.cs` — PKCS#1 + sign/verify round-trips.
- `tests/Enigma.Core.UnitTests/PublicKey/RsaOaepTests.cs` — OAEP all-hash round-trips, default, mismatch/corrupt → `CryptographicException`.
- `tests/Enigma.Core.UnitTests/PublicKey/RsaSignatureAlgorithmTests.cs` — sign/verify for every `RsaSignatureAlgorithm` (enum→JCA mapping proof).
- `tests/Enigma.Core.UnitTests/PublicKey/RsaServiceTests.cs` — real fixture PEMs (`pk_key1.pem` + `test1234`, `pub_key1.pem`).
- `tests/Enigma.Core.UnitTests/PublicKey/RsaKeyGenerationTests.cs` — `GenerateRsaKeyPair` formats, round-trips, passphrase paths, key-size guard.
- `tests/Enigma.Core.UnitTests/PublicKey/RsaArgumentValidationTests.cs` — null/empty/malformed PEM, null data/signature, wrong password, mapping exhaustiveness.
- `tests/Enigma.Core.UnitTests/PublicKey/PublicKeyServiceFactoryTests.cs` — factory type + fresh-instance.
- `tests/Enigma.Core.UnitTests/PublicKey/PublicKeyBouncyCastleIsolationTests.cs` — namespace-scoped BC-isolation reflection guard.
- `tests/Enigma.Core.UnitTests/PublicKey/pk_key1.pem`, `pub_key1.pem` — copied fixtures (`CopyToOutputDirectory`).

**Modified**
- `src/Enigma.Core/Asymmetric/PublicKey/IPublicKeyService.cs` — added the `GenerateRsaKeyPair(int, char[]?)` member (approved contract amendment).
- `src/Enigma.Core/Asymmetric/PublicKey/PublicKeyService.cs` — full implementation (replaced skeleton stubs).
- `src/Enigma.Core/Asymmetric/PublicKey/PublicKeyServiceFactory.cs` — `CreatePublicKeyService()` → `new PublicKeyService()`.
- `tests/Enigma.Core.UnitTests/Enigma.Core.UnitTests.csproj` — copy `**/*.pem` fixtures to output.
- `docs/roadmap.md`, `docs/plan/FEATURE-2E3E.md` — status → DONE.

## Deviations & follow-ups

- **Encrypted private-key PEM format (user decision, 2026-07-22).** The plan asked for both an
  `ENCRYPTED PRIVATE KEY` header **and** AES-256-CBC. These are mutually exclusive in BouncyCastle 2.6.2:
  `Pkcs8Generator` (`ENCRYPTED PRIVATE KEY`) supports only legacy PBE ciphers (DES/3DES/RC2), never AES, while
  the AES-256-CBC path (exactly the old `SavePrivateKey` call, `WriteObject(key, "AES-256-CBC", pw, random)`)
  produces a traditional `RSA PRIVATE KEY` PEM (`Proc-Type: 4,ENCRYPTED` / `DEK-Info: AES-256-CBC`). Per the
  user's choice, `GenerateRsaKeyPair(password: …)` uses **AES-256-CBC in an `RSA PRIVATE KEY` PEM** — honoring
  the explicit AES-256-CBC acceptance criterion and "matches old `SavePrivateKey`". The only divergence from
  the plan prose is the PEM header label (`RSA PRIVATE KEY` rather than `ENCRYPTED PRIVATE KEY`). Unencrypted
  output (`password = null`) is an unencrypted PKCS#8 `PRIVATE KEY` PEM as specified.
- **`InternalsVisibleTo` not introduced.** The plan's test plan mentioned an internal round-trip via
  `InternalsVisibleTo`. The codebase deliberately uses none, testing through the public surface + reflection
  guards. The retained internal PEM-write path is covered publicly (encrypted `GenerateRsaKeyPair` output →
  re-parsed by the private-key operations), and mapping exhaustiveness is covered by casting undefined enum
  values through the public methods. No `InternalsVisibleTo` was added, keeping consistency with the codebase.
- **Oversized-plaintext encrypt** raises BouncyCastle's `System.ArgumentException` ("input too large for RSA
  cipher") rather than a wrapped `CryptographicException`. This is a BCL type (no BC type leaks) and a
  reasonable caller-input error; left as-is (not an acceptance-criterion case).
- **DER `byte[]` key overloads** remain out of scope (plan "Open for PR" — PEM-only parity preserved).
- Line endings: no CRLF/line-ending issues observed in the touched files.

## Build/test evidence

- **Build:** `Enigma.Core` builds clean across `netstandard2.0;net8.0;net10.0` under `GenerateDocumentationFile`
  + `TreatWarningsAsErrors` — **0 warnings, 0 errors**. Test project builds clean (0 warnings).
- **Tests:** full suite **1499 tests, 0 failed, 0 skipped** on both net8.0 and net10.0. The 48 new
  `Enigma.Core.UnitTests.PublicKey` tests all pass. The netstandard2.0 library build is validated by a clean
  compile (PolySharp) and exercised through the net8.0 host TFM.
- **Principle-1 isolation:** the namespace-scoped `PublicKeyBouncyCastleIsolationTests` and the assembly-wide
  `Api/BouncyCastleIsolationTests` both pass — no `Org.BouncyCastle.*` type on the public surface.
