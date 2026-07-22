# FEATURE-0D6D — Asymmetric.Pqc implementation (ML-DSA, ML-KEM) — DONE

## Summary
Implemented the post-quantum module behind the FEATURE-4442 frozen contract in
`Enigma.Core.Asymmetric.Pqc`: ML-DSA (FIPS 204 signatures) and ML-KEM (FIPS 203 key encapsulation),
ported from Enigma.Cryptography v5.0.0 at full fidelity. BouncyCastle 2.6.2 backs every operation but
stays entirely internal — all keys, signatures, ciphertexts and shared secrets cross the public API as
raw `byte[]` in their FIPS 204/203 encoding. The dropped ML-DSA **deterministic signing** capability is
restored via the approved contract amendment (a trailing optional `bool deterministic = false` on the
factory method), and the raw-FIPS encoding / expanded-private-key decisions are settled as implemented.

## Files / modules touched

### Source — implemented (previously throwing skeleton stubs)
- **Modified** `src/Enigma.Core/Asymmetric/Pqc/MLDsaService.cs` — full ML-DSA service: `GenerateKeyPair`
  (raw expanded key bytes via `GetEncoded()`), `Sign`, `Verify`; internal ctor takes the BouncyCastle
  `MLDsaParameters` + `deterministic` flag; malformed keys wrapped to `CryptographicException`.
- **Modified** `src/Enigma.Core/Asymmetric/Pqc/MLKemService.cs` — full ML-KEM service: `GenerateKeyPair`,
  `Encapsulate`, `Decapsulate`; internal ctor takes `MLKemParameters`; malformed input wrapped to
  `CryptographicException`.
- **Modified** `src/Enigma.Core/Asymmetric/Pqc/MLDsaServiceFactory.cs` — maps `MLDsaParameterSet` →
  `MLDsaParameters.ml_dsa_44/65/87`; forwards the restored `deterministic` flag.
- **Modified** `src/Enigma.Core/Asymmetric/Pqc/MLKemServiceFactory.cs` — maps `MLKemParameterSet` →
  `MLKemParameters.ml_kem_512/768/1024`.

### Source — contract amendment (approved 2026-07-21) + XML-doc updates
- **Modified** `src/Enigma.Core/Asymmetric/Pqc/IMLDsaServiceFactory.cs` — added the trailing optional
  `bool deterministic = false` parameter to `CreateMLDsaService` (source-compatible with the frozen
  signature; no BouncyCastle type introduced — plain `bool`).
- **Modified** `src/Enigma.Core/Asymmetric/Pqc/IMLDsaService.cs`,
  `src/Enigma.Core/Asymmetric/Pqc/IMLKemService.cs` — XML docs on `GenerateKeyPair` now name the exact
  encoding (public = standard FIPS key; private = **expanded** secret/decapsulation key, not the seed).

### Tests — new (`tests/Enigma.Core.UnitTests/Pqc/`)
- `PqcBouncyCastleIsolationTests.cs` — reflection guard: no `Org.BouncyCastle.*` type on any exported
  member of the `Enigma.Core.Asymmetric.Pqc` namespace (criterion 2 / test a).
- `MLDsaServiceTests.cs` — round-trip 44/65/87, deterministic-identical, hedged-differs-still-verifies,
  encode→re-inject round-trip, tampered message/signature ⇒ false, wrong-key ⇒ false, null guards,
  malformed key ⇒ `CryptographicException`.
- `MLDsaFixedVectorTests.cs` — pinned ML-DSA-87 vector verifies true under key A, false under key B.
- `MLDsaServiceFactoryTests.cs` — type/fresh-instance, default = MLDsa65, parameter-set→security-level
  mapping via FIPS public-key sizes, undefined enum ⇒ `ArgumentOutOfRangeException`.
- `MLKemServiceTests.cs` — round-trip 512/768/1024, encode→re-inject, wrong-key mismatch, fresh secret
  per call, null guards, malformed ciphertext/key ⇒ `CryptographicException`.
- `MLKemFixedVectorTests.cs` — pinned ML-KEM-1024 vector decapsulates to the known 32-byte secret under
  key A, differs under key B.
- `MLKemServiceFactoryTests.cs` — type/fresh-instance, default = MLKem768, mapping via public-key sizes,
  undefined enum ⇒ `ArgumentOutOfRangeException`.

### Test fixtures — regenerated as raw FIPS bytes (`tests/Enigma.Core.UnitTests/Pqc/`)
- **New** `dsa87_A_public.key`, `dsa87_B_public.key` (2592 B each) — raw FIPS 204 public keys extracted
  from the legacy `dsa87_A/B_public.pem` (SPKI PEM → `GetEncoded()`).
- **New** `kem1024_A_private.key`, `kem1024_B_private.key` (3168 B each) — raw FIPS 203 expanded private
  keys extracted from the legacy encrypted-PKCS#8 `kem1024_A/B_private.pem` (decrypted once with the
  `test1234` password during regeneration, stored unencrypted).
- **New** `message.txt`, `signature.bin`, `encapsulation.bin`, `secret.bin` — copied unchanged from the
  legacy fixtures. The regeneration was self-verified before adoption: key A validates the unchanged
  `signature.bin` / recovers the unchanged `secret.bin`, key B does not.

### Build config
- **Modified** `tests/Enigma.Core.UnitTests/Enigma.Core.UnitTests.csproj` — added `**/*.key`, `**/*.bin`,
  `**/*.txt` copy-to-output globs (mirroring the existing `**/*.csv` / `**/*.pem` fixture convention) so
  the raw PQC vectors load by relative path next to the test assembly.

## Deviations & follow-ups
- **Test-harness naming (minor).** The plan text referenced reusing foundation types
  `CryptoKeyPairFixture` / `ArgumentValidationTests`. Those types were never added to the test project by
  FEATURE-61D1; the actual established house pattern (set by the RSA feature FEATURE-2E3E) is a
  per-feature service/factory/argument test set plus a per-namespace `*BouncyCastleIsolationTests`
  reflection guard. This feature follows that established pattern, which satisfies the plan's intent
  (BC-free keys-as-`byte[]` coverage + the principle-1 guard). No shared fixture was needed: ML-DSA/ML-KEM
  key generation is cheap, so tests generate keys inline rather than through a collection fixture.
- **BC-exception wrapping — actual behaviour.** In BouncyCastle 2.6.2, malformed keys/ciphertexts surface
  as `System.ArgumentException` (`"invalid encoding"` / `"encapsulation"`), not the BC
  `InvalidCipherTextException` the plan anticipated. Either way the services catch the input-failure region
  (`ArgumentException` or BouncyCastle `CryptoException`) and rethrow `System.Security.Cryptography.CryptographicException`,
  so criterion 5 holds and no BouncyCastle exception type escapes. Null-argument guards run before that
  region, so they still surface as `ArgumentNullException`.
- **`PemUtils` / `RandomUtils`** remained deferred/unused as the plan dictated — the raw-`byte[]` API needs
  neither.
- **Line endings (CRLF):** no line-ending anomalies observed in the touched files; no action taken (this
  note is recommendation-only per the workflow).
- The throwaway regeneration/probe tool lives only in the session scratchpad; it is not part of the repo.

## Build / test evidence
- **Library build:** `dotnet build src/Enigma.Core` — clean across `netstandard2.0;net8.0;net10.0` under
  `TreatWarningsAsErrors` + `GenerateDocumentationFile`. **0 warnings, 0 errors** (criterion 1).
- **Full solution build:** `dotnet build -c Release` — **0 warnings, 0 errors**.
- **Full test suite:** `dotnet test -f net10.0` — **1546 passed, 0 failed**; also **1546 passed** on
  `net8.0` (criterion 9). New PQC namespace: **47 tests, all passing**.
- **Multi-TFM PQC availability confirmed:** ML-DSA and ML-KEM (`MLDsaParameters.ml_dsa_*`,
  `MLKemParameters.ml_kem_*`, key generators, `MLDsaSigner`, `MLKemEncapsulator`/`MLKemDecapsulator`,
  `MLDsa/MLKem*KeyParameters` with `GetEncoded()` + `FromEncoding(parameters, byte[])`) are present on the
  BouncyCastle.Cryptography 2.6.2 `netstandard2.0` assembly (backing Core's netstandard2.0) and are
  exercised by the test project on both net8.0 and net10.0 — no TFM gap.

## Acceptance criteria — status
1. Zero-warning multi-TFM build — **met**.
2. No BouncyCastle type on the PQC public surface (reflection guard) — **met**.
3. All four services/factories implemented; no `NotImplementedException`, including the amended
   `CreateMLDsaService(..., bool deterministic)` — **met**.
4. ML-DSA generate→sign→verify for 44/65/87; fixed ML-DSA-87 vector true (right key) / false (wrong key) /
   false (tampered message & signature) — **met**.
5. ML-KEM generate→encapsulate→decapsulate for 512/768/1024; fixed ML-KEM-1024 vector recovers the known
   32-byte secret with the matching key and fails with the wrong key; malformed input ⇒
   `CryptographicException` — **met**.
6. Deterministic signing implemented + tested (byte-identical signatures) — **met**.
7. Raw-FIPS (expanded private-key) encoding recorded in XML docs + encode→re-inject round-trip test — **met**.
8. Factory→BC parameter mapping verified (via unique FIPS public-key sizes); defaults MLDsa65 / MLKem768 —
   **met**.
9. Full suite green on net10.0; multi-TFM PQC availability confirmed against BouncyCastle 2.6.2 — **met**.
10. Roadmap + plan status updated to DONE; this completion record written — **met**.
