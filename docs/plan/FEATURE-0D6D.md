# FEATURE-0D6D — Asymmetric.Pqc implementation (ML-DSA, ML-KEM)

- **Status:** DONE
- **Type:** FEATURE (single-phase)
- **Depends on:** FEATURE-61D1 (foundation — package ref; verify BC 2.6.2 ML-DSA/ML-KEM across all 3 TFMs)
- **Suggested branch (at build):** `feature/feature-0d6d-pqc`
- **Basis:** ported from Enigma.Cryptography v5.0.0 (`/home/jo/Dev/Enigma.Cryptography`); redesign decisions validated by user 2026-07-21.

## Objective
Implement the post-quantum cryptography module — ML-DSA (FIPS 204 signatures) and ML-KEM (FIPS 203 key encapsulation) — behind the FEATURE-4442 frozen contract in `Enigma.Core.Asymmetric.Pqc`, at MAXIMUM FIDELITY to Enigma.Cryptography v5.0.0. Every capability the skeleton dropped is restored (notably ML-DSA deterministic signing), while BouncyCastle stays entirely internal: all keys, signatures and ciphertexts cross the public API as raw `byte[]` in their FIPS 204/203 encoding.

## Basis — port from Enigma.Cryptography v5.0.0
Old source files (from the spec's oldToNewMapping):
- `src/Enigma.Cryptography/PQC/IMLDsaService.cs`, `PQC/MLDsaService.cs`
- `src/Enigma.Cryptography/PQC/IMLDsaServiceFactory.cs`, `PQC/MLDsaServiceFactory.cs`
- `src/Enigma.Cryptography/PQC/IMLKemService.cs`, `PQC/MLKemService.cs`
- `src/Enigma.Cryptography/PQC/IMLKemServiceFactory.cs`, `PQC/MLKemServiceFactory.cs`

Old tests + vectors to port/adapt:
- `src/UnitTests/PQC/MLDsaTests.cs`, `MLDsaKeyPairTests.cs`, `MLKemTests.cs`, `MLKemKeyPairTests.cs`
- Fixtures: `dsa87_A_public.pem`, `dsa87_A_private.pem`, `dsa87_B_public.pem`, `dsa87_B_private.pem`, `message.txt`, `signature.bin` (ML-DSA-87); `kem1024_A_public.pem`, `kem1024_A_private.pem`, `kem1024_B_public.pem`, `kem1024_B_private.pem`, `encapsulation.bin`, `secret.bin` (ML-KEM-1024).

## Scope & mapping
| Old | New home | Redesign / disposition |
|-----|----------|------------------------|
| `PQC/IMLDsaService.cs`, `PQC/MLDsaService.cs` | `Asymmetric/Pqc/IMLDsaService.cs`, `Asymmetric/Pqc/MLDsaService.cs` | Implemented behind raw `byte[]`; keypair → `(byte[] publicKey, byte[] privateKey)`; `AsymmetricKeyParameter` → `byte[]`; param `data` → `message`. BC (`MLDsaKeyPairGenerator`/`MLDsaSigner`) INTERNAL. |
| `PQC/IMLDsaServiceFactory.cs`, `PQC/MLDsaServiceFactory.cs` | `Asymmetric/Pqc/IMLDsaServiceFactory.cs`, `Asymmetric/Pqc/MLDsaServiceFactory.cs` | 3× `CreateDsa44/65/87Service(bool deterministic=false)` collapse to one `CreateMLDsaService(MLDsaParameterSet=MLDsa65, bool deterministic=false)` — **`deterministic` restored** (see amendments). Internal map `MLDsa44/65/87 → MLDsaParameters.ml_dsa_44/65/87`. |
| `PQC/IMLKemService.cs`, `PQC/MLKemService.cs` | `Asymmetric/Pqc/IMLKemService.cs`, `Asymmetric/Pqc/MLKemService.cs` | Implemented behind raw `byte[]`; `Encapsulate` tuple `(encapsulation,secret)` → `(ciphertext,sharedSecret)`; `AsymmetricKeyParameter` → `byte[]`. BC (`MLKemKeyPairGenerator`/`MLKemEncapsulator`/`MLKemDecapsulator`) INTERNAL. |
| `PQC/IMLKemServiceFactory.cs`, `PQC/MLKemServiceFactory.cs` | `Asymmetric/Pqc/IMLKemServiceFactory.cs`, `Asymmetric/Pqc/MLKemServiceFactory.cs` | 3× `CreateKem512/768/1024Service()` collapse to one `CreateMLKemService(MLKemParameterSet=MLKem768)`. Internal map `MLKem512/768/1024 → MLKemParameters.ml_kem_512/768/1024`. |
| — (was BC `MLDsaParameters` fan-out) | `Asymmetric/Pqc/MLDsaParameterSet.cs` | NEW enum `{ MLDsa44, MLDsa65, MLDsa87 }`. Already frozen. |
| — (was BC `MLKemParameters` fan-out) | `Asymmetric/Pqc/MLKemParameterSet.cs` | NEW enum `{ MLKem512, MLKem768, MLKem1024 }`. Already frozen. |
| `Utils/PemUtils.cs` | DEFERRED — NOT un-deferred by this feature | Raw `byte[]` API removes the `AsymmetricKeyParameter`/PEM coupling; PemUtils touches only legacy PEM vectors, handled in-test (regenerate as raw bytes). |
| `Utils/RandomUtils.cs` | DEFERRED — NOT needed | `SecureRandom` is used inline for key generation, exactly as the old code did. |

## Contract amendments to the frozen skeleton (FEATURE-4442)
Approved by user 2026-07-21.

| Member | Signature (BC-free) | Restores (old member/test) | Notes |
|--------|---------------------|----------------------------|-------|
| `IMLDsaServiceFactory.CreateMLDsaService` | `IMLDsaService CreateMLDsaService(MLDsaParameterSet parameterSet = MLDsaParameterSet.MLDsa65, bool deterministic = false)` | Old `CreateDsa44/65/87Service(bool deterministic = false)` and `MLDsaService(bool deterministic)` ctor; `MLDsaKeyPairTests.SignAndVerify_Deterministic` | Adds a trailing optional `bool` — source-compatible with the frozen signature. `deterministic` is a plain `bool`, so principle-1 BC-hiding is preserved (no BC type enters the signature). Internally forwarded to `MLDsaSigner(MLDsaParameters, deterministic)`. Added FIRST as a throwing stub (amend `IMLDsaServiceFactory` + `MLDsaServiceFactory` to the new signature, body `throw new NotImplementedException()`), then implemented. |

No other amendment is required: the ML-KEM contract, both parameter-set enums, the tuple shapes and the raw-`byte[]` surface are implemented as frozen. The `byte[]` encoding and private-key form (previously open in the spec) are settled implementation decisions, not contract changes (see Redesign decisions).

## BouncyCastle usage (internal only)
- ML-DSA: `Org.BouncyCastle.Crypto.Generators.MLDsaKeyPairGenerator`, `Crypto.Parameters.MLDsaKeyGenerationParameters`, `Crypto.Parameters.MLDsaParameters` (`ml_dsa_44/65/87`), `Crypto.Signers.MLDsaSigner(MLDsaParameters, bool deterministic)` (`Init`/`BlockUpdate`/`GenerateSignature`/`VerifySignature`), `Crypto.Parameters.MLDsaPublicKeyParameters`/`MLDsaPrivateKeyParameters` for `byte[]`↔key via `GetEncoded()` + `(parameters, byte[])` reconstruction.
- ML-KEM: `Crypto.Generators.MLKemKeyPairGenerator`, `Crypto.Parameters.MLKemKeyGenerationParameters`, `Crypto.Parameters.MLKemParameters` (`ml_kem_512/768/1024`), `Crypto.Kems.MLKemEncapsulator`/`MLKemDecapsulator` (`EncapsulationLength`/`SecretLength`; `Encapsulate`/`Decapsulate`), `Crypto.Parameters.MLKemPublicKeyParameters`/`MLKemPrivateKeyParameters` for `byte[]`↔key.
- `Org.BouncyCastle.Security.SecureRandom` used inline for generation.
- `Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair` / `AsymmetricKeyParameter` appear only as transient locals before encoding to `byte[]`.
- Any BC decapsulation/auth failure (`InvalidCipherTextException`) is wrapped in `System.Security.Cryptography.CryptographicException` at the service boundary (orchestrator decision) — no BC exception type escapes.
- `PublicKeyFactory`/`PrivateKeyFactory` + `*InfoFactory` are NOT used: the raw-FIPS encoding decision (below) makes them unnecessary.
None of these may appear in a public signature, base type, thrown-type-in-signature or public support member — enforced by a reflection test.

## Redesign decisions
### Already frozen (FEATURE-4442, PHASE05)
- Keys/signatures/ciphertexts are raw `byte[]` in FIPS 203/204 encoding — no BC `AsymmetricKeyParameter`/`AsymmetricCipherKeyPair` in any public signature (principle 1; satisfies the PHASE05 flag).
- `GenerateKeyPair` → `(byte[] publicKey, byte[] privateKey)` and `Encapsulate` → `(byte[] ciphertext, byte[] sharedSecret)` as named `ValueTuple`s; no new DTO types.
- New enums `MLDsaParameterSet { MLDsa44, MLDsa65, MLDsa87 }` and `MLKemParameterSet { MLKem512, MLKem768, MLKem1024 }` replace the BC parameter fan-out (principle 2).
- Single factory method per scheme; defaults `MLDsa65` (category 3) and `MLKem768` (category 3).
- `ML` acronym kept upper-case; sync `byte[]` surface, no async/Stream, no `bufferSize`.
- TFMs `netstandard2.0;net8.0;net10.0` — ML-DSA/ML-KEM confirmed present in BouncyCastle.Cryptography 2.6.2 on the netstandard2.0 assembly (used by Core's netstandard2.0) and the net6.0 assembly (used by net8.0/net10.0). **No TFM gap.**

### Restored per user validation (2026-07-21)
- **ML-DSA deterministic signing** — restored via the optional `bool deterministic = false` on `CreateMLDsaService` (decision `trims_restore.mldsaDeterministic`). Rationale: FIPS 204 deterministic-vs-hedged signing is a real public capability of the source library; dropping it is a feature regression. A trailing optional `bool` restores it without breaking the frozen shape and without introducing any BC type. The old `SignAndVerify_Deterministic` test is ported.
- **Raw FIPS key encoding** (settled implementation decision, orchestrator `orchestrator_impl_choices`): PQC keys are raw FIPS 204/203 bytes obtained via `GetEncoded()` and reconstructed via the `(parameters, byte[])` constructors — no DER SPKI/PKCS#8 wrapping. Rationale: matches the frozen XML-doc wording ("raw byte arrays in their FIPS 204/203 encoding"), smallest and interop-neutral. The XML docs are updated to name the exact encoding. This resolves the spec's open "byte[] encoding" divergence — no user question needed.
- **ML-DSA private key = expanded-key encoding** (settled, orchestrator `orchestrator_impl_choices`): the canonical private-key `byte[]` is BouncyCastle's expanded-key encoding, guaranteed to round-trip `GenerateKeyPair → Sign`; an explicit round-trip test is added. Rationale: expanded key is directly usable for signing without seed re-derivation. This resolves the spec's open "seed vs expanded" divergence — no user question needed.
- **KEM raw private-key bytes** — the encrypted-PKCS#8 PEM/password concern is gone by design; when regenerating vectors the PKCS#8 PEM is decrypted once and stored as raw unencrypted private-key bytes. No password parameter on the new API.

### Open for PR
- None. Every PQC divergence is resolved by a decision key (`mldsaDeterministic`, `orchestrator_impl_choices` for encoding/private-key form/BC-exception wrapping) or is a frozen accept (factory enum, tuple renames, parameter rename). Recommended default if any is reopened: keep the resolutions above.

## Test plan
Port the four old test files to the new BC-free API:
- **Round-trip tests** (port near-verbatim): `MLDsaKeyPairTests` sign/verify for `MLDsa44/65/87` and `MLKemKeyPairTests` encapsulate/decapsulate for `MLKem512/768/1024` — replace `CreateDsaNNService()`/`CreateKemNNNService()` with `CreateMLDsaService(MLDsaParameterSet.MLDsaNN)`/`CreateMLKemService(MLKemParameterSet.MLKemNNN)`, replace `keyPair.Public`/`.Private` with `(publicKey, privateKey)` deconstruction, and use the new `(ciphertext, sharedSecret)` tuple names.
- **Fixed-vector tests** (`MLDsaTests`, `MLKemTests`): bridge the PEM→raw-`byte[]` gap dictated by the raw-FIPS decision. **Regenerate the fixed vectors as raw key bytes once** — extract `dsa87_A/B` public raw bytes and `kem1024_A/B` private raw bytes (decrypting the PKCS#8 PEM during regeneration), keeping `message.txt`/`signature.bin`/`secret.bin`/`encapsulation.bin` unchanged — and load them directly as `byte[]` (no PemUtils, no BouncyCastle in test). `Verify_ValidSignature` true / `Verify_WrongKey` false; `Decapsulate_MatchingPrivateKey` equals the 32-byte `secret.bin` / `Decapsulate_WrongPrivateKey` differs.
- **New tests warranted by the redesign:**
  - (a) **Reflection guard** — assert no public member (signature, base type, generic argument, return/parameter type) in `Enigma.Core.Asymmetric.Pqc` references any `Org.BouncyCastle` type. Proves principle 1.
  - (b) **Private-key encode→re-inject round-trip** — `GenerateKeyPair → Sign(message, privateKey) → Verify` and `GenerateKeyPair → Decapsulate(ciphertext, privateKey)`, proving the expanded-key `byte[]` produced by `GenerateKeyPair` is accepted back by `Sign`/`Decapsulate`.
  - (c) **Deterministic signing test** — with `deterministic: true`, two signings of the same message are byte-identical; with `deterministic: false` (default, hedged) they may differ. (Restored capability.)
  - (d) **Negative tests** — tampered message and tampered signature ⇒ `Verify` false; wrong-key decapsulation ⇒ shared-secret mismatch.
  - (e) **BC-exception wrapping** — a malformed ciphertext/key surfaces as `System.Security.Cryptography.CryptographicException`, never a BC `InvalidCipherTextException`.
  - (f) Optionally one NIST ACVP known-answer vector for a single parameter set per scheme as an added confidence test.
- **Vector regeneration required:** the fixed ML-DSA-87 public and ML-KEM-1024 private fixtures are regenerated as raw FIPS bytes (the legacy vectors are PEM/DER and are NOT the same bytes). No CSV harness applies here (PQC has no CSV theory data). Reuse foundation's `CryptoKeyPairFixture`/`ArgumentValidationTests` rebuilt BC-free for keys-as-`byte[]`; coverage via `coverlet.collector`.

## Dependencies
- **foundation (FEATURE-61D1)** — MUST land first. It adds the `BouncyCastle.Cryptography` 2.6.2 + `System.Buffers` package references to `Enigma.Core` (the skeleton left BC unreferenced) and ports the shared test harness (`CryptoKeyPairFixture`, `ArgumentValidationTests`, `coverlet.collector`). This is the feature's only dependency: the raw `byte[]` API needs neither `PemUtils` nor any RSA/PublicKey type, so there is **no dependency on publickey (FEATURE-2E3E)**.

## Phases
Single-phase — the frozen skeleton (four service/factory stubs + two enums) is small, cohesive and in-memory. No sub-phasing.

## Acceptance criteria
1. `Enigma.Core` builds clean with **ZERO warnings** across `netstandard2.0;net8.0;net10.0` under `TreatWarningsAsErrors` + `GenerateDocumentationFile`.
2. **No BouncyCastle type** appears in any public signature, base type, thrown-type-in-signature or public member of `Enigma.Core.Asymmetric.Pqc` — enforced by the reflection unit test.
3. All four stubs (`MLDsaService`, `MLDsaServiceFactory`, `MLKemService`, `MLKemServiceFactory`) fully implemented; **no member throws `NotImplementedException`**, including the amended `CreateMLDsaService(..., bool deterministic)`.
4. **ML-DSA:** `GenerateKeyPair → Sign → Verify` round-trips for `MLDsa44/65/87`; ported fixed ML-DSA-87 vector verifies true against the right key, false against the wrong key, and false for a tampered message/signature.
5. **ML-KEM:** `GenerateKeyPair → Encapsulate → Decapsulate` recovers the same shared secret for `MLKem512/768/1024`; ported fixed ML-KEM-1024 vector decapsulates to the known 32-byte secret with the matching key and fails with the wrong key; malformed input raises `CryptographicException` (no BC exception escapes).
6. **Restored deterministic signing implemented + tested:** `deterministic: true` produces byte-identical signatures for the same message (ported `SignAndVerify_Deterministic`).
7. **Raw-FIPS encoding recorded** in XML docs and covered by the private-key encode→re-inject round-trip test (expanded-key form accepted by `Sign`/`Decapsulate`).
8. Factory→BC parameter mapping verified (`MLDsa44/65/87 → ml_dsa_44/65/87`; `MLKem512/768/1024 → ml_kem_512/768/1024`); defaults `MLDsa65` and `MLKem768`.
9. Full solution test suite green on net10.0; completion doc states multi-TFM PQC availability confirmed against BouncyCastle 2.6.2.
10. Roadmap (`docs/roadmap.md`) and this plan's status updated; completion record `docs/done/FEATURE-0D6D.md` written.
