# FEATURE-4442-PHASE05 — Asymmetric (PublicKey + Pqc) (DONE)

## Summary
Fifth phase of the abstraction skeleton: scaffolded the **Asymmetric** modules — **PublicKey** (RSA
encryption PKCS#1 v1.5 + OAEP, and RSASSA-PKCS1-v1_5 signing) and **Pqc** (post-quantum **ML-DSA** /
FIPS 204 signatures and **ML-KEM** / FIPS 203 key encapsulation) — as redesigned, BouncyCastle-free
public contracts with empty (`throw new NotImplementedException()`) implementations. No algorithm logic —
later features fill the stubs behind these stable interfaces. All operations are in-memory, so they use
**sync `byte[]`** APIs with **no `bufferSize`** on their factories (mirroring the KeyDerivation/OTP
decisions from PHASE03/04). The BouncyCastle `IPasswordFinder`-based `PemPasswordFinder` support type is
**redesigned away** into a plain `char[]? password` parameter, per the support-type triage.

## Files/modules touched

### Created — `Enigma.Core.Asymmetric.PublicKey` (`src/Enigma.Core/Asymmetric/PublicKey/`)
- `RsaOaepHash.cs` — ported enum `{ Sha1, Sha256, Sha384, Sha512 }` (pure; the hash backing RSAES-OAEP).
  Referenced by `EncryptOaep`/`DecryptOaep`.
- `IPublicKeyService.cs` — interface (6 members): `EncryptPkcs1`/`DecryptPkcs1`,
  `EncryptOaep`/`DecryptOaep(…, RsaOaepHash hash = Sha256, char[]? password = null)`,
  `Sign(…, RsaSignatureAlgorithm algorithm = Sha256WithRsa, char[]? password = null)` / `Verify(…)`.
  Keys are PEM `string`.
- `PublicKeyService.cs` — sealed stub (all 6 methods throw).
- `IPublicKeyServiceFactory.cs` — interface: `CreatePublicKeyService()` (single, parameterless).
- `PublicKeyServiceFactory.cs` — sealed stub (method throws).

### Created — `Enigma.Core.Asymmetric.Pqc` (`src/Enigma.Core/Asymmetric/Pqc/`)
- `MLDsaParameterSet.cs` — new Enigma enum `{ MLDsa44, MLDsa65, MLDsa87 }` (FIPS 204 security levels).
- `IMLDsaService.cs` — interface: `(byte[] publicKey, byte[] privateKey) GenerateKeyPair()`,
  `byte[] Sign(byte[] message, byte[] privateKey)`, `bool Verify(byte[] message, byte[] signature, byte[] publicKey)`.
- `MLDsaService.cs` — sealed stub (all 3 methods throw).
- `IMLDsaServiceFactory.cs` — interface: `CreateMLDsaService(MLDsaParameterSet parameterSet = MLDsa65)`.
- `MLDsaServiceFactory.cs` — sealed stub (method throws).
- `MLKemParameterSet.cs` — new Enigma enum `{ MLKem512, MLKem768, MLKem1024 }` (FIPS 203 security levels).
- `IMLKemService.cs` — interface: `(byte[] publicKey, byte[] privateKey) GenerateKeyPair()`,
  `(byte[] ciphertext, byte[] sharedSecret) Encapsulate(byte[] publicKey)`,
  `byte[] Decapsulate(byte[] ciphertext, byte[] privateKey)`.
- `MLKemService.cs` — sealed stub (all 3 methods throw).
- `IMLKemServiceFactory.cs` — interface: `CreateMLKemService(MLKemParameterSet parameterSet = MLKem768)`.
- `MLKemServiceFactory.cs` — sealed stub (method throws).

### Modified — workflow tracking
- `docs/roadmap.md` — PHASE05 `TODO` → `IN PROGRESS` → `DONE` (base FEATURE-4442 stays `IN PROGRESS`;
  PHASE06 remains `TODO`).
- `docs/plan/FEATURE-4442.md` — PHASE05 status flips; recorded the full build-time signature design in the
  PHASE05 section (per principle 8), including the source-parity note.

## Design decisions (recorded for downstream phases)
- **In-memory ⇒ sync + no `bufferSize`.** RSA processes data smaller than the modulus; ML-DSA/ML-KEM
  operate on small messages/keys — none stream. So (like the KDFs/OTP) the APIs are sync `byte[]` and the
  factories carry no `bufferSize`. Principle 4's "async-Stream vs sync-`byte[]` split" applies only where
  the source streamed, which none of these did.
- **RSA encryption padding = explicit method pairs, not a padding enum.** `EncryptPkcs1`/`EncryptOaep`
  (and their `Decrypt*` inverses) keep the two schemes the plan names ("PKCS#1 v1.5 + OAEP") unambiguous
  and keep the ported `RsaOaepHash` meaningful as the OAEP methods' hash parameter — a second
  padding-selector enum would duplicate `RsaOaepHash`, which the plan says to port verbatim. Parallels the
  Padding module's per-scheme methods.
- **`RsaSignatureAlgorithm` consumed from root (PHASE01).** `Sign`/`Verify` take the PHASE01 root enum
  (default `Sha256WithRsa`), exactly as PHASE01 intended when it fixed the shared signature vocabulary.
- **`PemPasswordFinder` redesigned away** (principle 1 / triage): replaced by `char[]? password = null`
  on the private-key operations (`DecryptPkcs1`, `DecryptOaep`, `Sign`); `null` means the PEM is not
  encrypted. `char[]` (not `string`) is the conventional clearable passphrase form and matches
  `IPasswordFinder.GetPassword()`'s return. No `PemPasswordFinder` type created.
- **Single parameterless RSA factory method.** RSA is the only algorithm, so `CreatePublicKeyService()`
  takes no config — padding/OAEP-hash/signature-algorithm are per-call parameters (as block-cipher *mode*
  is a per-call parameter rather than a factory fan-out).
- **PQC parameter set = new owning-module enum, on the factory.** `MLDsaParameterSet`/`MLKemParameterSet`
  give a BouncyCastle-free way to select the security level via the factory (principle 2); introduced in
  the owning module per the plan's Notes ("new Enigma type … define it in the owning module"), analogous
  to `BlockCipherMode`/`PaddingScheme` in PHASE02. Defaults are category-3 (`MLDsa65`, `MLKem768`).
- **PQC multi-value results = named `ValueTuple`s.** `GenerateKeyPair` and `Encapsulate` return named
  tuples rather than new named DTOs, keeping the skeleton to the plan's triage (no extra support type).
- **All factory `Create*` members throw too** (principle 5 / acceptance 3), so no concrete stub needs
  constructor parameters — avoids unused-field/unread-parameter errors under `TreatWarningsAsErrors`.

## Deviations & follow-ups
- **Source-parity (no source library in the repo).** As in PHASE01–04, the original library isn't present,
  so signatures were designed at build time per principle 8. To verify against source at PR: (1) RSA key
  material — whether the source also took/returned DER `byte[]` overloads or exposed key-pair generation on
  this service (kept to PEM `string` + encrypt/sign per the mapping's stated scope); (2) whether encryption
  padding was one method with a scheme selector vs the `EncryptPkcs1`/`EncryptOaep` pairs chosen here;
  (3) passphrase type (`char[]` vs `string`) and the exact `RsaOaepHash` member set; (4) PQC key
  representation (raw `byte[]` vs PEM `string` vs a named key-pair DTO) and whether the parameter set sat
  on the factory (as here) or per call; (5) exact PQC parameter-set member sets. All adjustable later
  without disturbing the skeleton (stubs throw).
- **`RsaSignatureAlgorithm` / nested-namespace resolution.** `IPublicKeyService` references the root
  `RsaSignatureAlgorithm` with **no `using`** — `Enigma.Core.Asymmetric.PublicKey` is nested within
  `Enigma.Core`, so the root type resolves through the enclosing namespace. Confirmed by the clean build.
- **`ValueTuple` on `netstandard2.0`.** Named tuples in the PQC signatures compile clean on all three TFMs
  (`System.ValueTuple` is intrinsic to netstandard2.0; PolySharp covers any remaining polyfills). Verified
  by the clean multi-TFM build.
- **Line endings (CRLF):** none observed — all new files are LF, consistent with `.gitattributes`
  `* text=auto eol=lf`. No action taken (recommendation-only per `dev-workflow`).
- **No new unit tests** (acceptance criterion 5): stubs throw, nothing meaningful to assert; real tests
  arrive with the RSA/PQC implementation features.

## Build/test evidence
- **Build:** `dotnet build Enigma.Core.slnx -warnaserror` → `Build succeeded. 0 Warning(s) 0 Error(s)`,
  producing `Enigma.Core.dll` for `netstandard2.0`, `net8.0`, and `net10.0` under `TreatWarningsAsErrors`
  + `GenerateDocumentationFile` (so all-public-members XML docs, CS1591, are enforced as errors).
- **Test:** `dotnet test --solution Enigma.Core.slnx` (MTP) → `Passed! total: 1, failed: 0, succeeded: 1,
  skipped: 0`. Definition-of-Done criterion 2 satisfied by the existing smoke test staying green (no new
  tests this phase, per acceptance criterion 5).
- **No BouncyCastle exposure:** `grep -rniE "bouncy|org\.bouncycastle|ICipherParameters|IPasswordFinder|
  IDigest|SecureRandom|AsymmetricKeyParameter"` over `src/Enigma.Core/Asymmetric` returns no matches;
  `BouncyCastle.Cryptography` remains unreferenced by the project, so the clean build proves zero coupling.

## Acceptance criteria (per-phase list) — all met
1. ✅ Build clean (zero warnings) across `netstandard2.0`, `net8.0`, `net10.0` under `TreatWarningsAsErrors`.
2. ✅ No BouncyCastle types in any public signature, base type, or support-type member.
3. ✅ Every service/factory is a `sealed` class implementing its interface with `throw new
   NotImplementedException()` bodies (6 stub classes, 15 members).
4. ✅ XML docs on all public types/members (enforced by CS1591-as-error).
5. ✅ No new unit tests; existing smoke test passes green.
6. ✅ Roadmap + plan PHASE05 status updated; this completion doc written.
