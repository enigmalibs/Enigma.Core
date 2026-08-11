# FEATURE-5413 — PQC PEM services (ML-DSA / ML-KEM)

**Status:** TODO (multi-phase)
**Type:** FEATURE (multi-phase)
**Branch (per phase, at build time):** `feature/feature-5413-phaseNN-<slug>` — one branch per phase, cut from current `HEAD`.

## Objective

Add PEM serialization for post-quantum keys as a **separate, additive** concern: two new services
(`IMLDsaPemService`, `IMLKemPemService`) that convert between the library's canonical `byte[]` key
form and PEM text — public keys, unencrypted private keys, and PBES2-encrypted private keys — and
that recover the parameter set from the algorithm OID on read.

`IMLDsaService` and `IMLKemService` are **not modified**. This item breaks nothing.

It also creates the **single shared internal PEM implementation** (`Enigma.Core.Internal.PemEnvelope`)
that FEATURE-6852 and FEATURE-57A9 will use, so the encryption scheme, the iteration count and the
exception mapping exist exactly once in the assembly.

## Context & constraints

- **Evolution of an existing, published codebase.** Enigma.Core 1.1.0 is on nuget.org. This item is
  additive; it ships as part of **2.0.0** together with FEATURE-6852 / FEATURE-57A9 (see FEATURE-19C7).
- Source brief: `docs/pem-work-brief.md` (untracked working document) plus the `/interview` session
  that produced this plan. Where the two disagree, **this plan wins** — three of the brief's
  statements were disproved by measurement (see *Planning-time evidence*).
- **Load-bearing invariant** — no `Org.BouncyCastle.*` type on any exported type or member
  (`tests/Enigma.Core.UnitTests/Api/BouncyCastleIsolationTests.cs` plus the per-category guards).
  `Pqc/PqcBouncyCastleIsolationTests.cs` filters **by namespace**, so every new public type in
  `Enigma.Core.Asymmetric.Pqc` is covered automatically — no test edit needed, but it must stay green.
- Multi-targets `netstandard2.0;net8.0;net10.0`; `TreatWarningsAsErrors=true`,
  `EnforceCodeStyleInBuild=true`, `Nullable=enable`, `ImplicitUsings=disable`, `LangVersion=14`.
- Central Package Management — no new packages; BouncyCastle stays at **2.7.0**.
- Tests are MTP-native (`xunit.v3` + `coverlet.collector`), test TFMs `net8.0;net10.0`.
- **The solution has no `InternalsVisibleTo` anywhere.** `PemEnvelope`, `MLParameterSets` and
  `PemUtils` are therefore **not directly testable**; every assertion must go through the public
  surface. This is why some behaviour specified here is only *verified* in FEATURE-6852-PHASE01,
  where `RsaKey` first makes the RSA code paths publicly reachable — see design step 1.
- **Test fixture files are copied by wildcard**: `tests/Enigma.Core.UnitTests/Enigma.Core.UnitTests.csproj`
  globs `**/*.pem`, `**/*.csv`, `**/*.key`, `**/*.bin`, `**/*.txt` with `PreserveNewest`. A new fixture
  needs no `.csproj` edit.
- `.gitattributes` enforces `eol=lf`; no line-ending recommendation to make.
- **Module independence:** `docs/plan/FEATURE-0D6D.md:74` records that the PQC module was built with
  "no dependency on publickey". The shared PEM code therefore lives in a **neutral** internal
  namespace, not in `Asymmetric.PublicKey`.

## Planning-time evidence (measured against BouncyCastle 2.7.0 — do not re-derive)

Probed during the interview with a throwaway console project; the repository was not modified.

| Probe | Result |
|---|---|
| `MLDsaPrivateKeyParameters` nested `Format` enum | `SeedOnly`, `EncodingOnly`, `SeedAndEncoding` |
| `MLDsaPrivateKeyParameters.DefaultFormat` | **`SeedOnly`** — the brief's claim of `SeedAndEncoding` is **wrong**. A *generated* instance reports `SeedAndEncoding`; one rebuilt via `FromEncoding` reports `EncodingOnly` |
| **Seed recoverability** | `generated.GetSeed()` → 32 bytes; **`FromEncoding(expanded).GetSeed()` → `null`** |
| `WithPreferredFormat` on a rebuilt key | `SeedOnly` → **`InvalidOperationException: no seed available`**; `SeedAndEncoding` → same; `EncodingOnly` → DER 4060 bytes. Identical for ML-KEM |
| PKCS#8 DER sizes, ML-DSA-65 | generated+`SeedOnly` 54 B · generated+`EncodingOnly` 4060 B · generated+`SeedAndEncoding` 4098 B |
| PKCS#8 DER sizes, ML-KEM-768 | generated+`SeedOnly` 86 B · `EncodingOnly` 2428 B · `SeedAndEncoding` 2498 B |
| Seed-PEM round trip | 132-char seed-only PEM → `OpenSsl.PemReader` → `MLDsaPrivateKeyParameters` → `GetEncoded()` **4032 B, byte-identical to the original expanded key** |
| PBES2 on a PQC key | `CreateEncryptedPrivateKeyInfo(IdAes256Cbc, IdHmacWithSha256, pwd, salt16, 600000, rnd, pki)` → `EncryptedPrivateKeyInfo.GetInstance` → `PrivateKeyInfoFactory.CreatePrivateKeyInfo(pwd, epki)` → `PrivateKeyFactory.CreateKey` returns `MLDsaPrivateKeyParameters`. **Works** |
| 600 000-iteration decrypt cost | **605 ms** (net10.0, Release, this machine) |
| Wrong password, manual path | `Org.BouncyCastle.Crypto.InvalidCipherTextException: pad block corrupted` |
| `OpenSsl.PemReader` on an ML-DSA `PUBLIC KEY` PEM | returns `MLDsaPublicKeyParameters`; `.Parameters` → `ML-DSA-65` |
| SPKI OIDs | ML-DSA-65 `2.16.840.1.101.3.4.3.18` · ML-KEM-768 `2.16.840.1.101.3.4.4.2` (brief confirmed) |

## Design decisions (from the interview)

1. **BLOCKER — the seed is not in the expanded key, so the brief's `ToPrivateKeyPem(..., format)`
   cannot work.** FIPS 204/203 expanded private keys carry no seed; a key rebuilt from the encoding
   that `IMLDsaService.GenerateKeyPair()` returns has `GetSeed() == null` and throws for two of the
   three formats. **Resolution:** `ToPrivateKeyPem` **loses its `format` parameter** and always writes
   the expanded encoding (`EncodingOnly`); a new **`GenerateKeyPairPem`** on the PEM service generates
   the key internally — where the seed still exists — so all three formats stay genuinely producible
   with `Seed` as the default. `IMLDsaService`/`IMLKemService` remain untouched.
2. **Per-family split, not one combined service** — the read direction cannot be overloaded by return
   type, and the split mirrors the module's existing `IMLDsaService`/`IMLKemService` shape.
3. **Shared PEM code in a neutral internal namespace** — `src/Enigma.Core/Internal/PemEnvelope.cs`,
   namespace `Enigma.Core.Internal`. Keeps `Asymmetric.Pqc` free of any dependency on
   `Asymmetric.PublicKey` (FEATURE-0D6D:74). `PemUtils` is **not touched by this item** — it is
   re-pointed at `PemEnvelope` in FEATURE-6852-PHASE01, because doing it here would change the RSA
   encrypted-write format inside an item billed as non-breaking.
4. **PBES2 / PBKDF2-HMAC-SHA256 / AES-256-CBC, 16-byte salt, `600_000` iterations**, as one named
   internal constant. Confirmed at interview against the measured 605 ms cost: it is a one-time
   per-import cost and matches OWASP's current PBKDF2-HMAC-SHA256 guidance.
5. **Read dispatch by PEM label.** `ENCRYPTED PRIVATE KEY` → the manual `EncryptedPrivateKeyInfo`
   path (verified for PQC); every other label → `Org.BouncyCastle.OpenSsl.PemReader`, which returns
   `MLDsaPublicKeyParameters` / `MLDsaPrivateKeyParameters` / `MLKem…` directly. One dispatch, used
   by every module.
6. **Parameter-set mapping is centralised.** A new internal `MLParameterSets` helper owns both
   directions (`MLDsaParameterSet ↔ MLDsaParameters`, `MLKemParameterSet ↔ MLKemParameters`), and the
   two **existing** factories are re-pointed at it. This is the only edit to existing PQC product
   files and is a pure internal refactor with no behaviour change — accepted deliberately, because
   duplicating the mapping is exactly the drift this item exists to prevent.
7. **Factories are parameterless**, `new`-constructed, like every other factory in the library; the
   parameter set is a per-call argument, not factory state. No `deterministic` flag — it is a signing
   concern, irrelevant to serialization.

## Public surface added by this item

In `Enigma.Core.Asymmetric.Pqc` (ML-DSA shown; ML-KEM is identical with `MLKemParameterSet`):

```csharp
public enum MLPrivateKeyPemFormat
{
    Seed,                 // DEFAULT — smallest; 132-char PEM for ML-DSA-65
    ExpandedKey,
    SeedAndExpandedKey,
}

public interface IMLDsaPemService
{
    (string publicKeyPem, string privateKeyPem) GenerateKeyPairPem(
        MLDsaParameterSet parameterSet,
        char[]? password = null,
        MLPrivateKeyPemFormat format = MLPrivateKeyPemFormat.Seed);

    string ToPublicKeyPem(byte[] publicKey, MLDsaParameterSet parameterSet);

    string ToPrivateKeyPem(byte[] privateKey, MLDsaParameterSet parameterSet, char[]? password = null);

    (byte[] publicKey, MLDsaParameterSet parameterSet) FromPublicKeyPem(string pem);

    (byte[] privateKey, MLDsaParameterSet parameterSet) FromPrivateKeyPem(string pem, char[]? password = null);
}

public interface IMLDsaPemServiceFactory
{
    IMLDsaPemService CreateMLDsaPemService();
}
```

Contract notes, identical for both families:

- `privateKey` **in** is always the expanded FIPS encoding — exactly what `GenerateKeyPair()` returns.
- `privateKey` **out** is always the expanded FIPS encoding, whatever the PEM stored; a seed-only PEM
  is expanded on read so the bytes are directly usable by `Sign` / `Decapsulate`.
- The parameter set is recovered from the algorithm OID and returned — a capability the raw `byte[]`
  API cannot offer.
- Emitted labels are exactly `PUBLIC KEY`, `PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`.
- Passwords are `char[]?`, never `string`, never `SecureString`; the library never clears the
  caller's array — the XML docs must say the caller owns its lifetime (match the wording currently on
  `IPublicKeyService.GenerateRsaKeyPair`).

## Exception contract (identical across every module)

| Condition | Exception |
|---|---|
| `null` argument | `ArgumentNullException`, guarded **before** any `try` |
| malformed / structurally invalid PEM | `ArgumentException` with `paramName` |
| `FromPublicKeyPem` on a private-key PEM, or the reverse | `ArgumentException` with `paramName` |
| encrypted PEM, no password supplied | `CryptographicException` |
| wrong password | `CryptographicException` |
| key bytes of the wrong length / wrong parameter set | `ArgumentException` with `paramName` |
| undefined enum value | `ArgumentOutOfRangeException` (matches the existing PQC factories) |

No BouncyCastle exception may escape. The shared mapping helper must implement **exactly these four
branches, in this order** — mirroring `PemUtils.cs:70-85`, which is the behaviour FEATURE-6852 and
FEATURE-57A9 inherit:

1. `Org.BouncyCastle.OpenSsl.PasswordException` → `CryptographicException`
   ("encrypted; a password is required"). **Must be caught first**: it derives from
   `Org.BouncyCastle.Security.PasswordException` → `System.IO.IOException`, **not** from
   `PemException`, so an `IOException` fallback placed above it would swallow it and produce
   `ArgumentException` instead — silently breaking the "encrypted PEM, no password" row above.
   Bind it through a `using PasswordException = Org.BouncyCastle.OpenSsl.PasswordException;` alias:
   `Org.BouncyCastle.Security.PasswordException` is `[Obsolete]` and would fail the build under
   `TreatWarningsAsErrors` (see `PemUtils.cs:7-9` and `docs/plan/FEATURE-797D.md` decision 2).
2. `Org.BouncyCastle.Crypto.InvalidCipherTextException` → `CryptographicException`
   ("could not be decrypted; the password may be incorrect"). This is the wrong-password case on the
   manual PBES2 path — measured message: `pad block corrupted`.
3. `Org.BouncyCastle.OpenSsl.PemException` → `CryptographicException` (same message). This is the
   wrong-password **and** missing-password case on the `OpenSsl.PemReader` PBES2 path.
4. any remaining `System.IO.IOException` → `ArgumentException` with `paramName` ("malformed"). This
   deliberately catches `Org.BouncyCastle.OpenSsl.EncryptionException` (also an `IOException`, raised
   for an unrecognised `DEK-Info` cipher): an unknown cipher header is a structural PEM defect, not a
   failed decryption. **Do not** collapse this into branch 3 — the split is pinned by
   `tests/…/PublicKey/RsaArgumentValidationTests.cs:94`
   (`PrivateKeyOperation_UnsupportedDekAlgorithm_ThrowsArgumentException`, added by FEATURE-797D) and
   re-based onto the legacy fixture by FEATURE-6852-PHASE01.

## FORBIDDEN implementation paths

- `PemWriter.WriteObject(key, "AES-256-CBC", password, random)` — does **not** throw for ML-DSA; it
  silently emits a malformed hybrid (`BEGIN PRIVATE KEY` carrying `Proc-Type`/`DEK-Info` over a
  PKCS#8 body).
- `Pkcs8Generator` with a password — in 2.7.0 it offers only legacy PKCS#12 PBE (SHA1+3DES / RC2 /
  RC4).

## Definition of Done (applies to every phase)

Standard `dev-workflow` DoD:

1. `dotnet build Enigma.Core.slnx -c Release` succeeds with **zero warnings** across all three TFMs.
2. `dotnet test --solution Enigma.Core.slnx -c Release` passes in full on **net8.0 and net10.0**.
3. Every acceptance criterion of the phase is met.
4. Roadmap row + this plan file's phase status updated.
5. `docs/done/FEATURE-5413-PHASENN.md` written.

---

## PHASE01 — Shared PEM internals + ML-DSA PEM service

**Status:** TODO
**Branch:** `feature/feature-5413-phase01-mldsa-pem`

### Scope

**In scope**

| File | Change |
|---|---|
| `src/Enigma.Core/Internal/PemEnvelope.cs` | **new** — the single shared PEM/PBES2 implementation |
| `src/Enigma.Core/Asymmetric/Pqc/MLParameterSets.cs` | **new** — internal two-way parameter-set mapping for both families |
| `src/Enigma.Core/Asymmetric/Pqc/MLPrivateKeyPemFormat.cs` | **new** — public enum |
| `src/Enigma.Core/Asymmetric/Pqc/IMLDsaPemService.cs` | **new** |
| `src/Enigma.Core/Asymmetric/Pqc/MLDsaPemService.cs` | **new** |
| `src/Enigma.Core/Asymmetric/Pqc/IMLDsaPemServiceFactory.cs` | **new** |
| `src/Enigma.Core/Asymmetric/Pqc/MLDsaPemServiceFactory.cs` | **new** |
| `src/Enigma.Core/Asymmetric/Pqc/MLDsaServiceFactory.cs` | re-point its private mapping at `MLParameterSets` (decision 6) |
| `tests/Enigma.Core.UnitTests/Pqc/MLDsaPemServiceTests.cs` | **new** — round-trips, formats, OID recovery, labels |
| `tests/Enigma.Core.UnitTests/Pqc/MLDsaPemErrorTests.cs` | **new** — nulls, malformed, wrong-type, password paths |
| `tests/Enigma.Core.UnitTests/Pqc/MLDsaPemServiceFactoryTests.cs` | **new** |
| `docs/guides/pqc.md` | add the ML-DSA PEM section |

**Out of scope**
- `IMLDsaService` / `IMLKemService` and their implementations — signatures and behaviour untouched.
- `src/Enigma.Core/Asymmetric/PublicKey/PemUtils.cs` — **not touched in this item** (decision 3).
- Anything ML-KEM — PHASE02.
- Key-handle types for PQC. `byte[]` stays canonical: reconstruction costs 0.61 ms (ML-DSA) /
  0.006 ms (ML-KEM) against 1.04 ms / 0.35 ms operations, so the RSA caching argument does not
  transfer.
- Any cross-module `IPemService` spanning RSA + PQC.

### Design / approach

1. **`Enigma.Core.Internal.PemEnvelope`** — `internal static class`, the only place any of this
   exists:

   ```csharp
   internal const string PublicKeyLabel           = "PUBLIC KEY";
   internal const string PrivateKeyLabel          = "PRIVATE KEY";
   internal const string EncryptedPrivateKeyLabel = "ENCRYPTED PRIVATE KEY";
   internal const int    Pbkdf2IterationCount     = 600_000;   // OWASP, PBKDF2-HMAC-SHA256
   private  const int    SaltSizeBytes            = 16;

   internal static string WritePem(string label, byte[] der);
   internal static string ReadPemLabel(string pem, string paramName);
   internal static byte[] ReadPemContent(string pem, string paramName);

   internal static string WritePublicKeyPem(AsymmetricKeyParameter publicKey);
   internal static string WritePrivateKeyPem(PrivateKeyInfo keyInfo, char[]? password);
   internal static string WritePrivateKeyPem(AsymmetricKeyParameter privateKey, char[]? password);

   internal static AsymmetricKeyParameter ReadPublicKey(string pem, string paramName);
   internal static AsymmetricKeyParameter ReadPrivateKey(string pem, char[]? password, string paramName);
   ```

   - The `PrivateKeyInfo` overload exists because PQC must call `WithPreferredFormat` *before*
     `PrivateKeyInfoFactory.CreatePrivateKeyInfo`; RSA uses the `AsymmetricKeyParameter` overload.
   - Public write: `Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(key)`
     → `.GetDerEncoded()` → label `PUBLIC KEY`. (Note: `SubjectPublicKeyInfoFactory` is in
     `Org.BouncyCastle.X509`, **not** `…Pkcs`.)
   - Private write, no password: `PrivateKeyInfoFactory.CreatePrivateKeyInfo(key)` → `.GetDerEncoded()`
     → label `PRIVATE KEY`.
   - Private write, with password: 16 random bytes from `SecureRandom`, then
     `EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(NistObjectIdentifiers.IdAes256Cbc,
     PkcsObjectIdentifiers.IdHmacWithSha256, password, salt, Pbkdf2IterationCount, secureRandom,
     privateKeyInfo)` → `.GetDerEncoded()` → label `ENCRYPTED PRIVATE KEY`. The caller's password
     array is used as-is and never cleared.
   - **Read dispatch** (decision 5): read the envelope once via
     `Org.BouncyCastle.Utilities.IO.Pem.PemReader.ReadPemObject()` to get `.Type`.
     - `ENCRYPTED PRIVATE KEY` → if `password is null`, throw `CryptographicException` **before**
       touching BouncyCastle; else `EncryptedPrivateKeyInfo.GetInstance(content)` →
       `PrivateKeyInfoFactory.CreatePrivateKeyInfo(password, epki)` → `PrivateKeyFactory.CreateKey`.
     - anything else → fresh `StringReader` → `Org.BouncyCastle.OpenSsl.PemReader` (with an
       `IPasswordFinder` when a password was supplied) → `ReadObject()`.
   - **`ReadObject()` returns `object`, and for the traditional-OpenSSL RSA form it returns an
     `AsymmetricCipherKeyPair`, not an `AsymmetricKeyParameter`.** Both readers must unwrap it before
     the type check, exactly as `PemUtils.cs:45-50` and `:87-92` do today:
     - `ReadPrivateKey`: `AsymmetricCipherKeyPair pair => pair.Private`, then
       `AsymmetricKeyParameter { IsPrivate: true } key => key`, else `ArgumentException`.
     - `ReadPublicKey`: `AsymmetricKeyParameter { IsPrivate: false } key => key`, then
       `AsymmetricCipherKeyPair pair => pair.Public`, else `ArgumentException`.

     Preserve both the arm ordering and the observable behaviour, so FEATURE-6852-PHASE01 can adopt
     `PemEnvelope` without changing it. This branch is invisible to PQC — ML-DSA/ML-KEM PEMs never
     take it — which is exactly why it is easy to omit and is called out here.
   - **Alias the two `PemReader` types** — `Org.BouncyCastle.OpenSsl.PemReader` and
     `Org.BouncyCastle.Utilities.IO.Pem.PemReader` are both in scope and the unqualified name is
     ambiguous. Follow the existing house style in `PemUtils.cs:9` (a `using X = …;` alias with a
     comment explaining why).
   - **One exception-mapping helper** implementing the four ordered branches specified in
     *Exception contract* above; port the `IPasswordFinder` adapter from
     `PemUtils.CharArrayPasswordFinder` (it must keep cloning, because the PEM reader may clear the
     array it receives).
   - **Verification of the RSA-specific paths is deferred to FEATURE-6852-PHASE01.** The unwrap in
     the previous bullet and branches 1 and 4 of the exception mapping are only reachable through an
     RSA PEM, and this phase ships no public RSA path that uses `PemEnvelope` — with no
     `InternalsVisibleTo`, they cannot be asserted here. They are covered there by that phase's
     acceptance criteria 3, 6 and 11 (all three private-key forms; wrong/missing password on legacy
     **and** PBES2; the re-based `DEK-Info` characterization test). **Write them anyway, to this
     specification** — omitting them leaves FEATURE-6852-PHASE01 unable to meet its criteria without
     re-opening `PemEnvelope`, which that phase declares out of scope.

2. **`MLParameterSets`** — `internal static class` in `Enigma.Core.Asymmetric.Pqc`:
   `ToBcParameters(MLDsaParameterSet)`, `FromBcParameters(MLDsaParameters)` and the ML-KEM pair.
   Undefined enum input → `ArgumentOutOfRangeException` (preserving today's behaviour in
   `MLDsaServiceFactory.ToBcParameters`). A BouncyCastle parameter object the library does not expose
   — e.g. `ml_dsa_44_with_sha512` — maps to `ArgumentException` on read, never to a wrong enum value.
   Re-point `MLDsaServiceFactory` at it; `MLKemServiceFactory` follows in PHASE02.

3. **`MLDsaPemService`** — `public sealed class`, parameterless public constructor (the factory adds
   nothing to construct), implementing the contract above:
   - `GenerateKeyPairPem` — run `MLDsaKeyPairGenerator` as `MLDsaService.GenerateKeyPair` does, then
     `((MLDsaPrivateKeyParameters)pair.Private).WithPreferredFormat(<mapped format>)` →
     `PrivateKeyInfoFactory.CreatePrivateKeyInfo` → `PemEnvelope.WritePrivateKeyPem(pki, password)`;
     public half via `PemEnvelope.WritePublicKeyPem`.
   - `ToPrivateKeyPem` — `MLDsaPrivateKeyParameters.FromEncoding(bcParams, privateKey)` →
     `WithPreferredFormat(EncodingOnly)` → `CreatePrivateKeyInfo` → write. Applying `EncodingOnly`
     explicitly is required: a rebuilt key's *default* is already `EncodingOnly`, but pinning it
     makes the intent explicit and immune to an upstream default change.
   - `ToPublicKeyPem` — `MLDsaPublicKeyParameters.FromEncoding(bcParams, publicKey)` → write.
   - `FromPrivateKeyPem` — `PemEnvelope.ReadPrivateKey` → require `MLDsaPrivateKeyParameters` (a
     public key, an ML-KEM key or an RSA key here → `ArgumentException`) → `(GetEncoded(),
     MLParameterSets.FromBcParameters(key.Parameters))`.
   - `FromPublicKeyPem` — symmetric, requiring `MLDsaPublicKeyParameters`.
   - `MLPrivateKeyPemFormat` → BC `Format` mapping: `Seed`→`SeedOnly`,
     `ExpandedKey`→`EncodingOnly`, `SeedAndExpandedKey`→`SeedAndEncoding`; undefined →
     `ArgumentOutOfRangeException`.

4. **XML docs** on every public type and member (`GenerateDocumentationFile=true`). The enum's
   `Seed` member documents the size difference (132 vs 5642 vs 5692 chars for ML-DSA-65) and that
   `Seed` is the library's default, **not** BouncyCastle's. `ToPrivateKeyPem` documents that it always
   emits the expanded encoding and points at `GenerateKeyPairPem` for seed-format output.

5. **`docs/guides/pqc.md`** — add an "ML-DSA key PEM" section in the guide's established shape
   (supported formats → key types → copy-pasteable samples), every snippet targeting the real API.

### Acceptance criteria

1. `Enigma.Core.Internal.PemEnvelope` exists, is `internal`, and is the **only** place in the assembly
   that names `EncryptedPrivateKeyInfoFactory` or holds an iteration-count constant
   (`Pbkdf2IterationCount == 600_000`), and the only **new** implementation of the BouncyCastle PEM
   exception mapping. `PemUtils` deliberately keeps its own mapping until FEATURE-6852-PHASE01
   re-points it (decision 3); **assembly-wide** uniqueness of the exception mapping is asserted there
   (FEATURE-6852-PHASE01 acceptance criterion 10), not here.
2. `PemEnvelope`'s exception-mapping helper has the four branches specified in *Exception contract*,
   in that order, and `PemEnvelope`'s two readers unwrap `AsymmetricCipherKeyPair` as specified —
   both verified **by inspection** in this phase (no `InternalsVisibleTo`; they are asserted
   behaviourally in FEATURE-6852-PHASE01).
3. The public surface added is exactly: `MLPrivateKeyPemFormat`, `IMLDsaPemService`,
   `MLDsaPemService`, `IMLDsaPemServiceFactory`, `MLDsaPemServiceFactory` — signatures as specified,
   XML-documented, factory parameterless and `new`-constructible.
4. `ToPrivateKeyPem` has **no** `format` parameter.
5. Round-trip, `[Theory]` over all three parameter sets × all three `MLPrivateKeyPemFormat` values:
   `GenerateKeyPairPem` → `FromPrivateKeyPem` → bytes equal the expanded encoding and are accepted by
   `IMLDsaService.Sign`, whose signature `Verify`s against the public key from `FromPublicKeyPem`.
6. Round-trip over all three parameter sets: `GenerateKeyPair()` → `ToPrivateKeyPem` →
   `FromPrivateKeyPem` returns **byte-identical** private-key bytes; same for `ToPublicKeyPem` /
   `FromPublicKeyPem`.
7. `FromPublicKeyPem` / `FromPrivateKeyPem` return the **correct parameter set** for all three sets
   (OID recovery), including from an encrypted private-key PEM.
8. Encrypted round-trip with a password succeeds; wrong password → `CryptographicException`;
   encrypted PEM read with `password: null` → `CryptographicException`; the caller's password array
   is **not** cleared by any call.
9. Emitted labels are exactly `-----BEGIN PUBLIC KEY-----`, `-----BEGIN PRIVATE KEY-----`,
   `-----BEGIN ENCRYPTED PRIVATE KEY-----`; an encrypted PEM contains **no** `Proc-Type` or
   `DEK-Info` header.
10. A `Seed`-format ML-DSA-65 private-key PEM is **under 200 characters**, and an `ExpandedKey` one is
    over 5000 — pinning that the format argument is actually honoured.
11. `FromPublicKeyPem` on a private-key PEM, `FromPrivateKeyPem` on a public-key PEM, an ML-KEM PEM,
    an RSA PEM, a truncated PEM, an empty/whitespace string, and non-PEM text all → `ArgumentException`
    carrying the right `paramName`.
12. Every `null` argument → `ArgumentNullException`; every undefined enum value →
    `ArgumentOutOfRangeException`.
13. **No BouncyCastle exception type escapes any public method** — asserted for the wrong-password,
    malformed-PEM and wrong-length-key paths.
14. `Pqc/PqcBouncyCastleIsolationTests` and `Api/BouncyCastleIsolationTests` are green with the new
    types exported.
15. `MLDsaServiceFactory` behaviour is unchanged (its existing tests pass untouched) despite being
    re-pointed at `MLParameterSets`, **and the duplication is genuinely gone**: `MLDsaServiceFactory`
    contains no `MLDsaParameterSet` → `MLDsaParameters` switch of its own, and
    `MLDsaParameters.ml_dsa_` appears in exactly one product file,
    `src/Enigma.Core/Asymmetric/Pqc/MLParameterSets.cs`.
16. `docs/guides/pqc.md` documents the ML-DSA PEM API and every snippet compiles against it.
17. `docs/done/FEATURE-5413-PHASE01.md` records the seed blocker and its resolution, the corrected
    `DefaultFormat` fact, and the build/test counts.

---

## PHASE02 — ML-KEM PEM service

**Status:** TODO
**Branch:** `feature/feature-5413-phase02-mlkem-pem`

### Scope

**In scope**

| File | Change |
|---|---|
| `src/Enigma.Core/Asymmetric/Pqc/IMLKemPemService.cs` | **new** |
| `src/Enigma.Core/Asymmetric/Pqc/MLKemPemService.cs` | **new** |
| `src/Enigma.Core/Asymmetric/Pqc/IMLKemPemServiceFactory.cs` | **new** |
| `src/Enigma.Core/Asymmetric/Pqc/MLKemPemServiceFactory.cs` | **new** |
| `src/Enigma.Core/Asymmetric/Pqc/MLKemServiceFactory.cs` | re-point its private mapping at `MLParameterSets` |
| `tests/Enigma.Core.UnitTests/Pqc/MLKemPemServiceTests.cs` | **new** |
| `tests/Enigma.Core.UnitTests/Pqc/MLKemPemErrorTests.cs` | **new** |
| `tests/Enigma.Core.UnitTests/Pqc/MLKemPemServiceFactoryTests.cs` | **new** |
| `docs/guides/pqc.md` | add the ML-KEM PEM section |
| `docs/guides/README.md` | only if the PQC index entry's description changes |

**Out of scope**
- `PemEnvelope` — created and settled in PHASE01. If a change is genuinely required here, it must be
  additive and recorded as a deviation in the completion doc.
- Everything listed out of scope in PHASE01.

### Design / approach

Mirror PHASE01 exactly, substituting `MLKemParameterSet` / `MLKemParameters` /
`MLKemPublicKeyParameters` / `MLKemPrivateKeyParameters` / `MLKemKeyPairGenerator` /
`MLKemKeyGenerationParameters`, and reusing `PemEnvelope`, `MLParameterSets` and
`MLPrivateKeyPemFormat` unchanged. The ML-KEM seed is 64 bytes (ML-DSA's is 32); `SeedOnly` PKCS#8
DER is 86 bytes for ML-KEM-768. There is no `deterministic` notion in ML-KEM.

Cross-use test differs by family: PEM → bytes → `IMLKemService.Decapsulate` must yield the shared
secret produced by `Encapsulate` against the public key recovered from `FromPublicKeyPem`.

### Acceptance criteria

1. The public surface added is exactly `IMLKemPemService`, `MLKemPemService`,
   `IMLKemPemServiceFactory`, `MLKemPemServiceFactory`, mirroring the ML-DSA contract with
   `MLKemParameterSet`; `MLPrivateKeyPemFormat` is **reused**, not duplicated.
2. PHASE01 acceptance criteria 5-14 hold for ML-KEM over all three parameter sets, with the
   `Encapsulate`/`Decapsulate` cross-use replacing sign/verify: the shared secret recovered through
   a PEM round-trip equals the one from `Encapsulate`.
3. A `Seed`-format ML-KEM-768 private-key PEM is **under 250 characters**; an `ExpandedKey` one is
   over 2000.
4. `MLKemServiceFactory` behaviour is unchanged (its existing tests pass untouched), and it contains
   no mapping switch of its own: `MLKemParameters.ml_kem_` appears only in `MLParameterSets.cs`.
5. `PemEnvelope` gained no ML-KEM-specific branch — the shared code is genuinely family-agnostic.
6. `docs/guides/pqc.md` covers both families; `docs/guides/README.md` updated only if its PQC entry
   needed it.
7. `docs/done/FEATURE-5413-PHASE02.md` written; the item's roadmap row flips to `DONE` alongside it.

---

## Out of scope / suggestions recorded (not planned here)

- **`RSAParameters` import/export** on `RsaKey` — verified netstandard2.0-safe and a good future
  escape hatch, but deliberately out of scope for this batch. Worth its own FEATURE.
- **ML-DSA / ML-KEM support in `Certificates/`** — separate future work; no PQC certificate,
  CSR or PKCS#12 support is added here.
- **SLH-DSA (FIPS 205)** — still available in BouncyCastle 2.7.0 and still declined (recorded in
  `docs/plan/FEATURE-797D.md`).
