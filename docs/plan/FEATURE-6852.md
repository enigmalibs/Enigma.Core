# FEATURE-6852 — `RsaKey` handle for the PublicKey module (BREAKING)

**Status:** TODO (multi-phase)
**Type:** FEATURE (multi-phase)
**Branch (per phase, at build time):** `feature/feature-6852-phaseNN-<slug>` — one branch per phase, cut from current `HEAD`.

## Objective

Replace the PEM-string surface of `IPublicKeyService` with a parsed **`RsaKey` handle**, so a key is
parsed and validated **once** instead of on every call, and a passphrase is supplied **once**, at
import, instead of on every private-key operation.

This is a **deliberate breaking change** shipping in a new MAJOR version. Every PEM-string overload
is deleted outright — **nothing is marked `[Obsolete]`**, no compatibility shims, no transitional
overloads, no "legacy" namespace.

**Depends on FEATURE-5413-PHASE01**, which creates `Enigma.Core.Internal.PemEnvelope`. Build that
first.

## Why (settled — do not re-litigate)

Every method in `PublicKeyService.cs` re-parses its PEM on every call. Measured, RSA-2048, Release,
200 iterations:

```
PemReader, unencrypted PKCS#8 PEM :  23.1 ms
PemReader, encrypted PEM + pwd    :  38.6 ms
new RsaPrivateCrtKeyParameters    :  22.3 ms   <- BouncyCastle CRT key validation, the real cost
RSA-2048 SHA256 sign, key cached  :   7.1 ms
```

84 % of a `Sign(data, encryptedPem, password)` call is key reconstruction — a ~6x penalty. The cost
is BouncyCastle's CRT key **validation**, not PEM decoding, so changing the wire format to `byte[]`
or to a components struct would not fix it. Only caching the constructed key fixes it.

## Context & constraints

- Ships in **2.0.0** with FEATURE-5413 and FEATURE-57A9 (release: FEATURE-19C7).
- All the shared constraints of FEATURE-5413 apply: BouncyCastle isolation, three TFMs, zero
  warnings, CPM, xUnit v3 / MTP, `.gitattributes` `eol=lf`.
- `PemUtils` **stays `internal` and keeps its four current signatures for the whole of this item** —
  `Certificates/X509CertificateService.cs` calls it at lines 36, 57, 89, 183 and 199 and must keep
  compiling and behaving identically. It is deleted in FEATURE-57A9, not here.
- `RsaSignatureAlgorithm` lives in the root `Enigma.Core` namespace (not in `Asymmetric.PublicKey`);
  `PublicKeyBouncyCastleIsolationTests` appends it explicitly to the type list it walks.
- **No `InternalsVisibleTo` anywhere in the solution** — `PemEnvelope`, `PemUtils` and `RsaKey`'s
  internal member cannot be tested directly; every assertion goes through the public surface.
  This phase is therefore the **first** place `PemEnvelope`'s RSA-specific paths become observable:
  acceptance criteria 3, 6 and 11 below are what verifies the `AsymmetricCipherKeyPair` unwrap and
  exception-mapping branches 1 and 4 that FEATURE-5413-PHASE01 specifies but cannot assert.

## Planning-time evidence (measured against BouncyCastle 2.7.0 — do not re-derive)

| Probe | Result |
|---|---|
| `OpenSsl.PemReader` + `IPasswordFinder` on a **PBES2** `ENCRYPTED PRIVATE KEY` (RSA) | returns `RsaPrivateCrtKeyParameters` — **it works**; the brief's open question is settled, and no manual fallback is needed for RSA |
| Same PEM, **no** password | `Org.BouncyCastle.OpenSsl.PemException: problem creating ENCRYPTED private key` |
| Same PEM, **wrong** password | the same `PemException` — the two cases are indistinguishable at the BouncyCastle boundary |
| Existing repo fixture `tests/…/PublicKey/pk_key1.pem` | is **already** a PBES2 `-----BEGIN ENCRYPTED PRIVATE KEY-----` file (passphrase `test1234`) that today's `PemUtils.ParsePrivateKey` reads successfully — live proof the PBES2 read path already works |
| Manual EPKI decrypt path | also works for RSA; kept for PQC, shared via `PemEnvelope` |
| 600 000-iteration PBES2 decrypt | **605 ms** (net10.0, Release, this machine) |

Current `PemUtils` already maps `PemException` → `CryptographicException`, so both the
missing-password and wrong-password cases already satisfy the exception contract.

## Design decisions (from the interview)

1. **The handle owns PEM; the service owns operations.** This matches the BCL idiom
   (`RSA.ExportRSAPrivateKeyPem`, `ExportEncryptedPkcs8PrivateKeyPem`, `RSA.ImportFromPem`).
2. **No `IDisposable` on `RsaKey`.** BouncyCastle stores RSA private components as `BigInteger`,
   which cannot be zeroized, so `Dispose` would be security theatre. The XML docs **must** state that
   private key material lives in managed memory and cannot be wiped.
3. **Additive phase first.** PHASE01 adds `RsaKey` and switches the PEM format with the whole suite
   staying green; PHASE02 makes the breaking cut. This keeps a working commit between the two halves
   and lets the legacy-format fixture be generated while the old writer still exists.
4. **`GenerateRsaKeyPair` → `GenerateRsaKey`** is a rename, not just a retype: one `RsaKey` holds both
   halves, so "KeyPair" no longer describes the return value.
5. **The `char[]? password` parameter disappears from `DecryptPkcs1`, `DecryptOaep` and `Sign`.**
   The passphrase is supplied exactly once, at `RsaKey.ImportPrivateKeyPem`. Do not reintroduce it
   anywhere on the service — that is a primary goal of this item.
6. **Public-only handle on a private operation → `ArgumentException` with `paramName: "key"`**; it is
   a bad argument to a service method, and it preserves today's observable type (a public-key PEM
   passed to `Sign` currently reaches `PemUtils.ParsePrivateKey` and throws `ArgumentException`).
   `RsaKey.ExportPrivateKeyPem` on a public-only handle throws **`InvalidOperationException`**, because
   there the fault is the handle's own state, not a caller argument.
7. **A handle holding a private key is accepted by the public operations** (`Verify`, `EncryptPkcs1`,
   `EncryptOaep`, `ExportPublicKeyPem`) — forced, not optional: `GenerateRsaKey()` returns one object
   carrying both halves, so refusing it would break the primary flow. The public half is derived from
   the CRT components.
8. **Encrypted-PEM format change.** Writing moves from traditional-OpenSSL
   (`RSA PRIVATE KEY` + `Proc-Type: 4,ENCRYPTED` + `DEK-Info: AES-256-CBC`, whose key derivation is
   OpenSSL's legacy `EVP_BytesToKey` — MD5, single iteration) to **PBES2** via `PemEnvelope`.
   Reading must accept **all three** forms so existing user key files keep working. The *API* breaks;
   the *file format* must not.

## Public surface after this item

```csharp
namespace Enigma.Core.Asymmetric.PublicKey;

public sealed class RsaKey
{
    public int  KeySizeBits   { get; }
    public bool HasPrivateKey { get; }

    public static RsaKey ImportPublicKeyPem(string pem);
    public static RsaKey ImportPrivateKeyPem(string pem, char[]? password = null);

    public string ExportPublicKeyPem();
    public string ExportPrivateKeyPem(char[]? password = null);
}

public interface IPublicKeyService   // exactly seven members, nothing else
{
    RsaKey GenerateRsaKey(int keySizeBits = 2048);

    byte[] EncryptPkcs1(byte[] data, RsaKey key);
    byte[] DecryptPkcs1(byte[] ciphertext, RsaKey key);
    byte[] EncryptOaep(byte[] data, RsaKey key, RsaOaepHash hash = RsaOaepHash.Sha256);
    byte[] DecryptOaep(byte[] ciphertext, RsaKey key, RsaOaepHash hash = RsaOaepHash.Sha256);
    byte[] Sign(byte[] data, RsaKey key, RsaSignatureAlgorithm algorithm = RsaSignatureAlgorithm.Sha256WithRsa);
    bool   Verify(byte[] data, byte[] signature, RsaKey key, RsaSignatureAlgorithm algorithm = RsaSignatureAlgorithm.Sha256WithRsa);
}
```

Deleted members, for the record:

| Removed | Replacement |
|---|---|
| `(string, string) GenerateRsaKeyPair(int, char[]?)` | `RsaKey GenerateRsaKey(int)` + `RsaKey.ExportPublicKeyPem()` / `ExportPrivateKeyPem(char[]?)` |
| `EncryptPkcs1(byte[], string)` | `EncryptPkcs1(byte[], RsaKey)` |
| `DecryptPkcs1(byte[], string, char[]?)` | `DecryptPkcs1(byte[], RsaKey)` |
| `EncryptOaep(byte[], string, RsaOaepHash)` | `EncryptOaep(byte[], RsaKey, RsaOaepHash)` |
| `DecryptOaep(byte[], string, RsaOaepHash, char[]?)` | `DecryptOaep(byte[], RsaKey, RsaOaepHash)` |
| `Sign(byte[], string, RsaSignatureAlgorithm, char[]?)` | `Sign(byte[], RsaKey, RsaSignatureAlgorithm)` |
| `Verify(byte[], byte[], string, RsaSignatureAlgorithm)` | `Verify(byte[], byte[], RsaKey, RsaSignatureAlgorithm)` |

## Definition of Done (applies to every phase)

1. `dotnet build Enigma.Core.slnx -c Release` succeeds with **zero warnings** across all three TFMs.
2. `dotnet test --solution Enigma.Core.slnx -c Release` passes in full on **net8.0 and net10.0**.
3. Every acceptance criterion of the phase is met.
4. Roadmap row + this plan file's phase status updated.
5. `docs/done/FEATURE-6852-PHASENN.md` written.

---

## PHASE01 — `RsaKey` + PBES2 write / three-format read (additive)

**Status:** TODO
**Branch:** `feature/feature-6852-phase01-rsakey`

Nothing is removed in this phase. The whole existing suite stays green apart from two assertions that
pin the **old write format** and therefore change deliberately.

### Scope

**In scope**

| File | Change |
|---|---|
| `src/Enigma.Core/Asymmetric/PublicKey/RsaKey.cs` | **new** |
| `src/Enigma.Core/Asymmetric/PublicKey/PemUtils.cs` | re-pointed at `PemEnvelope`; encrypted write becomes PBES2; read dispatches over all three forms. **Signatures unchanged** |
| `tests/Enigma.Core.UnitTests/PublicKey/pk_key_legacy_encrypted.pem` | **new fixture** — traditional-OpenSSL encrypted RSA-2048 key, generated **before** the writer flips |
| `tests/Enigma.Core.UnitTests/PublicKey/RsaKeyTests.cs` | **new** — the handle's own tests |
| `tests/Enigma.Core.UnitTests/PublicKey/RsaKeyGenerationTests.cs` | one assertion re-based on PBES2 |
| `tests/Enigma.Core.UnitTests/PublicKey/RsaArgumentValidationTests.cs` | the `DEK-Info` characterization test re-based on the new fixture |

**Out of scope**
- Any change to `IPublicKeyService` or `PublicKeyService` — PHASE02.
- Any change to `Certificates/` product code or tests.
- `PemEnvelope` itself (owned by FEATURE-5413-PHASE01); any change here must be additive and recorded
  as a deviation.

### Design / approach

1. **Generate the legacy fixture FIRST, before touching the writer.** With the current code, produce
   an RSA-2048 traditional-OpenSSL encrypted PEM (`GenerateRsaKeyPair(2048, password)`), and commit it
   as `tests/Enigma.Core.UnitTests/PublicKey/pk_key_legacy_encrypted.pem` alongside the existing
   `pk_key1.pem` / `pub_key1.pem` (fixtures live flat in their category folder). Record its passphrase
   in the test that reads it. This file is the only remaining producer of the old format once the
   writer flips — if it is not captured first, the backward-compatibility guarantee becomes untestable.
   **No `.csproj` change is required:** the existing `<None Update="**/*.pem">` glob at
   `tests/Enigma.Core.UnitTests/Enigma.Core.UnitTests.csproj:29-31` copies every `.pem` under the test
   project to the output directory with `PreserveNewest` — that is how `pk_key1.pem` reaches
   `Path.Combine("PublicKey", …)` in `RsaServiceTests.cs:16-17`. Dropping the file in
   `tests/Enigma.Core.UnitTests/PublicKey/` is sufficient.

2. **`RsaKey`** — `public sealed class` in `Enigma.Core.Asymmetric.PublicKey`:
   - Private field holding the parsed `AsymmetricKeyParameter`. Exposed to `PublicKeyService` through
     a plain **`internal`** member (e.g. `internal AsymmetricKeyParameter BcKey { get; }`) — never
     `public`, and never `protected internal`: the isolation guard treats `IsFamilyOrAssembly` as
     exposed, so `protected internal` would fail the build's guard test.
   - Private constructor; instances come only from the two static importers and (in PHASE02)
     `GenerateRsaKey`. Add an `internal` constructor or factory for `PublicKeyService` to use.
   - `KeySizeBits` — the modulus bit length, from `RsaKeyParameters.Modulus.BitLength`.
   - `HasPrivateKey` — `BcKey.IsPrivate`.
   - `ImportPublicKeyPem` / `ImportPrivateKeyPem` — delegate to `PemEnvelope.ReadPublicKey` /
     `ReadPrivateKey`, then require the result to be an RSA key of the right kind; anything else
     (a PQC key, a public key where a private one is required) → `ArgumentException(paramName: "pem")`.
   - `ExportPublicKeyPem()` — works on either kind. From a private handle, derive the public half from
     the CRT components (`new RsaKeyParameters(false, modulus, publicExponent)`). A private key that
     is **not** `RsaPrivateCrtKeyParameters` (no public exponent available) → `InvalidOperationException`
     with a message saying the public half cannot be derived.
   - `ExportPrivateKeyPem(char[]? password = null)` — `InvalidOperationException` on a public-only
     handle; otherwise `PemEnvelope.WritePrivateKeyPem(BcKey, password)`, i.e. unencrypted PKCS#8
     `PRIVATE KEY` when `password is null`, PBES2 `ENCRYPTED PRIVATE KEY` otherwise.
   - **XML docs must state**: the type is immutable and safe for concurrent use; private key material
     lives in managed memory as `BigInteger` and **cannot be wiped**, so the type is deliberately not
     `IDisposable`; the caller owns its password array's lifetime and the library never clears it.

3. **`PemUtils` re-pointed at `PemEnvelope`.** All four members keep their exact current signatures
   and their `internal` visibility; each becomes a thin delegate:
   - `WritePublicKeyPem` → `PemEnvelope.WritePublicKeyPem`.
   - `WritePrivateKeyPem` → `PemEnvelope.WritePrivateKeyPem` — **this is the format change**:
     encrypted output becomes PBES2 (`ENCRYPTED PRIVATE KEY`, PBKDF2-HMAC-SHA256, AES-256-CBC,
     16-byte salt, 600 000 iterations). The unencrypted path is unchanged (PKCS#8 `PRIVATE KEY`), so
     `X509CertificateService.cs:199`, which writes with `password: null`, is unaffected.
   - `ParsePublicKey` / `ParsePrivateKey` → `PemEnvelope.ReadPublicKey` / `ReadPrivateKey`, which
     accept **all three** private-key forms: unencrypted PKCS#8, traditional-OpenSSL
     (`Proc-Type`/`DEK-Info`), and PBES2.
   - After this, `PemUtils` contains **no** cipher constant, no `PemWriter`/`PemReader` use of its
     own, and no exception mapping of its own — those live only in `PemEnvelope`.

4. **The two assertions that must change** (deliberate, not weakening):
   - `RsaKeyGenerationTests.GenerateRsaKeyPair_WithPassword_ProducesAes256CbcEncryptedPrivateKeyPem`
     currently asserts `BEGIN RSA PRIVATE KEY` + `Proc-Type: 4,ENCRYPTED` + `DEK-Info: AES-256-CBC`.
     Re-base it on PBES2: `BEGIN ENCRYPTED PRIVATE KEY`, **no** `Proc-Type`, **no** `DEK-Info`, and
     rename it accordingly.
   - `RsaArgumentValidationTests.PrivateKeyOperation_UnsupportedDekAlgorithm_ThrowsArgumentException`
     (added by FEATURE-797D-PHASE01) builds its input by string-replacing `DEK-Info: AES-256-CBC` in
     freshly generated output, which no longer exists. Re-base it on the committed legacy fixture so
     it keeps pinning the same behaviour: an unrecognised DEK cipher is a structural PEM defect →
     `ArgumentException`.

5. **Everything else stays green untouched** — in particular `RsaServiceTests` (which reads the
   PBES2 fixture `pk_key1.pem`, already supported), all `Certificates` tests (their fixture's
   encrypted PEM simply becomes PBES2, which the read path accepts), and every isolation guard.

6. **Budget the cost.** Each PBES2 read or write costs ~605 ms. `Certificates/EncryptedKeyPemTests`
   parses its encrypted fixture about seven times, so expect roughly +5 s on the suite. If the total
   run time becomes a problem, record it — do **not** lower the iteration count, which is a shared
   security constant.

### Acceptance criteria

1. `pk_key_legacy_encrypted.pem` is committed, is in the **traditional-OpenSSL** format
   (`-----BEGIN RSA PRIVATE KEY-----` + `Proc-Type: 4,ENCRYPTED` + `DEK-Info: AES-256-CBC`), and is
   copied to the test output directory.
2. `RsaKey` exists with exactly the six specified public members, is `sealed`, does **not** implement
   `IDisposable`, exposes its BouncyCastle key only through a plain `internal` member, and is fully
   XML-documented including the "cannot be wiped" and "immutable / thread-safe" statements.
3. `RsaKey.ImportPrivateKeyPem` imports all three forms: the unencrypted PKCS#8 PEM, the committed
   **legacy traditional-OpenSSL** fixture with its passphrase, and a PBES2 PEM (including the existing
   `pk_key1.pem` with `test1234`).
4. Export → re-import round trip: unencrypted and encrypted, both yielding a handle that produces the
   same signature/decryption results as the original.
5. `ExportPrivateKeyPem(password)` emits `-----BEGIN ENCRYPTED PRIVATE KEY-----` with no `Proc-Type`
   and no `DEK-Info`; `ExportPrivateKeyPem()` emits `-----BEGIN PRIVATE KEY-----`.
6. Wrong password → `CryptographicException`; missing password on an encrypted PEM →
   `CryptographicException`; both verified against **the legacy format and PBES2**.
7. `KeySizeBits` is 2048 and 3072 for keys of those sizes; `HasPrivateKey` is `true` for an imported
   private key and `false` for an imported public key.
8. `ExportPrivateKeyPem` on a public-only handle → `InvalidOperationException`;
   `ExportPublicKeyPem` on a **private** handle succeeds and produces a PEM that verifies signatures
   made with that handle.
9. `null` PEM → `ArgumentNullException`; empty/whitespace/malformed/wrong-type PEM →
   `ArgumentException` with `paramName: "pem"`. No BouncyCastle exception escapes.
10. `PemUtils` keeps its four signatures and its `internal` visibility, and now contains no
    encryption constant, no direct PEM reader/writer use and no exception mapping of its own.
11. The whole existing suite passes with **only** the two assertion changes listed in design step 4;
    no other test is modified, and no assertion is weakened to make anything compile.
12. All `Certificates` tests pass **unmodified** in this phase.
13. `Api/BouncyCastleIsolationTests` and `PublicKey/PublicKeyBouncyCastleIsolationTests` are green
    with `RsaKey` exported.
14. `docs/done/FEATURE-6852-PHASE01.md` records the format change, the fixture-before-flip ordering,
    the two re-based assertions, the measured suite-time delta, and build/test counts.

---

## PHASE02 — Cut the PEM-string surface (BREAKING)

**Status:** TODO
**Branch:** `feature/feature-6852-phase02-breaking-cut`

### Scope

**In scope**

| File | Change |
|---|---|
| `src/Enigma.Core/Asymmetric/PublicKey/IPublicKeyService.cs` | reduced to the seven members above |
| `src/Enigma.Core/Asymmetric/PublicKey/PublicKeyService.cs` | rewritten against `RsaKey`; **no reference to `PemUtils` remains** |
| `tests/…/PublicKey/RsaKeyFixture.cs` | holds an `RsaKey` instead of two PEM strings |
| `tests/…/PublicKey/RsaArgumentValidationTests.cs` | ported |
| `tests/…/PublicKey/RsaEncryptDecryptTests.cs` | ported |
| `tests/…/PublicKey/RsaOaepTests.cs` | ported |
| `tests/…/PublicKey/RsaServiceTests.cs` | ported (fixture PEMs → `RsaKey.ImportPrivateKeyPem`) |
| `tests/…/PublicKey/RsaSignatureAlgorithmTests.cs` | ported |
| `tests/…/PublicKey/RsaKeyGenerationTests.cs` | ported to `GenerateRsaKey` |
| `tests/…/PublicKey/PublicKeyServiceFactoryTests.cs` | check; likely unchanged |
| `tests/…/PublicKey/PublicKeyBouncyCastleIsolationTests.cs` | doc comment + asserted type list updated for `RsaKey` |
| `tests/…/Certificates/CertificateKeyFixture.cs` | **compile fix only** — 5 call sites |
| `tests/…/Certificates/Pkcs12Tests.cs` | **compile fix only** — lines 39, 49, 50 |
| `docs/guides/public-key.md` | **rewritten**, plus a migration section |
| `docs/guides/certificates.md` | minimal fix to its RSA key-generation snippets |

**Out of scope**
- `IX509CertificateService` and `X509CertificateService` — **not changed in this item** (that is
  FEATURE-57A9). `PemUtils` therefore stays `internal` with its current signatures.
- `RSAParameters` import/export — noted as a follow-up, not built.
- Any `[Obsolete]` attribute anywhere. Any PEM-string overload kept "just in case".
- The version bump and release notes — FEATURE-19C7 (this phase only *supplies* the copy).

### Design / approach

1. **`IPublicKeyService`** — delete every PEM-string overload and `GenerateRsaKeyPair`; the interface
   ends with exactly the seven members listed above and nothing else. XML docs rewritten: keys arrive
   as `RsaKey`, the passphrase is supplied once at import, and each private operation documents
   `ArgumentException` for a public-only handle.

2. **`PublicKeyService`** — every method reads `key.BcKey` and wires its cipher/signer exactly as
   today; the `PemUtils.Parse*` call at the head of each method disappears. Guard order per method:
   `ArgumentNullException` for `data`/`ciphertext`/`signature`/`key` first, then the
   private-key-required check (`ArgumentException`, `paramName: "key"`), then the operation.
   `GenerateRsaKey(int keySizeBits = 2048)` keeps today's `ArgumentException` for
   `keySizeBits <= 0` and returns a handle wrapping the generated **private** key (from which the
   public half is derivable), so a single `RsaKey` serves both directions.
   The `CryptoException` → `CryptographicException` mapping in `Transform` and `Sign` is unchanged,
   as is `ArgumentOutOfRangeException` for undefined `RsaOaepHash` / `RsaSignatureAlgorithm` values.

3. **Test port — every behavioural assertion survives.** Port, do not drop, and do not weaken an
   assertion to make a test compile. The mechanical mapping is:
   - `service.X(data, keys.PublicKeyPem)` → `service.X(data, keys.PublicKey)` where the fixture now
     exposes `RsaKey`.
   - `service.Sign(data, pem, password: p)` → `service.Sign(data, RsaKey.ImportPrivateKeyPem(pem, p))`.
   - Tests asserting `ArgumentException` for a **malformed/empty/null PEM** move to the
     `RsaKey.Import*` call site — same exception types, asserted where the PEM now enters the library.
   - `PrivateKeyOperation_WrongPassword_…` and `…_EncryptedPemWithoutPassword_…` likewise move to
     `ImportPrivateKeyPem` and keep asserting `CryptographicException`.
   - `PrivateKeyOperation_UnencryptedPemWithNullPassword_Succeeds` becomes an import with no password.
   - The `RsaOaepHash`/`RsaSignatureAlgorithm` exhaustiveness tests keep asserting
     `ArgumentOutOfRangeException` on the service.
   - **New** tests for the surface that did not exist before: a public-only handle passed to
     `Sign`/`DecryptPkcs1`/`DecryptOaep` → `ArgumentException` with `paramName: "key"`; a
     private-holding handle accepted by `Verify`/`EncryptPkcs1`/`EncryptOaep`.
   - **New** regression test for the point of the item: one `RsaKey` reused across many
     `Sign`/`Verify` calls with no re-import.

4. **Certificate test fixtures — compile fix only, at eight sites in two files.**
   - `CertificateKeyFixture.cs:21-25` — five sites: replace each `keyGen.GenerateRsaKeyPair(2048)`
     with `keyGen.GenerateRsaKey(2048).ExportPrivateKeyPem()`, and the encrypted one with
     `…ExportPrivateKeyPem(EncryptedKeyPassword)`.
   - `Pkcs12Tests.cs` — **three** sites, not one. Line 39 destructures `GenerateRsaKeyPair`, but
     lines 49 and 50 also bind to deleted string overloads (`Sign(byte[], string, …)` and
     `Verify(byte[], byte[], string, …)`), and `IX509CertificateService.ImportPkcs12` still returns
     `(string, string)` in this item, so `extractedKeyPem` stays a `string`:
     - `:39` → `var rsaKey = publicKeyService.GenerateRsaKey(2048);` plus
       `rsaKey.ExportPublicKeyPem()` / `rsaKey.ExportPrivateKeyPem()` where the tuple halves were used;
     - `:49` → `publicKeyService.Sign(data, RsaKey.ImportPrivateKeyPem(extractedKeyPem))` — the
       PKCS#12-extracted PEM is unencrypted, so no password;
     - `:50` → `publicKeyService.Verify(data, signature, rsaKey)` — a private-holding handle is
       accepted by `Verify` (design decision 7), so no separate public import is needed.

   **Every certificate assertion keeps its meaning**; the only assertion whose *text* changes is
   `Pkcs12Tests.cs:50`, where the key argument becomes a handle. No certificate product code is
   touched.

5. **`docs/guides/public-key.md` — rewritten, not patched.** Every current example uses the removed
   string API. Follow the house guide shape (supported schemes → key types → copy-pasteable samples),
   every snippet targeting the real API. Add a **Migration** section containing:
   - the seven-row before/after table above, verbatim;
   - a worked example of the `password`-on-every-call → `password`-at-import change, showing the old
     code and the new code side by side;
   - a note that the emitted encrypted-PEM format changed to PBES2 while **reading** still accepts
     traditional-OpenSSL and unencrypted PKCS#8, so existing key files keep working;
   - a note that `RsaKey` is not `IDisposable` and why.

6. **`docs/guides/certificates.md`** — its snippets call `GenerateRsaKeyPair`; fix them minimally to
   `GenerateRsaKey(...).ExportPrivateKeyPem(...)`. The guide is rewritten properly in FEATURE-57A9.

7. **Release-note copy** — produce, in `docs/done/FEATURE-6852-PHASE02.md`, ready-to-paste prose for
   FEATURE-19C7 covering: the removed members and their replacements, the passphrase-at-import change,
   the `GenerateRsaKeyPair` → `GenerateRsaKey` rename, and the encrypted-PEM write-format change with
   its read-compatibility guarantee.

### Acceptance criteria

1. `IPublicKeyService` contains **exactly** the seven specified members — verified by reflection or
   by inspection — and no member anywhere in the item carries `[Obsolete]`.
2. `PublicKeyService.cs` contains **no** reference to `PemUtils`; `grep PemUtils src/` matches only
   `PemUtils.cs` itself and `Certificates/X509CertificateService.cs`.
3. No `char[]` password parameter appears anywhere on `IPublicKeyService`.
4. `GenerateRsaKey` → `ExportPublicKeyPem`/`ExportPrivateKeyPem` → re-import → sign/verify **and**
   encrypt/decrypt succeed, for both the encrypted and unencrypted export paths.
5. A public-only handle passed to `Sign`, `DecryptPkcs1` or `DecryptOaep` → `ArgumentException` with
   `paramName: "key"`; a private-holding handle is accepted by `Verify`, `EncryptPkcs1` and
   `EncryptOaep`.
6. Every behavioural assertion from the pre-existing `PublicKey` tests is present in the rewritten
   suite — ciphertext round-trips for PKCS#1 and all four OAEP hashes, signature validity for every
   `RsaSignatureAlgorithm`, wrong-message verification returning `false`, all exception-type
   assertions, and the "caller's password array is not cleared" assertion. Nothing dropped, nothing
   weakened.
7. The fixture-file tests still pass using `pk_key1.pem` (PBES2, `test1234`), `pub_key1.pem` and
   `pk_key_legacy_encrypted.pem`.
8. All `Certificates` tests pass with **only** the mechanical compile edits in
   `CertificateKeyFixture.cs` (5 sites) and `Pkcs12Tests.cs` (3 sites); no certificate assertion's
   meaning is altered and no certificate product file is touched.
9. `Api/BouncyCastleIsolationTests` and `PublicKey/PublicKeyBouncyCastleIsolationTests` are green,
   the latter updated to assert the new surface including `RsaKey`.
10. `docs/guides/public-key.md` is rewritten with the migration section, and `certificates.md`'s RSA
    snippets compile against the new API.
11. `docs/done/FEATURE-6852-PHASE02.md` contains the ready-to-paste release-note copy for
    FEATURE-19C7, plus the usual record; the item's roadmap row flips to `DONE` alongside it.

---

## Out of scope / suggestions recorded (not planned here)

- **`RsaKey.ExportRsaParameters` / `ImportRsaParameters`** — `RSAParameters` is verified
  netstandard2.0-safe and would be a good escape hatch for interop with `System.Security.Cryptography`.
  Deliberately excluded from this batch; worth its own FEATURE.
- **A public-only projection** (e.g. `RsaKey.ExtractPublicKey()`) — not requested; a caller who needs
  one can round-trip through `ExportPublicKeyPem` / `ImportPublicKeyPem`.
- **RSA key components (p, q, n, e, d, dp, dq, qInv) are never exposed** on the public surface, by
  design.
