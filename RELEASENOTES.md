# Enigma.Core v2.0.0 Release Notes

The first MAJOR release. **RSA key material now crosses the public surface as a reusable `RsaKey`
handle instead of PEM text** — across both the public-key and the certificate modules — and a
passphrase is supplied once, where the key is parsed, rather than on every call. Alongside that
breaking change: PEM import/export for ML-DSA and ML-KEM keys, and a new Checksum module with seven
CRC variants.

Read *Breaking Changes & Migration* before upgrading. The important reassurance up front: **existing
key files keep working**. Only the API breaks, not the file formats.

## Breaking Changes & Migration

Every removed member was **deleted outright**. Nothing is marked `[Obsolete]`, and there are no
compatibility shims or transitional overloads — so there is no deprecation window, and 1.x call sites
fail to compile rather than warn. That is deliberate: a silently-still-working PEM overload would have
kept paying the per-call parsing cost this release exists to remove.

### RSA keys are now handles, not PEM strings

`IPublicKeyService` no longer accepts PEM text. A key is parsed once into an `RsaKey` handle, and that
handle is passed to every operation:

```csharp
RsaKey key = RsaKey.ImportPrivateKeyPem(pem, password);

byte[] signature = rsa.Sign(message, key);
byte[] plaintext = rsa.DecryptOaep(ciphertext, key);
```

Parsing an RSA private key costs far more than using it — BouncyCastle validates the CRT components on
construction — and the old API paid that cost on **every call**. For a 2048-bit key, roughly 84 % of a
`Sign(data, encryptedPem, password)` call was key reconstruction. Importing once removes it.

| Removed | Replacement |
|---|---|
| `(string, string) GenerateRsaKeyPair(int, char[]?)` | `RsaKey GenerateRsaKey(int)` + `RsaKey.ExportPublicKeyPem()` / `ExportPrivateKeyPem(char[]?)` |
| `EncryptPkcs1(byte[], string)` | `EncryptPkcs1(byte[], RsaKey)` |
| `DecryptPkcs1(byte[], string, char[]?)` | `DecryptPkcs1(byte[], RsaKey)` |
| `EncryptOaep(byte[], string, RsaOaepHash)` | `EncryptOaep(byte[], RsaKey, RsaOaepHash)` |
| `DecryptOaep(byte[], string, RsaOaepHash, char[]?)` | `DecryptOaep(byte[], RsaKey, RsaOaepHash)` |
| `Sign(byte[], string, RsaSignatureAlgorithm, char[]?)` | `Sign(byte[], RsaKey, RsaSignatureAlgorithm)` |
| `Verify(byte[], byte[], string, RsaSignatureAlgorithm)` | `Verify(byte[], byte[], RsaKey, RsaSignatureAlgorithm)` |

`GenerateRsaKeyPair` → **`GenerateRsaKey`** is a rename, not just a retype: one `RsaKey` carries both
halves, so "key pair" no longer described the return value. The single handle serves both directions —
`Verify`, `EncryptPkcs1` and `EncryptOaep` accept a private-holding handle and use its derived public
half. Serialize either half with `ExportPublicKeyPem()` / `ExportPrivateKeyPem(char[]?)`. A
public-only handle passed to `Sign`, `DecryptPkcs1` or `DecryptOaep` throws `ArgumentException`.

`RsaKey` is deliberately **not `IDisposable`**. BouncyCastle holds RSA private components as
arbitrary-precision integers — immutable managed objects the garbage collector may copy — so there is
no address a `Dispose` could reliably overwrite, and offering one would imply a guarantee the runtime
cannot make. Treat the lifetime of a private handle as the lifetime of the secret.

### Certificates take the same handle

`IX509CertificateService` no longer accepts private keys as PEM text either, and its per-call
`char[]? password` parameter is gone. The `char[] password` on `ExportPkcs12` / `ImportPkcs12` is
**unchanged** — it protects the PKCS#12 archive, not a key PEM.

| Before (1.x) | After (2.0.0) |
|---|---|
| `GenerateSelfSignedCertificate(string, string privateKeyPem, DateTimeOffset, DateTimeOffset, RsaSignatureAlgorithm, char[]? password, X509CertificateOptions?)` | `GenerateSelfSignedCertificate(string, RsaKey privateKey, DateTimeOffset, DateTimeOffset, RsaSignatureAlgorithm, X509CertificateOptions?)` |
| `GenerateCertificateSigningRequest(string, string privateKeyPem, RsaSignatureAlgorithm, char[]? password)` | `GenerateCertificateSigningRequest(string, RsaKey privateKey, RsaSignatureAlgorithm)` |
| `IssueCertificate(string, string, string issuerPrivateKeyPem, DateTimeOffset, DateTimeOffset, RsaSignatureAlgorithm, char[]? password, X509CertificateOptions?)` | `IssueCertificate(string, string, RsaKey issuerPrivateKey, DateTimeOffset, DateTimeOffset, RsaSignatureAlgorithm, X509CertificateOptions?)` |
| `ExportPkcs12(string, string privateKeyPem, char[] password, IReadOnlyList<string>?)` | `ExportPkcs12(string, RsaKey privateKey, char[] password, IReadOnlyList<string>?)` |
| `(string certificatePem, string privateKeyPem) ImportPkcs12(byte[], char[])` | `(string certificatePem, RsaKey privateKey) ImportPkcs12(byte[], char[])` |

Unchanged on that service: `IsCertificateSigningRequestValid`, `ValidateChain`, `IsRevoked`,
`GetCertificateInfo`, `ExportCertificateToDer`, `ImportCertificateFromDer`, `CertificateInfo`,
`X509CertificateOptions`, `X509KeyUsage` and `IX509CertificateServiceFactory`.

#### `ImportPkcs12` returns a handle

```csharp
// 1.x — the returned PEM had to be re-imported before it could be used
(string certPem, string keyPem) = certificates.ImportPkcs12(pfx, pfxPassword);
RsaKey key = RsaKey.ImportPrivateKeyPem(keyPem);

// 2.0.0 — the handle is the return value
(string certPem, RsaKey key) = certificates.ImportPkcs12(pfx, pfxPassword);
```

No private-key PEM is written or re-parsed on that path any more. If you want a file, call
`key.ExportPrivateKeyPem()` — and note the 1.x return was always *unencrypted*, so passing a password
to the export is usually the better choice. A PKCS#12 whose key entry is not an RSA key now raises
`ArgumentException`, since there is no `RsaKey` to return.

#### Watch for shifted positional arguments

`char[]? password` sat between `signatureAlgorithm` and `options`. With it removed, an `options`
argument that was passed positionally now binds to the wrong parameter — usually a compile error, but
check any call site that did not use `options:`.

### The passphrase is supplied once, at the import

No member of `IPublicKeyService` or `IX509CertificateService` takes a passphrase any more. Supply it to
`RsaKey.ImportPrivateKeyPem` and reuse the handle. For the RSA operations:

```csharp
// 1.x — the passphrase travelled with every private-key call
byte[] signature = rsa.Sign(message, privateKeyPem, RsaSignatureAlgorithm.Sha256WithRsa, password);
byte[] recovered = rsa.DecryptOaep(ciphertext, privateKeyPem, RsaOaepHash.Sha256, password);

// 2.0.0 — supplied once, where the key is parsed
RsaKey key = RsaKey.ImportPrivateKeyPem(privateKeyPem, password);
byte[] signature = rsa.Sign(message, key, RsaSignatureAlgorithm.Sha256WithRsa);
byte[] recovered = rsa.DecryptOaep(ciphertext, key, RsaOaepHash.Sha256);
```

An encrypted CA key used to mean repeating the passphrase at every certificate call site; now the
handle does the rest:

```csharp
// 1.x
string caCertPem = certificates.GenerateSelfSignedCertificate(
    "CN=Example Root CA", caPrivateKeyPem, notBefore, notAfter,
    RsaSignatureAlgorithm.Sha256WithRsa, password, caOptions);

string csrPem = certificates.GenerateCertificateSigningRequest(
    "CN=service.example.com", caPrivateKeyPem,
    RsaSignatureAlgorithm.Sha256WithRsa, password);

string leafPem = certificates.IssueCertificate(
    csrPem, caCertPem, caPrivateKeyPem, notBefore, notAfter,
    RsaSignatureAlgorithm.Sha256WithRsa, password, leafOptions);

// 2.0.0
RsaKey caKey = RsaKey.ImportPrivateKeyPem(caPrivateKeyPem, password);

string caCertPem = certificates.GenerateSelfSignedCertificate(
    "CN=Example Root CA", caKey, notBefore, notAfter,
    RsaSignatureAlgorithm.Sha256WithRsa, caOptions);

string csrPem = certificates.GenerateCertificateSigningRequest(
    "CN=service.example.com", caKey);

string leafPem = certificates.IssueCertificate(
    csrPem, caCertPem, caKey, notBefore, notAfter,
    RsaSignatureAlgorithm.Sha256WithRsa, leafOptions);
```

Two consequences worth knowing: a wrong or missing passphrase now surfaces as
`CryptographicException` from `RsaKey.ImportPrivateKeyPem` rather than from the operation that used to
consume it, and — as before — the library never clears a passphrase array. The caller owns clearing it.

### Encrypted private-key PEMs are now written as PBES2 — reading is unchanged

`ExportPrivateKeyPem(password)` emits a PKCS#8 `ENCRYPTED PRIVATE KEY` (PBKDF2-HMAC-SHA256,
AES-256-CBC, a 16-byte salt and 600 000 iterations) instead of the traditional OpenSSL envelope
(`RSA PRIVATE KEY` with `Proc-Type` / `DEK-Info`), whose derivation was OpenSSL's legacy
`EVP_BytesToKey` — MD5, a single iteration.

**The file format did not break, only the API.** `ImportPrivateKeyPem` — and the certificate service —
read all three forms: unencrypted PKCS#8, PBES2, and the traditional OpenSSL envelope, including every
file earlier versions of this library wrote. No key file needs converting; to move one onto the
stronger derivation, import it and export it again.

The change is file-compatible in both directions: 1.x reads PBES2 too, so a key written by 2.0.0 can
still be loaded by a 1.x consumer. The cost of the stronger derivation is a one-time **~0.6 s per
encrypted key at import** — paid once per key, not once per operation, which is the whole point of the
handle.

### Migration guides

Worked before/after examples live in the guides:

- `docs/guides/public-key.md` — the RSA migration section (the removed-member table, the passphrase
  example, and the file-format compatibility details).
- `docs/guides/certificates.md` — the certificate migration section (the five-member before/after, the
  passphrase consolidation, and the `ImportPkcs12` return change).

## New Features

### ML-DSA and ML-KEM key PEM support

Both post-quantum families can now serialize their keys as PEM, through a dedicated service per family
— `IMLDsaPemService` and `IMLKemPemService`, with `IMLDsaPemServiceFactory` and
`IMLKemPemServiceFactory` to create them. Each offers:

- `GenerateKeyPairPem(parameterSet, password = null, format = MLPrivateKeyPemFormat.Seed)` — generate
  straight to PEM, encrypted when a password is supplied.
- `ToPublicKeyPem` / `ToPrivateKeyPem` — serialize raw FIPS 203 / FIPS 204 key bytes you already hold.
- `FromPublicKeyPem` / `FromPrivateKeyPem` — read a PEM back, returning the key bytes **and the
  parameter set**, recovered from the algorithm OID in the PEM rather than supplied by the caller.

Private keys can be written in any of the three FIPS formats via `MLPrivateKeyPemFormat`: `Seed` (the
default — the compact 32-byte/64-byte seed), `ExpandedKey`, or `SeedAndExpandedKey`. Encrypted private
keys use the same PBES2 scheme as RSA.

`IMLDsaService` and `IMLKemService` — the key-generation, signing/verification and
encapsulation/decapsulation surfaces — are **unchanged**.

### Checksum module

A new `Enigma.Core.Checksum` namespace with `IChecksumService` and `IChecksumServiceFactory`, covering
seven named CRC variants:

- **CRC-16** — ARC, CCITT-FALSE, XMODEM, MODBUS, KERMIT.
- **CRC-32** — ISO-HDLC, CRC-32C (Castagnoli).

Each variant has its own factory method (`CreateCrc16ArcService`, `CreateCrc32CService`, …) — there is
deliberately no variant-ambiguous `CreateCrc16Service`. A service computes over a `byte[]` or a
`Stream`, synchronously or asynchronously with `IProgress<int>` and a `CancellationToken`, and returns
either big-endian bytes (`ComputeChecksum`, `ChecksumSize` long) or a `uint`
(`ComputeChecksumValue`). Every variant is pinned to its published check value over `"123456789"`.

**A CRC is error detection, not a security primitive.** It detects accidental corruption and is
trivially forgeable, so it can never stand in for a cryptographic digest — use `IHashService` or
`IHmacService` when integrity must hold against an adversary. The module lives in its own namespace
for exactly that reason.

## Compatibility

- Target frameworks are **unchanged**: .NET Standard 2.0, .NET 8.0, and .NET 10.0.
- The BouncyCastle.Cryptography floor is **unchanged at 2.7.0** — there is no dependency transition in
  this release, and the Checksum module is implemented in-repo, adding **no** new dependency.
- **RSA key files keep working; RSA code does not.** Every 1.x-written key PEM still imports (see
  *Encrypted private-key PEMs* above), but every 1.x call site that passed a PEM string or a per-call
  passphrase must be updated.
- **ML-KEM and ML-DSA raw key, ciphertext and signature encodings are unchanged**, so keys,
  ciphertexts and signatures persisted by 1.x continue to work. The new PEM services are additive:
  they wrap those same encodings, and `IMLDsaService` / `IMLKemService` were not touched.
- The Checksum module is purely **additive** — nothing existing changed to accommodate it.

## Version

- Release: **2.0.0**.

---

# Enigma.Core v1.1.0 Release Notes

A dependency release: Enigma.Core now builds on **BouncyCastle.Cryptography 2.7.0**. No public API is
added, removed, or changed, and the library's own behaviour is unchanged — the only consumer-visible
effect is the raised BouncyCastle floor.

## Dependencies

- **BouncyCastle.Cryptography 2.6.2 → 2.7.0** (runtime dependency, all target frameworks).
- `coverlet.collector` 6.0.4 → 10.0.1 — test-only, not redistributed as part of the package.

## Compatibility

- Target frameworks are unchanged: **.NET Standard 2.0**, **.NET 8.0**, and **.NET 10.0**.
- The **minimum BouncyCastle.Cryptography version is now 2.7.0**. Consumers pinned to 2.6.x must
  upgrade — 2.7.0 relocated `PasswordException` into `Org.BouncyCastle.OpenSsl`, and Enigma.Core
  binds to that type, so the assembly will not load against an older BouncyCastle.
- ML-KEM and ML-DSA key, ciphertext and signature encodings are **unchanged**, so keys, ciphertexts
  and signatures persisted by 1.0.0 continue to work. This is verified by fixed-vector tests against
  unmodified 1.0.0-era fixtures, plus encoding-contract tests that pin the exact FIPS 203 / FIPS 204
  sizes for all six parameter sets.

## Version

- Release: **1.1.0**.

---

# Enigma.Core v1.0.0 Release Notes

The first public release of **Enigma.Core** — a modern, service- and factory-oriented .NET
cryptography library built on BouncyCastle and designed for dependency injection. Every algorithm is
reached through the same pattern (create a factory, get a service, call the operation), and no
BouncyCastle type is ever exposed on the public surface.

## Feature overview

- **Block ciphers** — AES, DES, 3DES, Blowfish, Twofish, Serpent, Camellia, CAST5, IDEA, SEED,
  ARIA, and SM4, in ECB / CBC / CTR / GCM modes, with additional authenticated data (AAD) and a
  configurable MAC size for GCM.
- **Stream ciphers** — ChaCha20, ChaCha20-RFC7539, and Salsa20.
- **Padding** — None, PKCS#7, ISO 7816-4, ISO 10126-2, and ANSI X9.23.
- **Public-key (RSA)** — key generation with PEM import/export (optionally AES-256-CBC-encrypted
  private keys), PKCS#1 v1.5 and OAEP encryption, and RSASSA-PKCS1-v1_5 signing/verification.
- **Post-quantum (PQC)** — ML-KEM 512/768/1024 (FIPS 203) key encapsulation and ML-DSA 44/65/87
  (FIPS 204) signatures.
- **X.509 certificates** — self-signed generation, CSR creation & verification, CA issuance, chain
  validation, CRL-based revocation checks, PKCS#12 and DER import/export, and certificate inspection
  (subject, issuer, validity, thumbprint, and more).
- **Hashing** — MD5, SHA-1, SHA-256, SHA-512, and SHA-3.
- **HMAC** — HMAC-SHA1, HMAC-SHA256, and HMAC-SHA512.
- **One-time passwords** — HOTP (RFC 4226), TOTP (RFC 6238), and `otpauth://` provisioning URIs.
- **Key derivation** — PBKDF2 (four PRFs) and Argon2 (Argon2d/i/id).
- **Encoding** — Base64, Base32 (RFC 4648), and hexadecimal.
- **Streaming, async, cancellable** — the streaming operations (block and stream ciphers, hashing,
  and HMAC) offer `async` APIs with `IProgress<int>` progress reporting and `CancellationToken`
  support.

## Compatibility

- Targets **.NET Standard 2.0**, **.NET 8.0**, and **.NET 10.0**.
- Built on **BouncyCastle.Cryptography 2.6.2**.

## Version

- Initial release: **1.0.0**.
