# X.509 Certificates

Enigma.Core provides X.509 certificate operations through the same service +
factory pattern used across the library. You create an
`X509CertificateServiceFactory`, ask it for an `IX509CertificateService`, and
call the operation you need. The service is backed by BouncyCastle, but no
BouncyCastle types cross the API — certificates, CSRs and CRLs are PEM-encoded
text, and key material is an `RsaKey` handle.

```csharp
using Enigma.Core.Certificates;

var certFactory = new X509CertificateServiceFactory();
IX509CertificateService certificates = certFactory.CreateX509CertificateService();
```

> Upgrading from 1.x? The certificate methods no longer take a private-key PEM
> plus a `password`. See
> [Migrating from the PEM-string API](#migrating-from-the-pem-string-api).

Certificates never carry their own key generation. To obtain the key that
certifies a subject and signs a certificate, generate one with the public-key
service and pass the handle straight in:

```csharp
using Enigma.Core.Asymmetric.PublicKey;

var keyFactory = new PublicKeyServiceFactory();
IPublicKeyService rsa = keyFactory.CreatePublicKeyService();

RsaKey key = rsa.GenerateRsaKey();
```

If the key lives in a PEM file, import it once — supplying its passphrase there
if it is encrypted — and hand the resulting handle to as many certificate
operations as you need:

```csharp
RsaKey key = RsaKey.ImportPrivateKeyPem(privateKeyPem, password);
```

Both factories are constructed directly with `new`. The `I*` interfaces are
DI-friendly, so you can also register `X509CertificateServiceFactory` against
`IX509CertificateServiceFactory` (and `PublicKeyServiceFactory` against
`IPublicKeyServiceFactory`) in a Microsoft.Extensions.DependencyInjection
container and inject them where needed.

## Supported operations

| Operation | Method | Returns |
|-----------|--------|---------|
| Self-signed certificate | `GenerateSelfSignedCertificate` | certificate PEM |
| Certificate signing request | `GenerateCertificateSigningRequest` | CSR PEM |
| Validate a CSR | `IsCertificateSigningRequestValid` | `bool` |
| Issue from a CSR | `IssueCertificate` | certificate PEM |
| Chain validation | `ValidateChain` | `bool` |
| Revocation check (CRL) | `IsRevoked` | `bool` |
| Read certificate fields | `GetCertificateInfo` | `CertificateInfo` |
| Export PKCS#12 (PFX) | `ExportPkcs12` | `byte[]` |
| Import PKCS#12 (PFX) | `ImportPkcs12` | `(string, RsaKey)` |
| Export to DER | `ExportCertificateToDer` | `byte[]` |
| Import from DER | `ImportCertificateFromDer` | certificate PEM |

The four key-taking methods (`GenerateSelfSignedCertificate`,
`GenerateCertificateSigningRequest`, `IssueCertificate`, `ExportPkcs12`) take an
`RsaKey` that must hold a private key. A `null` handle raises
`ArgumentNullException`; a public-only handle raises `ArgumentException` naming
that parameter.

The signing methods (`GenerateSelfSignedCertificate`,
`GenerateCertificateSigningRequest`, `IssueCertificate`) take an optional
`RsaSignatureAlgorithm` that defaults to `RsaSignatureAlgorithm.Sha256WithRsa`.
The other values are `Sha1WithRsa`, `Sha384WithRsa` and `Sha512WithRsa`.

## Key types

| Type | Namespace | Role |
|------|-----------|------|
| `X509CertificateServiceFactory` | `Enigma.Core.Certificates` | Concrete factory. Implements `IX509CertificateServiceFactory`. Create with `new`. |
| `IX509CertificateServiceFactory` | `Enigma.Core.Certificates` | Factory interface. DI-friendly. |
| `IX509CertificateService` | `Enigma.Core.Certificates` | The certificate service returned by the factory. |
| `X509CertificateOptions` | `Enigma.Core.Certificates` | Optional X.509 v3 extensions to embed. `sealed record`, init-only. |
| `X509KeyUsage` | `Enigma.Core.Certificates` | `[Flags]` enum of permitted key usages. |
| `CertificateInfo` | `Enigma.Core.Certificates` | `sealed record` of the fields read back from a certificate. |
| `RsaSignatureAlgorithm` | `Enigma.Core` | Selects the certificate signature algorithm. |
| `RsaKey` | `Enigma.Core.Asymmetric.PublicKey` | The key handle every key-taking method accepts. |
| `IPublicKeyService` | `Enigma.Core.Asymmetric.PublicKey` | RSA service used to generate the key. |

### `X509CertificateOptions`

A `sealed record` whose init-only properties are all optional — a `null` options
argument, or a `null` property, omits the corresponding X.509 v3 extension. Use
an object initializer:

- `bool? IsCertificateAuthority` — emits the `BasicConstraints` extension. Set to
  `true` for a certificate that must act as a trust anchor or intermediate.
- `X509KeyUsage? KeyUsage` — emits the `KeyUsage` extension.
- `IReadOnlyList<string>? SubjectAlternativeNames` — emits the
  `SubjectAlternativeName` extension. Each entry is treated as a DNS name.

### `X509KeyUsage`

A `[Flags]` enum; combine values with a bitwise OR:

```
None = 0, DigitalSignature, NonRepudiation, KeyEncipherment, DataEncipherment,
KeyAgreement, KeyCertSign, CrlSign, EncipherOnly, DecipherOnly
```

For a CA, use `X509KeyUsage.KeyCertSign | X509KeyUsage.CrlSign`.

### `CertificateInfo`

A `sealed record` with read-only properties: `string Subject`, `string Issuer`,
`BigInteger SerialNumber`, `DateTimeOffset NotBefore`, `DateTimeOffset NotAfter`,
`string SignatureAlgorithm`, `int Version`, `string Thumbprint` (uppercase hex),
`bool IsCertificateAuthority`, `X509KeyUsage? KeyUsage` and
`IReadOnlyList<string> SubjectAlternativeNames`.

## Usage

### Self-signed certificate

Generate a key, sign a certificate for the subject, then read a couple of
fields back with `GetCertificateInfo`.

```csharp
using System;
using Enigma.Core;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Certificates;

var certFactory = new X509CertificateServiceFactory();
IX509CertificateService certificates = certFactory.CreateX509CertificateService();

var keyFactory = new PublicKeyServiceFactory();
IPublicKeyService rsa = keyFactory.CreatePublicKeyService();

RsaKey key = rsa.GenerateRsaKey();

string certificatePem = certificates.GenerateSelfSignedCertificate(
    "CN=example.com",
    key,
    DateTimeOffset.UtcNow,
    DateTimeOffset.UtcNow.AddYears(1));

CertificateInfo info = certificates.GetCertificateInfo(certificatePem);
Console.WriteLine(info.Subject);      // CN=example.com
Console.WriteLine(info.Thumbprint);   // uppercase hex fingerprint
```

The signature algorithm defaults to `RsaSignatureAlgorithm.Sha256WithRsa`. To
sign with a different one, pass it explicitly:

```csharp
string certificatePem = certificates.GenerateSelfSignedCertificate(
    "CN=example.com",
    key,
    DateTimeOffset.UtcNow,
    DateTimeOffset.UtcNow.AddYears(1),
    RsaSignatureAlgorithm.Sha384WithRsa);
```

### CSR and issuance from a CA

Build a self-signed CA (with the CA flag and the `KeyCertSign | CrlSign` key
usage set through `X509CertificateOptions`), then generate a leaf key and
CSR, issue a leaf certificate from that CSR, and validate that the leaf chains
back to the CA.

```csharp
using System;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Certificates;

var certFactory = new X509CertificateServiceFactory();
IX509CertificateService certificates = certFactory.CreateX509CertificateService();

var keyFactory = new PublicKeyServiceFactory();
IPublicKeyService rsa = keyFactory.CreatePublicKeyService();

// 1. Certificate authority.
RsaKey caKey = rsa.GenerateRsaKey();

string caCertPem = certificates.GenerateSelfSignedCertificate(
    "CN=Example Root CA",
    caKey,
    DateTimeOffset.UtcNow,
    DateTimeOffset.UtcNow.AddYears(10),
    options: new X509CertificateOptions
    {
        IsCertificateAuthority = true,
        KeyUsage = X509KeyUsage.KeyCertSign | X509KeyUsage.CrlSign,
    });

// 2. Leaf key and CSR.
RsaKey leafKey = rsa.GenerateRsaKey();

string csrPem = certificates.GenerateCertificateSigningRequest(
    "CN=service.example.com",
    leafKey);

bool csrOk = certificates.IsCertificateSigningRequestValid(csrPem);

// 3. Issue the leaf from the CSR, signed by the CA.
string leafPem = certificates.IssueCertificate(
    csrPem,
    caCertPem,
    caKey,
    DateTimeOffset.UtcNow,
    DateTimeOffset.UtcNow.AddYears(1),
    options: new X509CertificateOptions
    {
        KeyUsage = X509KeyUsage.DigitalSignature | X509KeyUsage.KeyEncipherment,
        SubjectAlternativeNames = new[] { "service.example.com", "www.example.com" },
    });

// 4. Validate the leaf chains to the trusted CA.
bool trusted = certificates.ValidateChain(leafPem, new[] { caCertPem });
```

When there are untrusted intermediates between the leaf and a trusted root, pass
them as the third argument so the chain can be built:

```csharp
bool trusted = certificates.ValidateChain(
    leafPem,
    new[] { rootCaPem },
    new[] { intermediateCaPem });
```

### Revocation check against a CRL

`IsRevoked` verifies the CRL's signature with the issuer certificate, then checks
whether the certificate's serial number is listed. All three arguments are PEM.

```csharp
bool revoked = certificates.IsRevoked(leafPem, crlPem, caCertPem);
```

### PKCS#12 (PFX) export and import

PKCS#12 bundles a certificate and its private key (optionally with chain
certificates) into a single password-protected binary archive. The password is a
`char[]`; it may be empty but must not be `null`.

```csharp
using System;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Certificates;

var certFactory = new X509CertificateServiceFactory();
IX509CertificateService certificates = certFactory.CreateX509CertificateService();

char[] pfxPassword = "correct horse battery staple".ToCharArray();

byte[] pfx = certificates.ExportPkcs12(
    leafPem,
    leafKey,
    pfxPassword,
    chainPems: new[] { caCertPem });

// ... later, unlock the archive back into a certificate + key handle.
(string certificatePem, RsaKey privateKey) = certificates.ImportPkcs12(pfx, pfxPassword);
```

`ImportPkcs12` hands back a ready-to-use `RsaKey` — no private-key PEM is written
or re-parsed on the way. If you do want a file, export one from the handle:

```csharp
string privateKeyPem = privateKey.ExportPrivateKeyPem();                 // unencrypted
string encryptedPem = privateKey.ExportPrivateKeyPem(filePassword);      // PBES2-encrypted
```

The archive must hold an RSA key: a PKCS#12 whose key entry is some other
algorithm raises `ArgumentException`, since there is no `RsaKey` to return.

### DER export and import

DER is the raw binary encoding of a single certificate. Round-trip it to and from
PEM with `ExportCertificateToDer` / `ImportCertificateFromDer`.

```csharp
byte[] der = certificates.ExportCertificateToDer(leafPem);

string certificatePem = certificates.ImportCertificateFromDer(der);
```

### Reading certificate fields

`GetCertificateInfo` decodes a certificate into an immutable `CertificateInfo`.

```csharp
using System;
using Enigma.Core.Certificates;

CertificateInfo info = certificates.GetCertificateInfo(leafPem);

Console.WriteLine(info.Subject);
Console.WriteLine(info.Issuer);
Console.WriteLine(info.SerialNumber);           // BigInteger
Console.WriteLine(info.NotBefore);
Console.WriteLine(info.NotAfter);
Console.WriteLine(info.SignatureAlgorithm);
Console.WriteLine(info.Version);                // e.g. 3
Console.WriteLine(info.Thumbprint);             // uppercase hex
Console.WriteLine(info.IsCertificateAuthority);
Console.WriteLine(info.KeyUsage);               // X509KeyUsage? — null if no KeyUsage extension

foreach (string dnsName in info.SubjectAlternativeNames)
{
    Console.WriteLine(dnsName);
}
```

## Migrating from the PEM-string API

In 1.x every key-taking certificate method took a private-key PEM plus a
`char[]? password`, and `ImportPkcs12` returned a private-key PEM. 2.0.0 replaces
all of that with the `RsaKey` handle, matching
[the public-key service](public-key.md#migrating-from-the-pem-string-api). The
old signatures were **removed outright** — there are no `[Obsolete]` overloads
and no compatibility shims.

| Before (1.x) | After (2.0.0) |
|---|---|
| `GenerateSelfSignedCertificate(string, string privateKeyPem, DateTimeOffset, DateTimeOffset, RsaSignatureAlgorithm, char[]? password, X509CertificateOptions?)` | `GenerateSelfSignedCertificate(string, RsaKey privateKey, DateTimeOffset, DateTimeOffset, RsaSignatureAlgorithm, X509CertificateOptions?)` |
| `GenerateCertificateSigningRequest(string, string privateKeyPem, RsaSignatureAlgorithm, char[]? password)` | `GenerateCertificateSigningRequest(string, RsaKey privateKey, RsaSignatureAlgorithm)` |
| `IssueCertificate(string, string, string issuerPrivateKeyPem, DateTimeOffset, DateTimeOffset, RsaSignatureAlgorithm, char[]? password, X509CertificateOptions?)` | `IssueCertificate(string, string, RsaKey issuerPrivateKey, DateTimeOffset, DateTimeOffset, RsaSignatureAlgorithm, X509CertificateOptions?)` |
| `ExportPkcs12(string, string privateKeyPem, char[] password, IReadOnlyList<string>?)` | `ExportPkcs12(string, RsaKey privateKey, char[] password, IReadOnlyList<string>?)` |
| `(string certificatePem, string privateKeyPem) ImportPkcs12(byte[], char[])` | `(string certificatePem, RsaKey privateKey) ImportPkcs12(byte[], char[])` |

Everything else is unchanged: `IsCertificateSigningRequestValid`,
`ValidateChain`, `IsRevoked`, `GetCertificateInfo`, `ExportCertificateToDer`,
`ImportCertificateFromDer`, `CertificateInfo`, `X509CertificateOptions`,
`X509KeyUsage` and the factory all keep their 1.x shapes.

### The passphrase moves to the import

Before, an encrypted key file meant repeating the passphrase at every call site:

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
```

Now it is supplied once, where the key is parsed:

```csharp
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

Each of those three 1.x calls parsed the PEM and re-derived the decryption key
from the passphrase before it could sign anything. Import once, keep the handle.

Two things to watch when you update call sites:

- **Positional arguments shift.** `char[]? password` sat between
  `signatureAlgorithm` and `options`; with it gone, an `options` argument that
  used to be passed positionally now binds to the wrong parameter — or, more
  often, simply stops compiling. Named arguments (`options:`) are unaffected.
- **A wrong or missing passphrase now fails earlier.** It surfaces as
  `CryptographicException` from `RsaKey.ImportPrivateKeyPem`, not from the
  certificate call that used to consume it.

### `ImportPkcs12` returns a handle

```csharp
// 1.x — the returned PEM had to be re-imported before it could be used
(string certPem, string keyPem) = certificates.ImportPkcs12(pfx, pfxPassword);
RsaKey key = RsaKey.ImportPrivateKeyPem(keyPem);

// 2.0.0 — the handle is the return value
(string certPem, RsaKey key) = certificates.ImportPkcs12(pfx, pfxPassword);
```

If your code genuinely wanted the PEM file, call
`key.ExportPrivateKeyPem()` on the result — but note the 1.x return value was
always an *unencrypted* private-key PEM, so passing a password to the export is
usually the better choice.

## Notes

- Certificates, CSRs and CRLs cross this API as PEM-encoded text, with two
  documented binary exceptions: PKCS#12 archives (`ExportPkcs12` /
  `ImportPkcs12`) and DER-encoded certificates (`ExportCertificateToDer` /
  `ImportCertificateFromDer`) are `byte[]`. Key material crosses as `RsaKey`.
- No passphrase reaches the certificate API. An encrypted private-key PEM is
  unlocked once, at `RsaKey.ImportPrivateKeyPem(pem, password)`, and the handle
  is what the certificate operations take. `ImportPrivateKeyPem` also reads the
  traditional OpenSSL encrypted envelope that earlier versions wrote, so existing
  key files keep working.
- The PKCS#12 password (`ExportPkcs12` / `ImportPkcs12`) is unrelated to any key
  passphrase — it protects the archive itself. It may be empty but must not be
  `null`. The private key stored inside the archive is unencrypted.
- A certificate that must act as a trust anchor or intermediate in a validated
  chain needs `IsCertificateAuthority = true` (and typically
  `X509KeyUsage.KeyCertSign`) set through `X509CertificateOptions` at generation
  or issuance time.
- `CertificateInfo.SignatureAlgorithm` is read back from the certificate as a
  string and may name any algorithm — not only the RSA variants selectable at
  generation time through `RsaSignatureAlgorithm`.
- The caller owns clearing any `char[]` password; these methods do not clear it.
