# X.509 Certificates

Enigma.Core provides X.509 certificate operations through the same service +
factory pattern used across the library. You create an
`X509CertificateServiceFactory`, ask it for an `IX509CertificateService`, and
call the operation you need. The service is backed by BouncyCastle, but no
BouncyCastle types cross the API — certificates, CSRs, CRLs and keys are all
PEM-encoded text.

```csharp
using Enigma.Core.Certificates;

var certFactory = new X509CertificateServiceFactory();
IX509CertificateService certificates = certFactory.CreateX509CertificateService();
```

Certificates never carry their own key pair generation. To obtain the
private-key PEM that certifies a subject and signs a certificate, use the RSA
public-key service:

```csharp
using Enigma.Core.Asymmetric.PublicKey;

var keyFactory = new PublicKeyServiceFactory();
IPublicKeyService rsa = keyFactory.CreatePublicKeyService();

(string publicKeyPem, string privateKeyPem) = rsa.GenerateRsaKeyPair();
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
| Import PKCS#12 (PFX) | `ImportPkcs12` | `(string, string)` |
| Export to DER | `ExportCertificateToDer` | `byte[]` |
| Import from DER | `ImportCertificateFromDer` | certificate PEM |

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
| `IPublicKeyService` | `Enigma.Core.Asymmetric.PublicKey` | RSA service used to generate the key pair. |

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

Generate a key pair, sign a certificate for the subject, then read a couple of
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

(string publicKeyPem, string privateKeyPem) = rsa.GenerateRsaKeyPair();

string certificatePem = certificates.GenerateSelfSignedCertificate(
    "CN=example.com",
    privateKeyPem,
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
    privateKeyPem,
    DateTimeOffset.UtcNow,
    DateTimeOffset.UtcNow.AddYears(1),
    RsaSignatureAlgorithm.Sha384WithRsa);
```

### CSR and issuance from a CA

Build a self-signed CA (with the CA flag and the `KeyCertSign | CrlSign` key
usage set through `X509CertificateOptions`), then generate a leaf key pair and
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
(string _, string caPrivateKeyPem) = rsa.GenerateRsaKeyPair();

string caCertPem = certificates.GenerateSelfSignedCertificate(
    "CN=Example Root CA",
    caPrivateKeyPem,
    DateTimeOffset.UtcNow,
    DateTimeOffset.UtcNow.AddYears(10),
    options: new X509CertificateOptions
    {
        IsCertificateAuthority = true,
        KeyUsage = X509KeyUsage.KeyCertSign | X509KeyUsage.CrlSign,
    });

// 2. Leaf key pair and CSR.
(string _, string leafPrivateKeyPem) = rsa.GenerateRsaKeyPair();

string csrPem = certificates.GenerateCertificateSigningRequest(
    "CN=service.example.com",
    leafPrivateKeyPem);

bool csrOk = certificates.IsCertificateSigningRequestValid(csrPem);

// 3. Issue the leaf from the CSR, signed by the CA.
string leafPem = certificates.IssueCertificate(
    csrPem,
    caCertPem,
    caPrivateKeyPem,
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
using Enigma.Core.Certificates;

var certFactory = new X509CertificateServiceFactory();
IX509CertificateService certificates = certFactory.CreateX509CertificateService();

char[] pfxPassword = "correct horse battery staple".ToCharArray();

byte[] pfx = certificates.ExportPkcs12(
    leafPem,
    leafPrivateKeyPem,
    pfxPassword,
    chainPems: new[] { caCertPem });

// ... later, unlock the archive back into a certificate + key.
(string certificatePem, string privateKeyPem) = certificates.ImportPkcs12(pfx, pfxPassword);
```

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

## Notes

- Everything that crosses this API is PEM-encoded text — certificates, CSRs, CRLs
  and keys — with two documented exceptions: PKCS#12 archives
  (`ExportPkcs12` / `ImportPkcs12`) and DER-encoded certificates
  (`ExportCertificateToDer` / `ImportCertificateFromDer`) are `byte[]`.
- `GenerateRsaKeyPair` returns an unencrypted private-key PEM by default. Pass a
  `char[]` password to have it returned AES-256-CBC-encrypted. When a private-key
  PEM is encrypted, supply the same `char[]` password to the `password` parameter
  of `GenerateSelfSignedCertificate`, `GenerateCertificateSigningRequest` and
  `IssueCertificate`; leave it `null` for an unencrypted PEM.
- The PKCS#12 password (`ExportPkcs12` / `ImportPkcs12`) is a separate `char[]`
  protecting the archive itself. It may be empty but must not be `null`. The
  private key stored in the archive is unencrypted, and `ImportPkcs12` returns it
  as an unencrypted PEM.
- A certificate that must act as a trust anchor or intermediate in a validated
  chain needs `IsCertificateAuthority = true` (and typically
  `X509KeyUsage.KeyCertSign`) set through `X509CertificateOptions` at generation
  or issuance time.
- `CertificateInfo.SignatureAlgorithm` is read back from the certificate as a
  string and may name any algorithm — not only the RSA variants selectable at
  generation time through `RsaSignatureAlgorithm`.
- The caller owns clearing any `char[]` password; these methods do not clear it.
