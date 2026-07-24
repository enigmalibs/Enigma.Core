# Public-Key Cryptography (RSA)

Enigma.Core provides RSA public-key cryptography through a small service +
factory API. You create a `PublicKeyServiceFactory`, ask it for an
`IPublicKeyService`, and use that service to generate key pairs, encrypt and
decrypt, and sign and verify.

Keys cross the API as PEM-encoded text: a `PUBLIC KEY` PEM for public operations
(encrypt, verify) and a `PRIVATE KEY` PEM for private operations (decrypt, sign).
Because RSA can only process data smaller than the modulus minus the padding
overhead, every operation works on in-memory `byte[]` rather than streams.

## Supported operations

| Operation | Method | Padding / algorithm |
|-----------|--------|---------------------|
| Generate key pair | `GenerateRsaKeyPair` | Returns `(publicKeyPem, privateKeyPem)`. |
| Encrypt (PKCS#1 v1.5) | `EncryptPkcs1` | PKCS#1 v1.5 padding, public key. |
| Decrypt (PKCS#1 v1.5) | `DecryptPkcs1` | PKCS#1 v1.5 padding, private key. |
| Encrypt (OAEP) | `EncryptOaep` | OAEP padding with a selectable hash, public key. |
| Decrypt (OAEP) | `DecryptOaep` | OAEP padding with a selectable hash, private key. |
| Sign | `Sign` | RSASSA-PKCS1-v1_5 with a selectable hash, private key. |
| Verify | `Verify` | RSASSA-PKCS1-v1_5 with a selectable hash, public key. |

The OAEP hash is chosen with `RsaOaepHash`; the signature algorithm is chosen
with `RsaSignatureAlgorithm`:

```csharp
enum RsaOaepHash { Sha1, Sha256, Sha384, Sha512 }
enum RsaSignatureAlgorithm { Sha1WithRsa, Sha256WithRsa, Sha384WithRsa, Sha512WithRsa }
```

Both default to the SHA-256 variant. The same padding, hash and algorithm must
be selected on both sides of an operation: decrypt with the hash used to encrypt,
and verify with the algorithm used to sign.

## Key types

| Type | Namespace | Role |
|------|-----------|------|
| `PublicKeyServiceFactory` | `Enigma.Core.Asymmetric.PublicKey` | Concrete factory. Implements `IPublicKeyServiceFactory`. Create with `new`. |
| `IPublicKeyServiceFactory` | `Enigma.Core.Asymmetric.PublicKey` | Factory interface. DI-friendly. |
| `IPublicKeyService` | `Enigma.Core.Asymmetric.PublicKey` | The RSA service returned by the factory. |
| `RsaOaepHash` | `Enigma.Core.Asymmetric.PublicKey` | Selects the OAEP mask/label hash. |
| `RsaSignatureAlgorithm` | `Enigma.Core` | Selects the signature hash + RSA. |

`IPublicKeyService` exposes:

```csharp
(string publicKeyPem, string privateKeyPem) GenerateRsaKeyPair(int keySizeBits = 2048, char[]? password = null);
byte[] EncryptPkcs1(byte[] data, string publicKeyPem);
byte[] DecryptPkcs1(byte[] ciphertext, string privateKeyPem, char[]? password = null);
byte[] EncryptOaep(byte[] data, string publicKeyPem, RsaOaepHash hash = RsaOaepHash.Sha256);
byte[] DecryptOaep(byte[] ciphertext, string privateKeyPem, RsaOaepHash hash = RsaOaepHash.Sha256, char[]? password = null);
byte[] Sign(byte[] data, string privateKeyPem, RsaSignatureAlgorithm algorithm = RsaSignatureAlgorithm.Sha256WithRsa, char[]? password = null);
bool Verify(byte[] data, byte[] signature, string publicKeyPem, RsaSignatureAlgorithm algorithm = RsaSignatureAlgorithm.Sha256WithRsa);
```

The factory is constructed directly with `new`. The `I*` interfaces are
DI-friendly, so you can also register `PublicKeyServiceFactory` against
`IPublicKeyServiceFactory` in a Microsoft.Extensions.DependencyInjection
container and inject it where needed.

## Usage

### Generate a key pair

`GenerateRsaKeyPair` returns two PEM strings. With no password, the private-key
PEM is unencrypted.

```csharp
using Enigma.Core.Asymmetric.PublicKey;

var factory = new PublicKeyServiceFactory();
IPublicKeyService rsa = factory.CreatePublicKeyService();

(string publicKeyPem, string privateKeyPem) = rsa.GenerateRsaKeyPair(keySizeBits: 2048);

// publicKeyPem  -> "-----BEGIN PUBLIC KEY----- ..."
// privateKeyPem -> "-----BEGIN PRIVATE KEY----- ..." (unencrypted)
```

### Encrypt and decrypt with OAEP

OAEP is the recommended padding for new work. Encrypt with the public key,
decrypt with the private key, and use the same `RsaOaepHash` on both sides.

```csharp
using System;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Extensions;

var factory = new PublicKeyServiceFactory();
IPublicKeyService rsa = factory.CreatePublicKeyService();

(string publicKeyPem, string privateKeyPem) = rsa.GenerateRsaKeyPair();

byte[] plaintext = "attack at dawn".GetUtf8Bytes();

byte[] ciphertext = rsa.EncryptOaep(plaintext, publicKeyPem, RsaOaepHash.Sha256);
byte[] recovered = rsa.DecryptOaep(ciphertext, privateKeyPem, RsaOaepHash.Sha256);

Console.WriteLine(recovered.GetString()); // attack at dawn
```

### Encrypt and decrypt with PKCS#1 v1.5

PKCS#1 v1.5 encryption is provided for interoperability with systems that
require it. The API mirrors OAEP but takes no hash parameter.

```csharp
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Extensions;

var factory = new PublicKeyServiceFactory();
IPublicKeyService rsa = factory.CreatePublicKeyService();

(string publicKeyPem, string privateKeyPem) = rsa.GenerateRsaKeyPair();

byte[] plaintext = "attack at dawn".GetUtf8Bytes();

byte[] ciphertext = rsa.EncryptPkcs1(plaintext, publicKeyPem);
byte[] recovered = rsa.DecryptPkcs1(ciphertext, privateKeyPem);
```

### Sign and verify

Sign with the private key and verify with the public key, using the same
`RsaSignatureAlgorithm` on both sides. `Verify` returns `true` only when the
signature matches the data.

```csharp
using System;
using Enigma.Core;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Extensions;

var factory = new PublicKeyServiceFactory();
IPublicKeyService rsa = factory.CreatePublicKeyService();

(string publicKeyPem, string privateKeyPem) = rsa.GenerateRsaKeyPair();

byte[] message = "release approved".GetUtf8Bytes();

byte[] signature = rsa.Sign(message, privateKeyPem, RsaSignatureAlgorithm.Sha256WithRsa);
bool valid = rsa.Verify(message, signature, publicKeyPem, RsaSignatureAlgorithm.Sha256WithRsa);

Console.WriteLine(valid); // True
```

### Protecting the private key with a passphrase

Pass a `char[]` password to `GenerateRsaKeyPair` to receive an AES-256-CBC
encrypted private-key PEM. Supply the same password back to any private
operation (`DecryptPkcs1`, `DecryptOaep`, `Sign`).

```csharp
using System;
using Enigma.Core;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Extensions;

var factory = new PublicKeyServiceFactory();
IPublicKeyService rsa = factory.CreatePublicKeyService();

char[] password = "correct horse battery staple".ToCharArray();

(string publicKeyPem, string privateKeyPem) = rsa.GenerateRsaKeyPair(2048, password);
// privateKeyPem -> "-----BEGIN ENCRYPTED PRIVATE KEY----- ..." (AES-256-CBC)

byte[] message = "release approved".GetUtf8Bytes();

// The passphrase is required to use the encrypted private key.
byte[] signature = rsa.Sign(message, privateKeyPem, RsaSignatureAlgorithm.Sha256WithRsa, password);
bool valid = rsa.Verify(message, signature, publicKeyPem, RsaSignatureAlgorithm.Sha256WithRsa);

// The library does not clear the password array; clear it yourself when done.
Array.Clear(password, 0, password.Length);

Console.WriteLine(valid); // True
```

## Notes

- **Keys are PEM text.** `GenerateRsaKeyPair` returns a `PUBLIC KEY` PEM and a
  `PRIVATE KEY` PEM. Pass the public-key PEM to `EncryptPkcs1`, `EncryptOaep` and
  `Verify`; pass the private-key PEM to `DecryptPkcs1`, `DecryptOaep` and `Sign`.
- **RSA works on in-memory `byte[]`, not streams.** RSA can only process data
  smaller than the modulus minus the padding overhead, so there is no streaming
  API. To encrypt a large payload, encrypt a symmetric key with RSA and encrypt
  the data with that symmetric key (hybrid encryption).
- **Encrypted private keys.** When `password` is `null`, the private-key PEM is
  unencrypted. When a passphrase is supplied, the private-key PEM is encrypted
  with AES-256-CBC, and the same `char[]` password must be passed to every
  private operation. The library does not clear the password array — the caller
  owns clearing it (for example with `Array.Clear`).
- **Match both sides.** Decrypt with the `RsaOaepHash` used to encrypt, and
  verify with the `RsaSignatureAlgorithm` used to sign. Both default to the
  SHA-256 variant.
