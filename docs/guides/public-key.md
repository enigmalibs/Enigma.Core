# Public-Key Cryptography (RSA)

Enigma.Core provides RSA public-key cryptography through a small service +
factory API. You create a `PublicKeyServiceFactory`, ask it for an
`IPublicKeyService`, and use that service to generate keys, encrypt and decrypt,
and sign and verify.

Keys cross the API as **`RsaKey` handles**, not as PEM text. A PEM is parsed once
— by `RsaKey.ImportPublicKeyPem` or `RsaKey.ImportPrivateKeyPem` — and the
resulting handle is reused for as many operations as you need. An encrypted
private-key PEM is decrypted at that import, so its passphrase is supplied
exactly once and never again.

Because RSA can only process data smaller than the modulus minus the padding
overhead, every operation works on in-memory `byte[]` rather than streams.

> Coming from 1.x, where every method took a PEM string? See
> [Migrating from the PEM-string API](#migrating-from-the-pem-string-api).

## Supported operations

| Operation | Method | Padding / algorithm |
|-----------|--------|---------------------|
| Generate a key | `GenerateRsaKey` | Returns one `RsaKey` carrying both halves. |
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
| `RsaKey` | `Enigma.Core.Asymmetric.PublicKey` | A parsed RSA key. Every operation takes one. |
| `RsaOaepHash` | `Enigma.Core.Asymmetric.PublicKey` | Selects the OAEP mask/label hash. |
| `RsaSignatureAlgorithm` | `Enigma.Core` | Selects the signature hash + RSA. |

`IPublicKeyService` exposes:

```csharp
RsaKey GenerateRsaKey(int keySizeBits = 2048);
byte[] EncryptPkcs1(byte[] data, RsaKey key);
byte[] DecryptPkcs1(byte[] ciphertext, RsaKey key);
byte[] EncryptOaep(byte[] data, RsaKey key, RsaOaepHash hash = RsaOaepHash.Sha256);
byte[] DecryptOaep(byte[] ciphertext, RsaKey key, RsaOaepHash hash = RsaOaepHash.Sha256);
byte[] Sign(byte[] data, RsaKey key, RsaSignatureAlgorithm algorithm = RsaSignatureAlgorithm.Sha256WithRsa);
bool Verify(byte[] data, byte[] signature, RsaKey key, RsaSignatureAlgorithm algorithm = RsaSignatureAlgorithm.Sha256WithRsa);
```

`RsaKey` exposes:

```csharp
int  KeySizeBits   { get; }   // the modulus size, e.g. 2048
bool HasPrivateKey { get; }   // false for a public-only handle

static RsaKey ImportPublicKeyPem(string pem);
static RsaKey ImportPrivateKeyPem(string pem, char[]? password = null);

string ExportPublicKeyPem();
string ExportPrivateKeyPem(char[]? password = null);
```

The factory is constructed directly with `new`. The `I*` interfaces are
DI-friendly, so you can also register `PublicKeyServiceFactory` against
`IPublicKeyServiceFactory` in a Microsoft.Extensions.DependencyInjection
container and inject it where needed.

## Which handle can do what

A handle either carries a private key (`HasPrivateKey` is `true`) or only a
public key.

- **A private handle serves every operation.** Its public half is derived from
  the private key's components, so `GenerateRsaKey` hands you a single object
  that both signs and verifies, both decrypts and encrypts.
- **A public-only handle serves the public operations only** — `EncryptPkcs1`,
  `EncryptOaep` and `Verify`. Passing one to `DecryptPkcs1`, `DecryptOaep` or
  `Sign` throws `ArgumentException`.

## Usage

### Generate a key

`GenerateRsaKey` returns one handle, ready to use — nothing needs to be
serialized first.

```csharp
using System;
using Enigma.Core.Asymmetric.PublicKey;

var factory = new PublicKeyServiceFactory();
IPublicKeyService rsa = factory.CreatePublicKeyService();

RsaKey key = rsa.GenerateRsaKey(keySizeBits: 2048);

Console.WriteLine(key.KeySizeBits);    // 2048
Console.WriteLine(key.HasPrivateKey);  // True
```

### Save and load keys

PEM is the storage format. Export what you want to persist or publish, and
import it back into a handle when you need it.

```csharp
using System.IO;
using Enigma.Core.Asymmetric.PublicKey;

var factory = new PublicKeyServiceFactory();
IPublicKeyService rsa = factory.CreatePublicKeyService();

RsaKey key = rsa.GenerateRsaKey();

string publicKeyPem = key.ExportPublicKeyPem();    // "-----BEGIN PUBLIC KEY----- ..."
string privateKeyPem = key.ExportPrivateKeyPem();  // "-----BEGIN PRIVATE KEY----- ..." (unencrypted)

File.WriteAllText("key.pub.pem", publicKeyPem);
File.WriteAllText("key.pem", privateKeyPem);

// ...later, in another process:
RsaKey loaded = RsaKey.ImportPrivateKeyPem(File.ReadAllText("key.pem"));
RsaKey publicOnly = RsaKey.ImportPublicKeyPem(File.ReadAllText("key.pub.pem"));
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

RsaKey key = rsa.GenerateRsaKey();

byte[] plaintext = "attack at dawn".GetUtf8Bytes();

byte[] ciphertext = rsa.EncryptOaep(plaintext, key, RsaOaepHash.Sha256);
byte[] recovered = rsa.DecryptOaep(ciphertext, key, RsaOaepHash.Sha256);

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

RsaKey key = rsa.GenerateRsaKey();

byte[] plaintext = "attack at dawn".GetUtf8Bytes();

byte[] ciphertext = rsa.EncryptPkcs1(plaintext, key);
byte[] recovered = rsa.DecryptPkcs1(ciphertext, key);
```

### Sign and verify

Sign with a private handle and verify with the matching public key, using the
same `RsaSignatureAlgorithm` on both sides. `Verify` returns `true` only when the
signature matches the data.

```csharp
using System;
using Enigma.Core;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Extensions;

var factory = new PublicKeyServiceFactory();
IPublicKeyService rsa = factory.CreatePublicKeyService();

RsaKey signingKey = rsa.GenerateRsaKey();

byte[] message = "release approved".GetUtf8Bytes();

byte[] signature = rsa.Sign(message, signingKey, RsaSignatureAlgorithm.Sha256WithRsa);

// The verifier only needs the public half.
RsaKey verifyingKey = RsaKey.ImportPublicKeyPem(signingKey.ExportPublicKeyPem());
bool valid = rsa.Verify(message, signature, verifyingKey, RsaSignatureAlgorithm.Sha256WithRsa);

Console.WriteLine(valid); // True
```

### Protecting the private key with a passphrase

Pass a `char[]` password to `ExportPrivateKeyPem` to write a PBES2-encrypted
private-key PEM (`ENCRYPTED PRIVATE KEY`, PBKDF2-HMAC-SHA256 + AES-256-CBC), and
the same password to `ImportPrivateKeyPem` to read it back. The passphrase is
needed only for those two calls — never for an operation.

```csharp
using System;
using Enigma.Core;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Extensions;

var factory = new PublicKeyServiceFactory();
IPublicKeyService rsa = factory.CreatePublicKeyService();

char[] password = "correct horse battery staple".ToCharArray();

string protectedPem = rsa.GenerateRsaKey(2048).ExportPrivateKeyPem(password);
// protectedPem -> "-----BEGIN ENCRYPTED PRIVATE KEY----- ..." (PBES2)

// Decrypted once, here. Every later operation just uses the handle.
RsaKey key = RsaKey.ImportPrivateKeyPem(protectedPem, password);

// The library does not clear the password array; clear it yourself when done.
Array.Clear(password, 0, password.Length);

byte[] message = "release approved".GetUtf8Bytes();

byte[] signature = rsa.Sign(message, key, RsaSignatureAlgorithm.Sha256WithRsa);
bool valid = rsa.Verify(message, signature, key);

Console.WriteLine(valid); // True
```

## Migrating from the PEM-string API

In 1.x every method took PEM text, and every private-key operation took the
passphrase again. 2.0.0 replaces that with the `RsaKey` handle. The old members
were **removed outright** — there are no `[Obsolete]` overloads and no
compatibility shims.

| Removed | Replacement |
|---|---|
| `(string, string) GenerateRsaKeyPair(int, char[]?)` | `RsaKey GenerateRsaKey(int)` + `RsaKey.ExportPublicKeyPem()` / `ExportPrivateKeyPem(char[]?)` |
| `EncryptPkcs1(byte[], string)` | `EncryptPkcs1(byte[], RsaKey)` |
| `DecryptPkcs1(byte[], string, char[]?)` | `DecryptPkcs1(byte[], RsaKey)` |
| `EncryptOaep(byte[], string, RsaOaepHash)` | `EncryptOaep(byte[], RsaKey, RsaOaepHash)` |
| `DecryptOaep(byte[], string, RsaOaepHash, char[]?)` | `DecryptOaep(byte[], RsaKey, RsaOaepHash)` |
| `Sign(byte[], string, RsaSignatureAlgorithm, char[]?)` | `Sign(byte[], RsaKey, RsaSignatureAlgorithm)` |
| `Verify(byte[], byte[], string, RsaSignatureAlgorithm)` | `Verify(byte[], byte[], RsaKey, RsaSignatureAlgorithm)` |

### The passphrase moves to the import

This is the change that reshapes calling code. Before, the passphrase travelled
with every private-key call:

```csharp
// 1.x
(string publicKeyPem, string privateKeyPem) = rsa.GenerateRsaKeyPair(2048, password);

byte[] signature = rsa.Sign(message, privateKeyPem, RsaSignatureAlgorithm.Sha256WithRsa, password);
byte[] recovered = rsa.DecryptOaep(ciphertext, privateKeyPem, RsaOaepHash.Sha256, password);
bool valid = rsa.Verify(message, signature, publicKeyPem);
```

Now it is supplied once, where the key is parsed:

```csharp
// 2.0.0
RsaKey key = RsaKey.ImportPrivateKeyPem(privateKeyPem, password);

byte[] signature = rsa.Sign(message, key, RsaSignatureAlgorithm.Sha256WithRsa);
byte[] recovered = rsa.DecryptOaep(ciphertext, key, RsaOaepHash.Sha256);
bool valid = rsa.Verify(message, signature, key);
```

Beyond being shorter, this is the point of the change: parsing an RSA private key
is far more expensive than using it (BouncyCastle validates the CRT components on
construction), and the 1.x API paid that cost on every single call. Import once,
keep the handle.

Two smaller notes on the same example:

- `GenerateRsaKeyPair` became `GenerateRsaKey` because one handle now carries
  both halves — "key pair" no longer described the return value.
- `Verify` accepts the private handle, so a caller that used to keep the
  public-key PEM around purely to verify its own signatures no longer needs to.

### Your existing key files still load

Only the *written* format changed. `ExportPrivateKeyPem(password)` now emits
PBES2 (`ENCRYPTED PRIVATE KEY`) instead of the traditional OpenSSL envelope
(`RSA PRIVATE KEY` with `Proc-Type`/`DEK-Info`), whose key derivation was
OpenSSL's legacy `EVP_BytesToKey` — MD5, a single iteration.

`ImportPrivateKeyPem` reads **all three** forms:

- unencrypted PKCS#8 (`PRIVATE KEY`),
- PBES2-encrypted PKCS#8 (`ENCRYPTED PRIVATE KEY`),
- the traditional OpenSSL envelope, encrypted or not — including files written by
  earlier versions of this library.

So no key file needs converting. To move an old file onto the stronger derivation,
import it and export it again.

### `RsaKey` is not `IDisposable`

Deliberately. BouncyCastle holds RSA private components as arbitrary-precision
integers — immutable managed objects the garbage collector may copy — so there is
no address a `Dispose` could reliably overwrite. Offering one would suggest a
guarantee the runtime cannot make. Treat the lifetime of a private handle as the
lifetime of the secret and keep it as short as the application allows.

## Notes

- **Keys are handles; PEM is the storage format.** Import a PEM once, hold the
  `RsaKey`, and pass it to as many operations as you need. Export only when you
  have to persist, publish or hand a key to another system.
- **A private handle also does the public work.** `Verify`, `EncryptPkcs1` and
  `EncryptOaep` accept either kind of handle. `Sign`, `DecryptPkcs1` and
  `DecryptOaep` require a private one and throw `ArgumentException` otherwise.
- **RSA works on in-memory `byte[]`, not streams.** RSA can only process data
  smaller than the modulus minus the padding overhead, so there is no streaming
  API. To encrypt a large payload, encrypt a symmetric key with RSA and encrypt
  the data with that symmetric key (hybrid encryption).
- **Encrypted private keys.** `ExportPrivateKeyPem()` writes unencrypted PKCS#8
  (`PRIVATE KEY`); `ExportPrivateKeyPem(password)` writes PBES2
  (`ENCRYPTED PRIVATE KEY`, PBKDF2-HMAC-SHA256 at 600 000 iterations +
  AES-256-CBC). That iteration count is why an encrypted import takes noticeably
  longer than an unencrypted one — it is a one-time cost per key, not per
  operation. The library never clears the password array; the caller owns
  clearing it (for example with `Array.Clear`).
- **Failure modes.** A malformed PEM, or one holding the wrong kind of key, is an
  `ArgumentException` from the importer; a wrong or missing passphrase is a
  `CryptographicException`. Exporting a private key from a public-only handle is
  an `InvalidOperationException` — the handle's own state is at fault, not an
  argument. Corrupt ciphertext, a mismatched OAEP hash and data too large for the
  key all surface as `CryptographicException`.
- **Match both sides.** Decrypt with the `RsaOaepHash` used to encrypt, and
  verify with the `RsaSignatureAlgorithm` used to sign. Both default to the
  SHA-256 variant.
