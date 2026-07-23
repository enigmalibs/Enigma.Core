# Stream Ciphers

Enigma.Core provides streaming symmetric encryption backed by BouncyCastle stream cipher
engines, exposed through a small, provider-agnostic surface. You obtain an
`IStreamCipherService` from `StreamCipherServiceFactory`, then call `EncryptAsync` /
`DecryptAsync` with a caller-supplied key and nonce. All types live in the
`Enigma.Core.Symmetric.StreamCiphers` namespace.

## Supported ciphers

| Factory method | Algorithm | Key size | Nonce size |
| --- | --- | --- | --- |
| `CreateChaCha7539Service` | ChaCha20 per RFC 7539 (96-bit nonce, 32-bit counter) | 32 bytes | 12 bytes |
| `CreateChaCha20Service` | Original ChaCha20 (64-bit nonce, 64-bit counter) | 32 bytes | 8 bytes |
| `CreateSalsa20Service` | Salsa20 | 32 bytes | 8 bytes |

Prefer `CreateChaCha7539Service` for new applications: it follows the RFC 7539 standard for
improved interoperability and security. The original ChaCha20 and Salsa20 services are
available for compatibility with existing data.

## Key types

- **`IStreamCipherServiceFactory`** — factory abstraction. The concrete
  `StreamCipherServiceFactory` is a parameterless, sealed implementation.
- **`IStreamCipherService`** — the cipher service returned by the factory. It exposes
  `EncryptAsync` and `DecryptAsync`, which share an identical signature.
- **`CryptoDefaults.StreamBufferSize`** — the default internal buffer size (`4096` bytes),
  defined in the `Enigma.Core` namespace. Every factory method takes an optional
  `int bufferSize = CryptoDefaults.StreamBufferSize` parameter.

Each factory method has the signature:

```csharp
IStreamCipherService CreateChaCha7539Service(int bufferSize = CryptoDefaults.StreamBufferSize);
IStreamCipherService CreateChaCha20Service(int bufferSize = CryptoDefaults.StreamBufferSize);
IStreamCipherService CreateSalsa20Service(int bufferSize = CryptoDefaults.StreamBufferSize);
```

`IStreamCipherService` exposes:

```csharp
Task EncryptAsync(
    Stream input,
    Stream output,
    byte[] key,
    byte[] nonce,
    IProgress<int>? progress = null,
    CancellationToken cancellationToken = default);

Task DecryptAsync(
    Stream input,
    Stream output,
    byte[] key,
    byte[] nonce,
    IProgress<int>? progress = null,
    CancellationToken cancellationToken = default);
```

Both methods stream from `input` to `output`. The optional `IProgress<int>? progress`
argument reports the number of bytes processed per chunk, and the optional
`CancellationToken` cancels a long-running operation. Neither stream is disposed by the
service — the caller owns the streams.

## Usage

The example below encrypts a plaintext buffer with ChaCha20-RFC7539 and decrypts it back,
using in-memory streams. The key is 32 bytes and the nonce is 12 bytes, both generated with
`RandomUtils`.

```csharp
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Enigma.Core.Symmetric.StreamCiphers;
using Enigma.Core.Utils;

// Factories are created with `new`. The IStreamCipherServiceFactory interface is
// DI-friendly, so you may also register StreamCipherServiceFactory in a container.
var factory = new StreamCipherServiceFactory();
IStreamCipherService cipher = factory.CreateChaCha7539Service();

// ChaCha20-RFC7539: 32-byte key, 12-byte nonce.
byte[] key = RandomUtils.GenerateRandomBytes(32);
byte[] nonce = RandomUtils.GenerateRandomBytes(12);

byte[] plaintext = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog.");

// --- Encrypt ---
using var plainInput = new MemoryStream(plaintext);
using var cipherOutput = new MemoryStream();
await cipher.EncryptAsync(plainInput, cipherOutput, key, nonce);
byte[] ciphertext = cipherOutput.ToArray();

// --- Decrypt (reuse the same key and nonce) ---
using var cipherInput = new MemoryStream(ciphertext);
using var plainOutput = new MemoryStream();
await cipher.DecryptAsync(cipherInput, plainOutput, key, nonce);

string recovered = Encoding.UTF8.GetString(plainOutput.ToArray());
Console.WriteLine(recovered); // The quick brown fox jumps over the lazy dog.
```

To report progress or support cancellation — useful when encrypting large files — pass the
optional arguments:

```csharp
using System;
using System.Threading;

var progress = new Progress<int>(bytes => Console.WriteLine($"Processed {bytes} bytes"));
using var cts = new CancellationTokenSource();

await cipher.EncryptAsync(plainInput, cipherOutput, key, nonce, progress, cts.Token);
```

## Notes

- **Nonce sizes are per cipher.** RFC 7539 ChaCha20 uses a **12-byte** nonce; the original
  ChaCha20 and Salsa20 use an **8-byte** nonce. All three use a **32-byte** key. Supplying a
  nonce of the wrong length surfaces as a `CryptographicException`.
- **Never reuse a nonce with the same key.** Stream ciphers are catastrophically weakened by
  nonce reuse: two messages encrypted under the same key and nonce leak the XOR of their
  plaintexts. Generate a fresh nonce for every encryption (for example with
  `RandomUtils.GenerateRandomBytes`) and transmit or store it alongside the ciphertext — the
  nonce is not secret.
- **Decryption reuses the encryption key and nonce.** Use the exact key/nonce pair that
  produced the ciphertext.
- **Streams are not disposed by the service.** Dispose the streams you create (the `using`
  statements above handle this).
- **These are unauthenticated ciphers.** They provide confidentiality but not integrity. If
  you need tamper detection, combine the ciphertext with a MAC or use an authenticated mode.
