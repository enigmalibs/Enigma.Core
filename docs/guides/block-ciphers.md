# Block Ciphers

Enigma.Core exposes symmetric block cipher encryption through a small service/factory pattern: create an `IBlockCipherService` for the algorithm you want from `BlockCipherServiceFactory`, then call `EncryptAsync` / `DecryptAsync` over streams, supplying the key, IV/nonce, mode of operation and padding per call. All engines are BouncyCastle-backed.

## Supported algorithms & modes

Create a service for an algorithm with the matching factory method on `BlockCipherServiceFactory`. Twelve engines are available:

| Algorithm | Factory method |
| --- | --- |
| AES | `CreateAesService()` |
| DES | `CreateDesService()` |
| Triple DES (3DES / DESede) | `CreateTripleDesService()` |
| Blowfish | `CreateBlowfishService()` |
| Twofish | `CreateTwofishService()` |
| Serpent | `CreateSerpentService()` |
| Camellia | `CreateCamelliaService()` |
| CAST-128 (CAST5) | `CreateCast128Service()` |
| IDEA | `CreateIdeaService()` |
| SEED | `CreateSeedService()` |
| ARIA | `CreateAriaService()` |
| SM4 | `CreateSm4Service()` |

Each factory method accepts an optional `int bufferSize = CryptoDefaults.StreamBufferSize` (4096 bytes) that sizes the internal stream-processing buffer.

The mode of operation is chosen per call via `BlockCipherMode`:

| Mode | Meaning | IV/nonce | Padding |
| --- | --- | --- | --- |
| `BlockCipherMode.Ecb` | Electronic Code Book | not used (`null`) | required |
| `BlockCipherMode.Cbc` | Cipher Block Chaining | required, random & unique | required |
| `BlockCipherMode.Ctr` | Counter (stream-like) | required | not used |
| `BlockCipherMode.Gcm` | Galois/Counter Mode (authenticated) | required | not used |

Padding schemes are selected with `PaddingScheme` (from `Enigma.Core.Padding`): `None`, `Pkcs7` (default), `Iso7816`, `Iso10126`, `X923`.

## Key types

Keys, IVs and nonces are plain `byte[]` supplied by the caller — the service holds no key state. Generate cryptographically strong material with `Enigma.Core.Utils.RandomUtils.GenerateRandomBytes(int size)`.

- **AES key sizes:** 16, 24 or 32 bytes (AES-128 / AES-192 / AES-256).
- **AES block size:** 16 bytes — the CBC IV length. For GCM a 12-byte nonce is conventional.

Other engines use their own key and block sizes; size the key and IV/nonce to the algorithm you selected.

## Usage

Construct the factory directly with `new` — the factory is a plain class, there is no DI-container helper. (The `IBlockCipherServiceFactory` / `IBlockCipherService` interfaces are DI-registration-friendly if you want to register them in your own container.)

```csharp
using Enigma.Core.Symmetric.BlockCiphers;

var factory = new BlockCipherServiceFactory();
IBlockCipherService aes = factory.CreateAesService();
```

### Example 1 — AES-CBC encrypt then decrypt

```csharp
using System.IO;
using System.Threading.Tasks;
using Enigma.Core.Padding;
using Enigma.Core.Symmetric.BlockCiphers;
using Enigma.Core.Utils;

var factory = new BlockCipherServiceFactory();
IBlockCipherService aes = factory.CreateAesService();

// AES-256 key + a random, unique 16-byte IV (AES block size).
byte[] key = RandomUtils.GenerateRandomBytes(32);
byte[] iv = RandomUtils.GenerateRandomBytes(16);

byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("Attack at dawn.");

// Encrypt.
using var plainIn = new MemoryStream(plaintext);
using var cipherOut = new MemoryStream();
await aes.EncryptAsync(
    plainIn,
    cipherOut,
    key,
    iv,
    BlockCipherMode.Cbc,
    PaddingScheme.Pkcs7);

byte[] ciphertext = cipherOut.ToArray();

// Decrypt with the same key, IV, mode and padding.
using var cipherIn = new MemoryStream(ciphertext);
using var plainOut = new MemoryStream();
await aes.DecryptAsync(
    cipherIn,
    plainOut,
    key,
    iv,
    BlockCipherMode.Cbc,
    PaddingScheme.Pkcs7);

byte[] roundTripped = plainOut.ToArray(); // equals plaintext
```

### Example 2 — AES-GCM with associated data (AAD)

GCM is authenticated encryption: it produces an authentication tag and can bind extra "associated data" that is authenticated but not encrypted. The same nonce, AAD and tag size must be supplied on decryption or authentication fails (surfacing as a `System.Security.Cryptography.CryptographicException`).

```csharp
using System.IO;
using System.Threading.Tasks;
using Enigma.Core.Padding;
using Enigma.Core.Symmetric.BlockCiphers;
using Enigma.Core.Utils;

var factory = new BlockCipherServiceFactory();
IBlockCipherService aes = factory.CreateAesService();

byte[] key = RandomUtils.GenerateRandomBytes(32);
byte[] nonce = RandomUtils.GenerateRandomBytes(12); // 12-byte nonce is conventional for GCM

byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("Attack at dawn.");
byte[] aad = System.Text.Encoding.UTF8.GetBytes("message-id:42"); // authenticated, not encrypted

// Encrypt: no padding for GCM; tag size defaults to GcmMacSize.MaxBits (128 bits).
using var plainIn = new MemoryStream(plaintext);
using var cipherOut = new MemoryStream();
await aes.EncryptAsync(
    plainIn,
    cipherOut,
    key,
    nonce,
    BlockCipherMode.Gcm,
    PaddingScheme.None,
    gcmMacSizeBits: GcmMacSize.MaxBits,
    associatedData: aad);

byte[] ciphertext = cipherOut.ToArray();

// Decrypt: nonce, tag size and AAD must match exactly.
using var cipherIn = new MemoryStream(ciphertext);
using var plainOut = new MemoryStream();
await aes.DecryptAsync(
    cipherIn,
    plainOut,
    key,
    nonce,
    BlockCipherMode.Gcm,
    PaddingScheme.None,
    gcmMacSizeBits: GcmMacSize.MaxBits,
    associatedData: aad);

byte[] roundTripped = plainOut.ToArray(); // equals plaintext
```

## Notes

### Async, progress & cancellation

Both `EncryptAsync` and `DecryptAsync` are fully asynchronous and stream-based, so they scale to large payloads without loading everything into memory. Each accepts two trailing optional parameters:

- `IProgress<int>? progress = null` — reports bytes processed as the operation runs; pass an `IProgress<int>` implementation (for example, `new Progress<int>(bytes => ...)`) to drive a progress bar.
- `CancellationToken cancellationToken = default` — pass a token to cancel a long-running operation.

```csharp
var progress = new Progress<int>(bytes => Console.WriteLine($"{bytes} bytes processed"));

await aes.EncryptAsync(
    plainIn,
    cipherOut,
    key,
    iv,
    BlockCipherMode.Cbc,
    PaddingScheme.Pkcs7,
    progress: progress,
    cancellationToken: cancellationToken);
```

### IV / nonce & padding rules per mode

- **ECB** — requires padding (e.g. `PaddingScheme.Pkcs7`); pass `iv: null`. ECB is not recommended beyond a single block: identical plaintext blocks yield identical ciphertext blocks.
- **CBC** — requires a random, unique IV (16 bytes for AES, matching the block size) **and** padding. Never reuse an IV with the same key. The IV need not be secret; store or transmit it alongside the ciphertext.
- **CTR** — requires an IV/nonce and needs no padding; the `padding` argument is ignored for this mode.
- **GCM** — authenticated encryption. Requires an IV/nonce (a 12-byte nonce is conventional), needs no padding, and produces an authentication tag. Never reuse a nonce with the same key.

Use the same `key`, `iv`, `mode` and `padding` for decryption as were used for encryption.

### GCM tag size & associated data

`gcmMacSizeBits` and `associatedData` apply to `BlockCipherMode.Gcm` only.

- `gcmMacSizeBits` sets the authentication tag size in bits; it defaults to `GcmMacSize.MaxBits` (128). A valid value is a multiple of 8 in the inclusive range [`GcmMacSize.MinBits`, `GcmMacSize.MaxBits`] = [32, 128] — check a candidate with `GcmMacSize.IsValid(int bits)`, and see `GcmMacSize.RangeDescription` for a ready-made error message. The same tag size must be used on decryption.
- `associatedData` (AAD) is authenticated but not encrypted. Supply the identical value on encryption and decryption; a mismatch (or tampering with the ciphertext or tag) fails authentication and surfaces as a `System.Security.Cryptography.CryptographicException`.

For the non-authenticated modes (`Ecb`, `Cbc`, `Ctr`), leave `associatedData` as `null` (or empty) and leave `gcmMacSizeBits` at its default — both are ignored.
