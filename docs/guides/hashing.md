# Hashing

Enigma.Core provides streaming cryptographic hashing through a small service +
factory API. You create an `HashServiceFactory`, ask it for the algorithm you
need, and get back an `IHashService` that computes a fixed-size digest over any
`Stream`.

All hashing is stream-based and asynchronous, so hashing a multi-gigabyte file
uses the same constant amount of memory as hashing a short string.

## Supported algorithms

| Algorithm | Factory method | Notes |
|-----------|----------------|-------|
| MD5 | `CreateMd5Service` | Legacy / broken. Interop only — never for security. |
| SHA-1 | `CreateSha1Service` | Deprecated. Avoid for new work. |
| SHA-256 | `CreateSha256Service` | Recommended general-purpose digest. |
| SHA-512 | `CreateSha512Service` | Recommended where a longer digest is wanted. |
| SHA-3 | `CreateSha3Service` | FIPS 202. Output size selectable: 224, 256, 384 or 512 bits. |

Every factory method accepts an optional `int bufferSize` parameter that
controls the size of the read buffer used while streaming. It defaults to
`CryptoDefaults.StreamBufferSize` (4096 bytes). `CreateSha3Service` additionally
takes a leading `int bitLength` parameter (default `256`); passing anything
other than 224, 256, 384 or 512 throws `ArgumentException`.

## Key types

| Type | Namespace | Role |
|------|-----------|------|
| `HashServiceFactory` | `Enigma.Core.Hashing.Hash` | Concrete factory. Implements `IHashServiceFactory`. Create with `new`. |
| `IHashServiceFactory` | `Enigma.Core.Hashing.Hash` | Factory interface. DI-friendly. |
| `IHashService` | `Enigma.Core.Hashing.Hash` | The hashing service returned by the factory. |
| `CryptoDefaults` | `Enigma.Core` | Shared defaults; `StreamBufferSize` is `4096`. |

`IHashService` exposes a single method:

```csharp
Task<byte[]> ComputeHashAsync(
    Stream input,
    IProgress<int>? progress = null,
    CancellationToken cancellationToken = default);
```

The result is the raw digest bytes; its length is fixed by the algorithm the
service was created for. To render it as text, use the `ToHexString()` extension
from `Enigma.Core.Extensions`.

The factory is constructed directly with `new`. The `I*` interfaces are
DI-friendly, so you can also register `HashServiceFactory` against
`IHashServiceFactory` in a Microsoft.Extensions.DependencyInjection container and
inject it where needed.

## Usage

### SHA-256 over some UTF-8 text

```csharp
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Enigma.Core.Hashing.Hash;
using Enigma.Core.Extensions;

var factory = new HashServiceFactory();
IHashService sha256 = factory.CreateSha256Service();

byte[] data = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
using var input = new MemoryStream(data);

byte[] digest = await sha256.ComputeHashAsync(input);

Console.WriteLine(digest.ToHexString());
```

### SHA-3 at 512 bits

```csharp
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Enigma.Core.Hashing.Hash;
using Enigma.Core.Extensions;

var factory = new HashServiceFactory();
IHashService sha3 = factory.CreateSha3Service(bitLength: 512);

byte[] data = Encoding.UTF8.GetBytes("hello world");
using var input = new MemoryStream(data);

byte[] digest = await sha3.ComputeHashAsync(input);

Console.WriteLine(digest.ToHexString());
```

### Reporting progress and supporting cancellation

`ComputeHashAsync` accepts an optional `IProgress<int>` that reports the number
of bytes processed, plus a `CancellationToken`. Both are useful when hashing
large streams such as files.

```csharp
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Hashing.Hash;
using Enigma.Core.Extensions;

var factory = new HashServiceFactory();
IHashService sha256 = factory.CreateSha256Service();

var progress = new Progress<int>(bytes => Console.WriteLine($"{bytes} bytes hashed"));
using var cts = new CancellationTokenSource();

await using var file = File.OpenRead("large-input.bin");
byte[] digest = await sha256.ComputeHashAsync(file, progress, cts.Token);

Console.WriteLine(digest.ToHexString());
```

## Notes

- MD5 and SHA-1 are provided for interoperability with existing systems only.
  They are cryptographically broken; prefer SHA-256, SHA-512 or SHA-3 for
  anything security-sensitive.
- The input stream is read to its end. Position it at the start of the data you
  want to hash before calling `ComputeHashAsync`.
- `bufferSize` only affects streaming throughput and memory use; it does not
  change the resulting digest.
