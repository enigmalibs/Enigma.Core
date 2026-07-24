# HMAC

Enigma.Core provides keyed-hash message authentication codes (HMAC) through the
same service + factory pattern as hashing. You create an `HmacServiceFactory`,
ask it for the algorithm you need, and get back an `IHmacService` that computes
an authentication tag over your data using a caller-supplied secret key.

`IHmacService` offers two variants: a synchronous method for in-memory `byte[]`
data, and an asynchronous streaming method for large inputs.

## Supported algorithms

| Algorithm | Factory method | Notes |
|-----------|----------------|-------|
| HMAC-SHA-1 | `CreateHmacSha1Service` | Legacy. Avoid for new work. |
| HMAC-SHA-256 | `CreateHmacSha256Service` | Recommended general-purpose choice. |
| HMAC-SHA-512 | `CreateHmacSha512Service` | Recommended where a longer tag is wanted. |

Every factory method accepts an optional `int bufferSize` parameter that
controls the size of the read buffer used while streaming. It defaults to
`CryptoDefaults.StreamBufferSize` (4096 bytes).

## Key types

| Type | Namespace | Role |
|------|-----------|------|
| `HmacServiceFactory` | `Enigma.Core.Hashing.Hmac` | Concrete factory. Implements `IHmacServiceFactory`. Create with `new`. |
| `IHmacServiceFactory` | `Enigma.Core.Hashing.Hmac` | Factory interface. DI-friendly. |
| `IHmacService` | `Enigma.Core.Hashing.Hmac` | The HMAC service returned by the factory. |
| `RandomUtils` | `Enigma.Core.Utils` | Secure random helper; use it to generate keys. |
| `CryptoDefaults` | `Enigma.Core` | Shared defaults; `StreamBufferSize` is `4096`. |

`IHmacService` exposes two methods:

```csharp
byte[] ComputeHmac(byte[] data, byte[] key);

Task<byte[]> ComputeHmacAsync(
    Stream input,
    byte[] key,
    IProgress<int>? progress = null,
    CancellationToken cancellationToken = default);
```

Both return the raw tag bytes; the tag length is fixed by the algorithm the
service was created for. The secret key is supplied per call, so a single
service instance can authenticate data under different keys. To render a tag as
text, use the `ToHexString()` extension from `Enigma.Core.Extensions`.

The factory is constructed directly with `new`. The `I*` interfaces are
DI-friendly, so you can also register `HmacServiceFactory` against
`IHmacServiceFactory` in a Microsoft.Extensions.DependencyInjection container and
inject it where needed.

## Usage

### In-memory data with a random key

Use `RandomUtils.GenerateRandomBytes` to produce a cryptographically secure key.
A 32-byte (256-bit) key is a good default for HMAC-SHA-256.

```csharp
using System;
using System.Text;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.Utils;
using Enigma.Core.Extensions;

var hmacFactory = new HmacServiceFactory();
IHmacService hmac = hmacFactory.CreateHmacSha256Service();

byte[] key = RandomUtils.GenerateRandomBytes(32);
byte[] data = Encoding.UTF8.GetBytes("message to authenticate");

byte[] tag = hmac.ComputeHmac(data, key);

Console.WriteLine(tag.ToHexString());
```

### Streaming data

For large inputs, stream the data through `ComputeHmacAsync`. It reads the input
stream to its end and returns the tag once complete.

```csharp
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.Utils;
using Enigma.Core.Extensions;

var hmacFactory = new HmacServiceFactory();
IHmacService hmac = hmacFactory.CreateHmacSha256Service();

byte[] key = RandomUtils.GenerateRandomBytes(32);
byte[] data = Encoding.UTF8.GetBytes("a larger message streamed in chunks");
using var input = new MemoryStream(data);

byte[] tag = await hmac.ComputeHmacAsync(input, key);

Console.WriteLine(tag.ToHexString());
```

### Reporting progress and supporting cancellation

`ComputeHmacAsync` accepts an optional `IProgress<int>` that reports the number
of bytes processed, plus a `CancellationToken`. Both are useful when
authenticating large streams such as files.

```csharp
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.Utils;
using Enigma.Core.Extensions;

var hmacFactory = new HmacServiceFactory();
IHmacService hmac = hmacFactory.CreateHmacSha256Service();

byte[] key = RandomUtils.GenerateRandomBytes(32);
var progress = new Progress<int>(bytes => Console.WriteLine($"{bytes} bytes processed"));
using var cts = new CancellationTokenSource();

await using var file = File.OpenRead("large-input.bin");
byte[] tag = await hmac.ComputeHmacAsync(file, key, progress, cts.Token);

Console.WriteLine(tag.ToHexString());
```

## Notes

- HMAC authenticates data with a shared secret; it does not encrypt. Both the
  sender and verifier must hold the same key.
- Keep the key secret and give it enough entropy — a random key at least as long
  as the hash output (for example 32 bytes for HMAC-SHA-256) is a sound choice.
- HMAC-SHA-1 is provided for interoperability with existing systems. Prefer
  HMAC-SHA-256 or HMAC-SHA-512 for new work.
- When verifying a tag, compare in constant time to avoid leaking information
  through timing.
