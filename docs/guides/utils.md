# Utilities & Defaults

Two small building blocks underpin the rest of Enigma.Core: a cryptographically
secure random-byte generator and a set of shared default constants. Both are
static, so there is no service or factory to construct.

## RandomUtils

`RandomUtils` lives in `Enigma.Core.Utils` and generates cryptographically secure
random bytes, backed by BouncyCastle's `SecureRandom`. Use it for keys, salts,
nonces and IVs — anything that must be unpredictable.

```csharp
static byte[] GenerateRandomBytes(int size);
```

- `size` is the number of bytes to generate.
- Throws `ArgumentException` when `size <= 0`.

Because it is seeded from a cryptographic source, do not use it as a drop-in for
`System.Random`-style, reproducible sequences — every call returns fresh,
unpredictable bytes.

## CryptoDefaults

`CryptoDefaults` lives in the root `Enigma.Core` namespace and exposes the
canonical default values the library shares, so callers can reference the same
constants instead of hard-coding magic numbers.

```csharp
public const int StreamBufferSize = 4096;
```

`StreamBufferSize` (4096 bytes, 4 KiB) is the default stream-processing buffer
size shared by the block ciphers, stream ciphers, hashing and HMAC. The relevant
`Create…Service` factory methods accept a `bufferSize` argument; pass
`CryptoDefaults.StreamBufferSize` to reuse the library default explicitly, or
pass your own value to tune throughput and memory use.

## Usage

### Generate a 32-byte key

```csharp
using System;
using Enigma.Core.Utils;

byte[] key = RandomUtils.GenerateRandomBytes(32);

Console.WriteLine(key.Length); // 32
```

### Reference the shared buffer-size default

```csharp
using System;
using Enigma.Core;

int bufferSize = CryptoDefaults.StreamBufferSize;

Console.WriteLine(bufferSize); // 4096
```

`CryptoDefaults.StreamBufferSize` is the value factory methods fall back to when
you do not supply a `bufferSize`, so passing it explicitly is equivalent to
accepting the default — it just makes the choice visible at the call site.

## Notes

- `GenerateRandomBytes` is cryptographically secure; prefer it over
  `System.Random` for any security-sensitive value.
- `size` must be greater than zero; a value of `0` or below throws
  `ArgumentException`.
- Adjusting `bufferSize` only affects streaming throughput and memory use, never
  the cryptographic result.
