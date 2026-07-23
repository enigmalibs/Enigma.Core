# Padding

Enigma.Core exposes standalone byte-padding primitives for aligning data to a block boundary.
You obtain an `IPaddingService` from `PaddingServiceFactory`, then call `Pad` / `Unpad`. All
types live in the `Enigma.Core.Padding` namespace and hide the underlying BouncyCastle padding
implementations.

## Supported schemes

| Factory method | Scheme | Description |
| --- | --- | --- |
| `CreateNoPaddingService` | None | No padding. The data must already be a whole number of blocks. |
| `CreatePkcs7Service` | PKCS#7 (a.k.a. PKCS#5 for 8-byte blocks) | Appends N bytes each of value N, where N completes the block. The most widely used scheme. |
| `CreateIso7816Service` | ISO/IEC 7816-4 | Appends a single `0x80` byte followed by zero bytes (`0x00`). Also known as scheme 2 of ISO/IEC 9797-1. |
| `CreateIso10126Service` | ISO 10126-2 | Fills the padding with random bytes; the final byte gives the padding length. |
| `CreateX923Service` | ANSI X9.23 | Fills the padding with zero bytes; the final byte gives the padding length. |

## Key types

- **`IPaddingServiceFactory`** — factory abstraction. The concrete `PaddingServiceFactory` is
  a parameterless, sealed implementation.
- **`IPaddingService`** — the padding service returned by the factory:

  ```csharp
  byte[] Pad(byte[] data, int blockSize);
  byte[] Unpad(byte[] data, int blockSize);
  ```

  `Pad` returns a new array containing the original data plus padding so the total length is a
  multiple of `blockSize` (in bytes). `Unpad` reverses this, returning a new array with the
  padding removed. `blockSize` must be between `1` and `255` inclusive.

- **`enum PaddingScheme { None, Pkcs7, Iso7816, Iso10126, X923 }`** — defined in the same
  `Enigma.Core.Padding` namespace. This enum is what you pass to the **block-cipher service**
  when configuring a block-aligned mode (ECB/CBC) so it can pad internally. It is a separate
  concern from the `IPaddingService` / `PaddingServiceFactory` primitives documented here,
  which are the standalone pad/unpad operations you call directly.

## Usage

The example below pads a byte array to a 16-byte block with PKCS#7, then unpads it back to the
original bytes.

```csharp
using System;
using System.Linq;
using System.Text;
using Enigma.Core.Padding;

// Factories are created with `new`. The IPaddingServiceFactory interface is DI-friendly, so
// you may also register PaddingServiceFactory in a container.
var padFactory = new PaddingServiceFactory();
IPaddingService padding = padFactory.CreatePkcs7Service();

const int blockSize = 16;
byte[] data = Encoding.UTF8.GetBytes("hello"); // 5 bytes

// --- Pad ---
byte[] padded = padding.Pad(data, blockSize);
Console.WriteLine(padded.Length); // 16 (5 data bytes + 11 padding bytes of value 0x0B)

// --- Unpad ---
byte[] unpadded = padding.Unpad(padded, blockSize);
Console.WriteLine(Encoding.UTF8.GetString(unpadded));        // hello
Console.WriteLine(unpadded.SequenceEqual(data));             // True
```

Selecting a different scheme is just a matter of choosing a different factory method:

```csharp
using Enigma.Core.Padding;

var padFactory = new PaddingServiceFactory();

IPaddingService none     = padFactory.CreateNoPaddingService();
IPaddingService pkcs7    = padFactory.CreatePkcs7Service();
IPaddingService iso7816  = padFactory.CreateIso7816Service();
IPaddingService iso10126 = padFactory.CreateIso10126Service();
IPaddingService x923     = padFactory.CreateX923Service();
```

## Notes

- **PKCS#7 vs PKCS#5.** They are the same algorithm; "PKCS#5" is the name used when the block
  size is 8 bytes. `CreatePkcs7Service` covers both.
- **`None` returns data unchanged.** `CreateNoPaddingService` accepts a `blockSize` argument
  for interface symmetry but ignores it — the caller is responsible for supplying
  block-aligned data.
- **PKCS#7 always adds a full block when already aligned.** If the input length is already a
  multiple of `blockSize`, an entire extra block of padding is appended so that `Unpad` can
  unambiguously recover the original data. (This applies to the length-encoding schemes;
  `None` never adds bytes.)
- **`blockSize` range.** Valid block sizes are `1` to `255`. Values outside this range throw
  `ArgumentException`.
- **Enum vs primitives.** Pass `PaddingScheme` to the block-cipher service for ECB/CBC modes;
  use the `IPaddingService` primitives here when you need to pad or unpad a buffer yourself.
