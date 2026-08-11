# Checksums (CRC)

Enigma.Core computes cyclic-redundancy-check (CRC) values through the same
service + factory API as the rest of the library. You create a
`ChecksumServiceFactory`, ask it for the CRC variant you need, and get back an
`IChecksumService` that produces the checksum of a `byte[]` or of a `Stream`.

Seven variants ship: five CRC-16 and two CRC-32. Every value is available in two
shapes — as bytes, for writing into a frame or a file header, and as a `uint`,
for comparing against a stored value.

> **A CRC is not a security primitive.** It detects accidental corruption —
> transmission errors, bit rot, truncated downloads — and nothing else. Anyone
> who can change the data can recompute a matching checksum, and collisions are
> trivial to construct on purpose. When integrity has to hold against an
> adversary, use an HMAC (see the [HMAC guide](hmac.md)) or a signature, never a
> checksum. This is why the checksum services live in their own namespace and do
> **not** implement `IHashService`: a CRC must never be substitutable for a
> cryptographic digest.

## Supported variants

| Variant | Factory method | Poly | Init | Reflected | XorOut | Check |
|---------|----------------|------|------|-----------|--------|-------|
| CRC-16/ARC | `CreateCrc16ArcService` | 0x8005 | 0x0000 | yes | 0x0000 | `0xBB3D` |
| CRC-16/IBM-3740 | `CreateCrc16CcittFalseService` | 0x1021 | 0xFFFF | no | 0x0000 | `0x29B1` |
| CRC-16/XMODEM | `CreateCrc16XmodemService` | 0x1021 | 0x0000 | no | 0x0000 | `0x31C3` |
| CRC-16/MODBUS | `CreateCrc16ModbusService` | 0x8005 | 0xFFFF | yes | 0x0000 | `0x4B37` |
| CRC-16/KERMIT | `CreateCrc16KermitService` | 0x1021 | 0x0000 | yes | 0x0000 | `0x2189` |
| CRC-32/ISO-HDLC | `CreateCrc32IsoHdlcService` | 0x04C11DB7 | 0xFFFFFFFF | yes | 0xFFFFFFFF | `0xCBF43926` |
| CRC-32C | `CreateCrc32CService` | 0x1EDC6F41 | 0xFFFFFFFF | yes | 0xFFFFFFFF | `0xE3069283` |

*Check* is the catalogue check value: the CRC of the ASCII bytes of
`"123456789"`. Use it to confirm you picked the same variant as the system you
are exchanging data with.

The same variants under the names you may know them by:

| Factory method | Also published as |
|----------------|-------------------|
| `CreateCrc16ArcService` | CRC-16, CRC-IBM, CRC-16/LHA, CRC-16/ZMODEM |
| `CreateCrc16CcittFalseService` | CRC-16/CCITT-FALSE |
| `CreateCrc16XmodemService` | CRC-16/ZMODEM, CRC-16/ACORN |
| `CreateCrc16ModbusService` | the Modbus RTU frame check |
| `CreateCrc16KermitService` | CRC-16/CCITT, CRC-16/CCITT-TRUE, CRC-16/V-41-LSB |
| `CreateCrc32IsoHdlcService` | CRC-32 (unqualified), zip / gzip / PNG / Ethernet CRC |
| `CreateCrc32CService` | Castagnoli, iSCSI, SCTP, ext4 metadata |

There is deliberately no `CreateCrc16Service` or `CreateCrc32Service`. "CRC-16"
and "CRC-32" each name a *family* of mutually incompatible parameter sets, so a
bare method would have to bind silently to one of them — and produce a value the
system on the other end cannot verify. Name the variant you mean.

Every factory method accepts an optional `int bufferSize` that controls the read
buffer used while streaming. It defaults to `CryptoDefaults.StreamBufferSize`
(4096 bytes) and never changes the resulting checksum. A value of zero or less
throws `ArgumentOutOfRangeException` at creation.

## Key types

| Type | Namespace | Role |
|------|-----------|------|
| `ChecksumServiceFactory` | `Enigma.Core.Checksum` | Concrete factory. Implements `IChecksumServiceFactory`. Create with `new`. |
| `IChecksumServiceFactory` | `Enigma.Core.Checksum` | Factory interface. DI-friendly. |
| `IChecksumService` | `Enigma.Core.Checksum` | The checksum service returned by the factory. |
| `Crc16Service` | `Enigma.Core.Checksum` | 16-bit implementation. Created by the factory only. |
| `Crc32Service` | `Enigma.Core.Checksum` | 32-bit implementation. Created by the factory only. |
| `CryptoDefaults` | `Enigma.Core` | Shared defaults; `StreamBufferSize` is `4096`. |

`IChecksumService` exposes the checksum size plus four compute methods — two
shapes, each synchronous for buffers and asynchronous for streams:

```csharp
int ChecksumSize { get; }

byte[] ComputeChecksum(byte[] data);
uint ComputeChecksumValue(byte[] data);

Task<byte[]> ComputeChecksumAsync(
    Stream input,
    IProgress<int>? progress = null,
    CancellationToken cancellationToken = default);

Task<uint> ComputeChecksumValueAsync(
    Stream input,
    IProgress<int>? progress = null,
    CancellationToken cancellationToken = default);
```

- `ChecksumSize` is `2` for a CRC-16 and `4` for a CRC-32.
- `ComputeChecksum` returns **big-endian** bytes (most-significant byte first) of
  exactly `ChecksumSize` length.
- `ComputeChecksumValue` returns the same value as a `uint`. For a CRC-16 it sits
  in the low 16 bits and the high 16 bits are zero.
- The byte and value shapes always agree, and so do the synchronous and
  asynchronous paths for the same input.
- The services keep no per-call state and their lookup tables are immutable, so a
  single instance is safe to share across threads.

The factory is constructed directly with `new`. The `I*` interfaces are
DI-friendly, so you can also register `ChecksumServiceFactory` against
`IChecksumServiceFactory` in a Microsoft.Extensions.DependencyInjection container
and inject it where needed.

## Usage

### CRC-32 of some UTF-8 text

```csharp
using System;
using System.Text;
using Enigma.Core.Checksum;

var factory = new ChecksumServiceFactory();
IChecksumService crc32 = factory.CreateCrc32IsoHdlcService();

byte[] data = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");

uint value = crc32.ComputeChecksumValue(data);

Console.WriteLine(value.ToString("X8")); // 414FA339
```

### Streaming a file, with progress and cancellation

`ComputeChecksumAsync` and `ComputeChecksumValueAsync` read the stream to its
end, reporting the bytes consumed by each read through the optional
`IProgress<int>` and honouring the `CancellationToken`.

```csharp
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Checksum;
using Enigma.Core.Extensions;

var factory = new ChecksumServiceFactory();
IChecksumService crc32 = factory.CreateCrc32IsoHdlcService();

var progress = new Progress<int>(bytes => Console.WriteLine($"{bytes} bytes read"));
using var cts = new CancellationTokenSource();

using var file = File.OpenRead("large-input.bin");
byte[] checksum = await crc32.ComputeChecksumAsync(file, progress, cts.Token);

Console.WriteLine(checksum.ToHexString()); // big-endian, 4 bytes
```

### Verifying a stored checksum

Compare the numeric shape — it is the one that reads naturally and avoids any
byte-order question.

```csharp
using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.Core.Checksum;

var factory = new ChecksumServiceFactory();
IChecksumService crc32c = factory.CreateCrc32CService();

const uint expected = 0xE3069283; // recorded when the payload was written

using var file = File.OpenRead("payload.bin");
uint actual = await crc32c.ComputeChecksumValueAsync(file);

Console.WriteLine(actual == expected ? "intact" : "corrupted");
```

### A Modbus RTU frame check

`ComputeChecksum` returns big-endian bytes. Modbus RTU appends its CRC
**low byte first**, so reverse the two bytes on the way out — a good illustration
of why the byte order is documented rather than left to chance.

```csharp
using System;
using Enigma.Core.Checksum;

var factory = new ChecksumServiceFactory();
IChecksumService modbus = factory.CreateCrc16ModbusService();

// Slave 0x01, function 0x03 (read holding registers), start 0x0000, count 0x000A.
byte[] frame = [0x01, 0x03, 0x00, 0x00, 0x00, 0x0A];

byte[] bigEndian = modbus.ComputeChecksum(frame);      // [0xCD, 0xC5]
byte[] onTheWire = [bigEndian[1], bigEndian[0]];       // Modbus order: [0xC5, 0xCD]

Console.WriteLine(modbus.ComputeChecksumValue(frame).ToString("X4")); // CDC5
Console.WriteLine(onTheWire.Length);                                  // 2
```

## Notes

- Pick the variant by name, and confirm it against the check value in the table
  above before exchanging data with another system. Two CRC-32s of the same width
  (ISO-HDLC and CRC-32C) produce completely different values for the same input.
- The input stream is read to its end. Position it at the start of the data you
  want to checksum before calling either async method.
- `bufferSize` affects only streaming throughput and memory use; it never changes
  the resulting checksum.
- Passing `null` data or a `null` stream throws `ArgumentNullException`. An empty
  input is valid and yields the variant's `Init ^ XorOut` value.
- The implementation is pure managed code, table-driven, and identical on every
  target framework. There is no hardware-intrinsics path.
