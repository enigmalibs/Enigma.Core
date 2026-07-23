# Extensions

The `Enigma.Core.Extensions` namespace ships two sets of C# extension methods.
Add a single `using Enigma.Core.Extensions;` and they light up as instance
methods on the types they extend — no factory, no service to construct.

- `EncodingExtensions` — convenience wrappers over the Base64, Hex and Base32
  encoders plus UTF-8/ASCII text conversion, on `byte[]` and `string`.
- `StreamExtensions` — typed binary read/write helpers on `System.IO.Stream`,
  each available in a synchronous and an asynchronous form.

## EncodingExtensions

These methods let you go straight from a `byte[]` to encoded text (and back)
without touching the encoding factory.

On `byte[]`:

| Method | Returns | Notes |
|--------|---------|-------|
| `ToBase64String()` | `string` | Base64 text. |
| `ToHexString()` | `string` | Hexadecimal text. |
| `ToBase32String()` | `string` | Base32 (RFC 4648, padded). |
| `GetString(System.Text.Encoding? encoding = null)` | `string` | Decode bytes to text; `null` ⇒ UTF-8. |
| `GetUtf8String()` | `string` | Decode bytes as UTF-8. |
| `GetAsciiString()` | `string` | Decode bytes as ASCII. |

On `string`:

| Method | Returns | Notes |
|--------|---------|-------|
| `FromBase64String()` | `byte[]` | Decode Base64 text. |
| `FromHexString()` | `byte[]` | Decode hexadecimal text. |
| `FromBase32String()` | `byte[]` | Decode Base32; tolerant of case, whitespace and missing padding. |
| `GetBytes(System.Text.Encoding? encoding = null)` | `byte[]` | Encode text to bytes; `null` ⇒ UTF-8. |
| `GetUtf8Bytes()` | `byte[]` | Encode text as UTF-8. |
| `GetAsciiBytes()` | `byte[]` | Encode text as ASCII. |

The text helpers standardise on UTF-8 rather than `Encoding.Default`.
`Encoding.Default` resolves to UTF-8 on modern .NET but to the system ANSI code
page on netstandard2.0/.NET Framework, so the same call could otherwise produce
different bytes across target frameworks. Defaulting to UTF-8 keeps results
identical everywhere.

## StreamExtensions

`StreamExtensions` adds typed binary read/write helpers to any
`System.IO.Stream`. Every helper has a synchronous form and an asynchronous
`…Async` form whose last parameter is
`CancellationToken cancellationToken = default`.

Write helpers:

| Sync | Async | Payload |
|------|-------|---------|
| `WriteBool(bool)` | `WriteBoolAsync(bool, …)` | 1-byte boolean. |
| `WriteBytes(byte[])` | `WriteBytesAsync(byte[], …)` | Raw bytes. |
| `WriteShort(short)` | `WriteShortAsync(short, …)` | Int16. |
| `WriteUShort(ushort)` | `WriteUShortAsync(ushort, …)` | UInt16. |
| `WriteInt(int)` | `WriteIntAsync(int, …)` | Int32. |
| `WriteUInt(uint)` | `WriteUIntAsync(uint, …)` | UInt32. |
| `WriteLong(long)` | `WriteLongAsync(long, …)` | Int64. |
| `WriteULong(ulong)` | `WriteULongAsync(ulong, …)` | UInt64. |
| `WriteFloat(float)` | `WriteFloatAsync(float, …)` | Single. |
| `WriteDouble(double)` | `WriteDoubleAsync(double, …)` | Double. |
| `WriteLengthValue(byte[])` | `WriteLengthValueAsync(byte[], …)` | Length prefix + bytes. |
| `WriteTagLengthValue(ushort tag, byte[] value)` | `WriteTagLengthValueAsync(ushort tag, byte[] value, …)` | Tag + length + bytes (TLV). |
| — | `WriteByteAsync(byte, …)` | Single byte (async only). |

Read helpers:

| Sync | Async | Returns |
|------|-------|---------|
| `ReadBool()` | `ReadBoolAsync(…)` | `bool` |
| `ReadBytes(int count)` | `ReadBytesAsync(int count, …)` | `byte[]` |
| `ReadShort()` | `ReadShortAsync(…)` | `short` |
| `ReadUShort()` | `ReadUShortAsync(…)` | `ushort` |
| `ReadInt()` | `ReadIntAsync(…)` | `int` |
| `ReadUInt()` | `ReadUIntAsync(…)` | `uint` |
| `ReadLong()` | `ReadLongAsync(…)` | `long` |
| `ReadULong()` | `ReadULongAsync(…)` | `ulong` |
| `ReadFloat()` | `ReadFloatAsync(…)` | `float` |
| `ReadDouble()` | `ReadDoubleAsync(…)` | `double` |
| `ReadLengthValue(int maxLength = 10*1024*1024)` | `ReadLengthValueAsync(int maxLength = 10*1024*1024, …)` | `byte[]` |
| `ReadTagLengthValue(int maxLength = 10*1024*1024)` | `ReadTagLengthValueAsync(int maxLength = 10*1024*1024, …)` | `(ushort tag, byte[] value)` |
| — | `ReadByteAsync(…)` | `byte` (async only) |

`WriteLengthValue`/`ReadLengthValue` write a length prefix followed by the bytes,
so the reader knows exactly how many bytes to consume.
`WriteTagLengthValue`/`ReadTagLengthValue` prepend a `ushort` tag before the
length and value — a simple tag-length-value (TLV) record. The read side of both
takes a `maxLength` guard (default 10 MB) that bounds how large an allocation an
incoming length field can request.

There is no synchronous `WriteByte(byte)`/`ReadByte()` extension: `Stream`
already exposes instance methods with those names, so the single-byte helpers are
provided only in their async forms (`WriteByteAsync`, `ReadByteAsync`).

## Usage

### Round-trip a byte[] as hex

```csharp
using System;
using Enigma.Core.Extensions;

byte[] original = { 0xDE, 0xAD, 0xBE, 0xEF };

string hex = original.ToHexString();
byte[] restored = hex.FromHexString();

Console.WriteLine(hex);                             // DEADBEEF-style hex text
Console.WriteLine(restored.Length == original.Length); // True
```

### Write and read typed values on a MemoryStream (sync)

```csharp
using System;
using System.IO;
using Enigma.Core.Extensions;

using var stream = new MemoryStream();

stream.WriteInt(42);
stream.WriteBool(true);
stream.WriteLengthValue(new byte[] { 1, 2, 3, 4 });

stream.Position = 0; // rewind before reading

int number = stream.ReadInt();
bool flag = stream.ReadBool();
byte[] payload = stream.ReadLengthValue();

Console.WriteLine(number);         // 42
Console.WriteLine(flag);           // True
Console.WriteLine(payload.Length); // 4
```

### The same round-trip, asynchronously

```csharp
using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.Core.Extensions;

using var stream = new MemoryStream();

await stream.WriteIntAsync(42);
await stream.WriteBoolAsync(true);
await stream.WriteLengthValueAsync(new byte[] { 1, 2, 3, 4 });

stream.Position = 0; // rewind before reading

int number = await stream.ReadIntAsync();
bool flag = await stream.ReadBoolAsync();
byte[] payload = await stream.ReadLengthValueAsync();

Console.WriteLine(number);         // 42
Console.WriteLine(flag);           // True
Console.WriteLine(payload.Length); // 4
```

## Notes

- Read helpers throw if the stream ends before the requested value is fully
  read; position the stream at the start of the data before reading.
- `ReadLengthValue`/`ReadTagLengthValue` reject a length that is negative or
  larger than `maxLength`, so untrusted input cannot force an unbounded
  allocation.
- The async forms accept an optional `CancellationToken` as their final
  argument.
