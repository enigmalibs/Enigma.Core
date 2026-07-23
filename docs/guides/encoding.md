# Encoding

Enigma.Core converts binary data to and from textual representations through a
small service + factory API. You create an `EncodingServiceFactory`, ask it for
the scheme you need, and get back an `IEncodingService` that encodes a `byte[]`
into text and decodes that text back into the original bytes.

Three schemes are built in: Base64 (RFC 4648), Base32 (RFC 4648) and hexadecimal
(base-16). The scheme is chosen when the service is created; the data to encode
or decode is supplied per call on the returned service.

## Supported schemes

| Scheme | Factory method | Notes |
|--------|----------------|-------|
| Base64 | `CreateBase64Service` | RFC 4648 Base64 text. |
| Base32 | `CreateBase32Service` | RFC 4648 Base32 text. |
| Hex | `CreateHexService` | Hexadecimal (base-16) text. |

## Key types

| Type | Namespace | Role |
|------|-----------|------|
| `EncodingServiceFactory` | `Enigma.Core.Encoding` | Concrete factory. Implements `IEncodingServiceFactory`. Create with `new`. |
| `IEncodingServiceFactory` | `Enigma.Core.Encoding` | Factory interface. DI-friendly. |
| `IEncodingService` | `Enigma.Core.Encoding` | The encoding service returned by the factory. |

`IEncodingService` exposes two methods that are exact inverses of each other:

```csharp
string Encode(byte[] data);
byte[] Decode(string encoded);
```

For any `byte[] data`, `service.Decode(service.Encode(data))` returns the
original bytes.

The factory is constructed directly with `new`. The `I*` interfaces are
DI-friendly, so you can also register `EncodingServiceFactory` against
`IEncodingServiceFactory` in a Microsoft.Extensions.DependencyInjection container
and inject it where needed.

## Usage

### Base64 round-trip

```csharp
using System;
using Enigma.Core.Encoding;
using Enigma.Core.Utils;

var factory = new EncodingServiceFactory();
IEncodingService base64 = factory.CreateBase64Service();

byte[] data = RandomUtils.GenerateRandomBytes(16);

string encoded = base64.Encode(data);
byte[] decoded = base64.Decode(encoded);

Console.WriteLine(encoded);                       // Base64 text
Console.WriteLine(decoded.Length == data.Length); // True
```

### Base32 and Hex

The same service shape works for every scheme; only the factory method changes.

```csharp
using System;
using Enigma.Core.Encoding;
using Enigma.Core.Utils;

var factory = new EncodingServiceFactory();
IEncodingService base32 = factory.CreateBase32Service();
IEncodingService hex = factory.CreateHexService();

byte[] data = RandomUtils.GenerateRandomBytes(16);

string base32Text = base32.Encode(data);
string hexText = hex.Encode(data);

byte[] fromBase32 = base32.Decode(base32Text);
byte[] fromHex = hex.Decode(hexText);

Console.WriteLine(base32Text); // Base32 text (RFC 4648)
Console.WriteLine(hexText);    // hexadecimal text
```

## Notes

- `Encode` and `Decode` are exact inverses within a given scheme. Decode text
  with the same service kind that produced it.
- Each factory call returns a fresh per-scheme service instance.
- To encode text directly from a `byte[]` or `string` without going through the
  factory, see the convenience extension methods in the Extensions guide
  (`ToBase64String`, `ToBase32String`, `ToHexString` and their `From…`
  counterparts).
