# One-Time Passwords (OTP)

Enigma.Core generates and verifies the one-time passwords used for two-factor
authentication, through the same service + factory API the rest of the library
uses. HMAC-based (HOTP) and time-based (TOTP) codes are supported, along with a
provisioning service that produces the `otpauth://` URIs authenticator apps read
when you enroll a new account.

The OTP factories are not parameterless: each is built over the factory below it
in the stack, so you compose the chain yourself with `new`. The `I*` interfaces
are DI-friendly, so you can also register the concrete factories against their
interfaces in a Microsoft.Extensions.DependencyInjection container and let the
container satisfy the constructor dependencies.

## Supported

| Standard | What it is | Type |
|----------|------------|------|
| RFC 4226 | HOTP — HMAC-based OTP, driven by an event counter. | `IHotpService` |
| RFC 6238 | TOTP — time-based OTP, driven by the current time split into fixed steps. | `ITotpService` |
| Key URI Format | `otpauth://totp/…` provisioning URIs, secret encoded as unpadded Base32. | `IOtpProvisioningService` |

The backing HMAC hash is selectable per service via `OtpHashAlgorithm`
(`Sha1`, `Sha256`, `Sha512`). Authenticator apps default to `Sha1`, so keep that
default unless every app that will read the credential is known to support
another algorithm.

## Key types

| Type | Namespace | Role |
|------|-----------|------|
| `HmacServiceFactory` | `Enigma.Core.Hashing.Hmac` | Concrete HMAC factory. Root of the HOTP/TOTP chain. Create with `new`. |
| `EncodingServiceFactory` | `Enigma.Core.Encoding` | Concrete encoding factory. Supplies the Base32 encoder for provisioning. Create with `new`. |
| `HotpServiceFactory` | `Enigma.Core.Otp` | Concrete factory. Needs an `IHmacServiceFactory`. Implements `IHotpServiceFactory`. |
| `TotpServiceFactory` | `Enigma.Core.Otp` | Concrete factory. Needs an `IHotpServiceFactory`. Implements `ITotpServiceFactory`. |
| `OtpProvisioningServiceFactory` | `Enigma.Core.Otp` | Concrete factory. Needs an `IEncodingServiceFactory`. Implements `IOtpProvisioningServiceFactory`. |
| `IHotpService` | `Enigma.Core.Otp` | HOTP generator/verifier returned by the factory. |
| `ITotpService` | `Enigma.Core.Otp` | TOTP generator/verifier returned by the factory. |
| `IOtpProvisioningService` | `Enigma.Core.Otp` | Builds/parses `otpauth://` URIs and generates secrets. |
| `OtpAuthParameters` | `Enigma.Core.Otp` | Sealed, read-only carrier for the fields of a provisioning URI. |
| `OtpHashAlgorithm` | `Enigma.Core.Otp` | Enum selecting the HMAC hash: `Sha1`, `Sha256`, `Sha512`. |

### Construction

Each factory is injected with the one beneath it, so build the chain from the
bottom up:

```csharp
using Enigma.Core.Encoding;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.Otp;

var hmacFactory = new HmacServiceFactory();                 // Enigma.Core.Hashing.Hmac
var hotpFactory = new HotpServiceFactory(hmacFactory);      // needs IHmacServiceFactory
var totpFactory = new TotpServiceFactory(hotpFactory);      // needs IHotpServiceFactory

var provFactory = new OtpProvisioningServiceFactory(new EncodingServiceFactory()); // needs IEncodingServiceFactory
```

`CreateHotpService` and `CreateTotpService` fix the authenticator configuration
(digit count, period, hash algorithm) at creation; the secret and moving factor
are supplied per call on the returned service.

```csharp
IHotpService CreateHotpService(int digits = 6, OtpHashAlgorithm hashAlgorithm = OtpHashAlgorithm.Sha1);
ITotpService CreateTotpService(int digits = 6, int periodSeconds = 30, OtpHashAlgorithm hashAlgorithm = OtpHashAlgorithm.Sha1);
```

## Usage

### TOTP — the authenticator-app flow

Generate a random secret, produce the code for the current time step, and verify
a code the user typed back. `GetRemainingSeconds()` drives a countdown so a UI
can show how long the current code stays valid.

```csharp
using System;
using Enigma.Core.Encoding;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.Otp;

var hmacFactory = new HmacServiceFactory();
var hotpFactory = new HotpServiceFactory(hmacFactory);
var totpFactory = new TotpServiceFactory(hotpFactory);
var provService = new OtpProvisioningServiceFactory(new EncodingServiceFactory())
    .CreateOtpProvisioningService();

// 20-byte (160-bit) secret, the authenticator-app default.
byte[] secret = provService.GenerateSecret();

ITotpService totp = totpFactory.CreateTotpService();

string code = totp.GenerateCode(secret);
Console.WriteLine($"Current code: {code} (valid for {totp.GetRemainingSeconds()}s)");

// Verify a code the user typed. The default window (±1 step) absorbs clock drift.
bool valid = totp.VerifyCode(secret, code);
Console.WriteLine(valid ? "Accepted" : "Rejected");
```

`VerifyCode` has an overload that reports which step matched, letting a server
reject replays by accepting only steps later than the last one it accepted:

```csharp
if (totp.VerifyCode(secret, code, DateTimeOffset.UtcNow, window: 1, out long matchedStep))
{
    Console.WriteLine($"Accepted at step {matchedStep}");
}
```

### HOTP — counter-driven codes

HOTP replaces TOTP's clock with an explicit counter that both sides advance in
lockstep. Generate a code for the current counter, and verify with a small
forward window to tolerate counter drift (RFC 4226 §7.4 resynchronization).

```csharp
using System;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.Otp;

var hmacFactory = new HmacServiceFactory();
var hotpFactory = new HotpServiceFactory(hmacFactory);

IHotpService hotp = hotpFactory.CreateHotpService();

byte[] secret = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39 };
long counter = 0;

string code = hotp.GenerateCode(secret, counter);
Console.WriteLine($"HOTP for counter {counter}: {code}");

// Verify allowing up to 3 counters of look-ahead, and learn which one matched
// so the server can resynchronize.
if (hotp.VerifyCode(secret, counter, code, window: 3, out long matchedCounter))
{
    counter = matchedCounter + 1; // advance past the accepted counter
    Console.WriteLine($"Accepted; next expected counter is {counter}");
}
```

### Provisioning — building and parsing an otpauth URI

Wrap the credential in an `OtpAuthParameters` and hand it to `BuildUri` to get a
URI you can render as a QR code during enrollment. `ParseUri` round-trips the URI
back into parameters.

```csharp
using System;
using Enigma.Core.Encoding;
using Enigma.Core.Otp;

var provService = new OtpProvisioningServiceFactory(new EncodingServiceFactory())
    .CreateOtpProvisioningService();

byte[] secret = provService.GenerateSecret();

var parameters = new OtpAuthParameters(
    issuer: "Example",
    accountName: "alice@example.com",
    secret: secret,
    digits: 6,
    periodSeconds: 30,
    algorithm: OtpHashAlgorithm.Sha1);

string uri = provService.BuildUri(parameters);
Console.WriteLine(uri); // otpauth://totp/Example:alice@example.com?secret=...&issuer=Example&...

// Round-trip back into parameters.
OtpAuthParameters parsed = provService.ParseUri(uri);
Console.WriteLine($"{parsed.Issuer} / {parsed.AccountName}, {parsed.Digits} digits, {parsed.Algorithm}");
```

`OtpAuthParameters` is sealed and its properties are read-only:

| Property | Type | Notes |
|----------|------|-------|
| `Issuer` | `string?` | May be `null`; supplying it is strongly recommended for correct display in apps. |
| `AccountName` | `string` | Required (typically a username or email). |
| `Secret` | `byte[]` | The decoded shared secret. |
| `Digits` | `int` | Digit count in generated codes. |
| `PeriodSeconds` | `int` | Time step, in seconds. |
| `Algorithm` | `OtpHashAlgorithm` | HMAC hash backing the codes. |

## Notes

- **Factory chain.** The OTP factories require constructor injection: `HotpServiceFactory` needs an `IHmacServiceFactory`, `TotpServiceFactory` needs an `IHotpServiceFactory`, and `OtpProvisioningServiceFactory` needs an `IEncodingServiceFactory`. Passing `null` to any of them throws `ArgumentNullException`. Build the chain bottom-up as shown, or register the concrete factories against their interfaces in a DI container.
- **Secret size.** `GenerateSecret` defaults to 20 bytes (160-bit) and rejects anything under 16 with `ArgumentOutOfRangeException`. The caller owns the returned array and is responsible for clearing it when done.
- **Hash algorithm.** Keep `OtpHashAlgorithm.Sha1` for credentials that will be scanned into authenticator apps — it is the default those apps assume. `Sha256` and `Sha512` are available where every consumer is known to support them.
- **Verification windows.** TOTP `VerifyCode` defaults to a ±1-step window to absorb clock drift; HOTP takes an explicit forward-only window for counter resynchronization. Both `out`-parameter overloads scan the whole window without early exit, so verification time does not reveal where a match occurred. A negative window throws `ArgumentOutOfRangeException`.
- **URI parsing.** `ParseUri` fills absent optional parameters with their defaults (SHA-1, 6 digits, 30-second period). A malformed URI, a missing secret, or an unrecognized algorithm throws `FormatException`; a `null` URI throws `ArgumentNullException`.
- **QR images out of scope.** The provisioning service produces the `otpauth://` URI only. Rendering it as a QR-code image is intentionally left out (it would require an external dependency) — pass the URI string to the QR library of your choice.
