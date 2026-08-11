# Enigma.Core

[![NuGet](https://img.shields.io/nuget/v/Enigma.Core.svg)](https://www.nuget.org/packages/Enigma.Core)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.md)

A modern, service- and factory-oriented .NET cryptography library built on BouncyCastle. Every
algorithm is exposed through the same small pattern — create a factory, ask it for the service you
need, call the operation — and the factory interfaces register cleanly in any dependency-injection
container. BouncyCastle powers the implementations but never leaks onto the public surface.

> **What's new in 1.1** — now built on BouncyCastle 2.7.0; the public API and its behaviour are
> unchanged, and ML-KEM/ML-DSA encodings stay byte-compatible with 1.0.0. See
> [RELEASENOTES.md](RELEASENOTES.md) for the full details.

## Features

- **Block ciphers** — AES, DES, 3DES, Blowfish, Twofish, Serpent, Camellia, CAST5, IDEA, SEED,
  ARIA, and SM4, in ECB / CBC / CTR / GCM modes (GCM with additional authenticated data).
- **Stream ciphers** — ChaCha20, ChaCha20-RFC7539, and Salsa20.
- **Padding** — None, PKCS#7, ISO 7816-4, ISO 10126-2, and ANSI X9.23.
- **Public-key (RSA)** — key generation with PEM import/export (optionally AES-256-CBC-encrypted
  private keys), PKCS#1 v1.5 and OAEP encryption, and RSASSA-PKCS1-v1_5 signing/verification.
- **Post-quantum (PQC)** — ML-KEM 512/768/1024 (FIPS 203) key encapsulation and ML-DSA 44/65/87
  (FIPS 204) signatures. Both families also have PEM import/export (optionally PBES2-encrypted
  private keys), recovering the parameter set from the PEM on read.
- **X.509 certificates** — self-signed generation, CSR creation & verification, CA issuance, chain
  validation, CRL-based revocation checks, PKCS#12 and DER import/export, and certificate inspection
  (including thumbprint).
- **Hashing** — MD5, SHA-1, SHA-256, SHA-512, and SHA-3.
- **HMAC** — HMAC-SHA1, HMAC-SHA256, and HMAC-SHA512.
- **One-time passwords** — HOTP (RFC 4226), TOTP (RFC 6238), and `otpauth://` provisioning URIs.
- **Key derivation** — PBKDF2 (four PRFs) and Argon2 (Argon2d/i/id).
- **Encoding** — Base64, Base32 (RFC 4648), and hexadecimal.

### Asynchronous, cancellable, observable

The streaming operations — block and stream ciphers, hashing, and HMAC — expose `async` APIs that
accept an `IProgress<int>` for progress reporting and a `CancellationToken` for cancellation, so
large-payload work stays responsive.

## Installation

```bash
dotnet add package Enigma.Core
```

Targets **.NET Standard 2.0**, **.NET 8.0**, and **.NET 10.0**; built on BouncyCastle 2.7.0.

## Quick start

Every category follows the same three steps — create a factory, get a service, call the operation:

```csharp
using System;
using System.IO;
using System.Text;
using Enigma.Core.Hashing.Hash;

IHashServiceFactory hashFactory = new HashServiceFactory();
IHashService sha256 = hashFactory.CreateSha256Service();

using var input = new MemoryStream(Encoding.UTF8.GetBytes("The quick brown fox"));
byte[] digest = await sha256.ComputeHashAsync(input);

string hex = BitConverter.ToString(digest).Replace("-", "").ToLowerInvariant();
```

## Documentation

Per-category guides — each with the supported algorithms, the key services and factories, and
copy-pasteable C# samples verified against the public API — live under `docs/guides/` in the
repository, indexed by `docs/guides/README.md`. They cover block ciphers, stream ciphers, padding,
hashing, HMAC, key derivation, encoding, OTP, public-key (RSA), post-quantum cryptography, X.509
certificates, the extension methods, and the utility helpers.

## License

Enigma.Core is released under the [MIT License](LICENSE.md).
