# Enigma.Core v1.0.0 Release Notes

The first public release of **Enigma.Core** — a modern, service- and factory-oriented .NET
cryptography library built on BouncyCastle and designed for dependency injection. Every algorithm is
reached through the same pattern (create a factory, get a service, call the operation), and no
BouncyCastle type is ever exposed on the public surface.

## Feature overview

- **Block ciphers** — AES, DES, 3DES, Blowfish, Twofish, Serpent, Camellia, CAST5, IDEA, SEED,
  ARIA, and SM4, in ECB / CBC / CTR / GCM modes, with additional authenticated data (AAD) and a
  configurable MAC size for GCM.
- **Stream ciphers** — ChaCha20, ChaCha20-RFC7539, and Salsa20.
- **Padding** — None, PKCS#7, ISO 7816-4, ISO 10126-2, and ANSI X9.23.
- **Public-key (RSA)** — key generation with PEM import/export (optionally AES-256-CBC-encrypted
  private keys), PKCS#1 v1.5 and OAEP encryption, and RSASSA-PKCS1-v1_5 signing/verification.
- **Post-quantum (PQC)** — ML-KEM 512/768/1024 (FIPS 203) key encapsulation and ML-DSA 44/65/87
  (FIPS 204) signatures.
- **X.509 certificates** — self-signed generation, CSR creation & verification, CA issuance, chain
  validation, CRL-based revocation checks, PKCS#12 and DER import/export, and certificate inspection
  (subject, issuer, validity, thumbprint, and more).
- **Hashing** — MD5, SHA-1, SHA-256, SHA-512, and SHA-3.
- **HMAC** — HMAC-SHA1, HMAC-SHA256, and HMAC-SHA512.
- **One-time passwords** — HOTP (RFC 4226), TOTP (RFC 6238), and `otpauth://` provisioning URIs.
- **Key derivation** — PBKDF2 (four PRFs) and Argon2 (Argon2d/i/id).
- **Encoding** — Base64, Base32 (RFC 4648), and hexadecimal.
- **Streaming, async, cancellable** — the streaming operations (block and stream ciphers, hashing,
  and HMAC) offer `async` APIs with `IProgress<int>` progress reporting and `CancellationToken`
  support.

## Compatibility

- Targets **.NET Standard 2.0**, **.NET 8.0**, and **.NET 10.0**.
- Built on **BouncyCastle.Cryptography 2.6.2**.

## Version

- Initial release: **1.0.0**.
