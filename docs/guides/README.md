# Enigma.Core — Guides & Samples

Per-category guides for **Enigma.Core**, a modern .NET cryptography library built on
BouncyCastle. Every algorithm is exposed through the same **service + factory** pattern: you
create a factory, ask it for the service you need, and call the operation. The factories are
plain classes (construct them with `new`), and their `I…Factory` interfaces register cleanly in
any dependency-injection container.

Each guide follows the same shape — **supported algorithms/schemes → key types → copy-pasteable
usage samples** — and every snippet targets the real public API.

## Symmetric encryption

- [Block ciphers](block-ciphers.md) — AES, DES, 3DES, Blowfish, Twofish, Serpent, Camellia,
  CAST5, IDEA, SEED, ARIA, SM4; ECB/CBC/CTR/GCM modes with AAD.
- [Stream ciphers](stream-ciphers.md) — ChaCha20, ChaCha20-RFC7539, Salsa20.
- [Padding](padding.md) — None, PKCS#7, ISO 7816-4, ISO 10126-2, ANSI X9.23.

## Hashing & message authentication

- [Hashing](hashing.md) — MD5, SHA-1, SHA-256, SHA-512, SHA-3; streaming with progress &
  cancellation.
- [HMAC](hmac.md) — HMAC-SHA1/256/512.

## Key derivation

- [Key derivation](key-derivation.md) — PBKDF2 (four PRFs) and Argon2 (Argon2d/i/id).

## Asymmetric cryptography

- [Public-key (RSA)](public-key.md) — key generation, PKCS#1 v1.5 & OAEP encryption,
  RSASSA-PKCS1-v1_5 signatures, all over the reusable `RsaKey` handle.
- [Post-quantum (PQC)](pqc.md) — ML-KEM (FIPS 203) key encapsulation and ML-DSA (FIPS 204)
  signatures, plus key PEM import/export for both families.

## Certificates

- [X.509 certificates](certificates.md) — self-signed generation, CSR & issuance, chain
  validation, CRL revocation, PKCS#12 and DER import/export, certificate info.

## One-time passwords

- [OTP](otp.md) — HOTP (RFC 4226), TOTP (RFC 6238), and `otpauth://` provisioning URIs.

## Data & helpers

- [Encoding](encoding.md) — Base64, Base32 (RFC 4648), hexadecimal.
- [Checksums](checksum.md) — CRC-16 (ARC, CCITT-FALSE, XMODEM, MODBUS, KERMIT) and
  CRC-32 (ISO-HDLC, CRC-32C). Error detection only — never a security primitive.
- [Extensions](extensions.md) — `byte[]`/`string` encoding helpers and typed `Stream` read/write
  extensions.
- [Utilities & defaults](utils.md) — `RandomUtils` secure random bytes and `CryptoDefaults`.
