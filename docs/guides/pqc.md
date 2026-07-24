# Post-Quantum Cryptography (PQC)

Enigma.Core provides NIST-standardised post-quantum primitives through the same
service + factory pattern as the rest of the library. You create a factory with
`new`, ask it for a service at the security level you want, and get back a small,
focused interface that works entirely in raw `byte[]` values.

Two algorithm families are covered, both built on module lattices and both
believed to resist attacks by large-scale quantum computers:

- **ML-KEM** (FIPS 203) — a *key-encapsulation mechanism* used to agree on a
  shared secret between two parties. Formerly known as CRYSTALS-Kyber.
- **ML-DSA** (FIPS 204) — a *digital signature algorithm* used to sign messages
  and verify signatures. Formerly known as CRYSTALS-Dilithium.

All types live in the `Enigma.Core.Asymmetric.Pqc` namespace.

## Supported algorithms

| Family | Standard | Purpose | Parameter sets |
|--------|----------|---------|----------------|
| ML-KEM | FIPS 203 | Key encapsulation (shared-secret agreement) | `MLKem512`, `MLKem768`, `MLKem1024` |
| ML-DSA | FIPS 204 | Digital signatures | `MLDsa44`, `MLDsa65`, `MLDsa87` |

Each parameter set maps to a NIST security category. Higher values give a larger
security margin at the cost of larger keys, ciphertexts and signatures.

| Parameter set | NIST category | |
|---------------|:-------------:|--|
| `MLKemParameterSet.MLKem512` | 1 | |
| `MLKemParameterSet.MLKem768` | 3 | Recommended default |
| `MLKemParameterSet.MLKem1024` | 5 | |
| `MLDsaParameterSet.MLDsa44` | 2 | |
| `MLDsaParameterSet.MLDsa65` | 3 | Recommended default |
| `MLDsaParameterSet.MLDsa87` | 5 | |

The parameter set is fixed for the lifetime of a service: it is chosen when the
factory creates the service, not per call.

## Key types

| Type | Role |
|------|------|
| `MLKemServiceFactory` | Concrete ML-KEM factory. Implements `IMLKemServiceFactory`. Create with `new`. |
| `IMLKemServiceFactory` | ML-KEM factory interface. DI-friendly. |
| `IMLKemService` | The ML-KEM service returned by the factory. |
| `MLKemParameterSet` | Enum selecting the ML-KEM security level. |
| `MLDsaServiceFactory` | Concrete ML-DSA factory. Implements `IMLDsaServiceFactory`. Create with `new`. |
| `IMLDsaServiceFactory` | ML-DSA factory interface. DI-friendly. |
| `IMLDsaService` | The ML-DSA service returned by the factory. |
| `MLDsaParameterSet` | Enum selecting the ML-DSA security level. |

The factory methods return the service interfaces:

```csharp
IMLKemService CreateMLKemService(MLKemParameterSet parameterSet = MLKemParameterSet.MLKem768);

IMLDsaService CreateMLDsaService(MLDsaParameterSet parameterSet = MLDsaParameterSet.MLDsa65, bool deterministic = false);
```

`IMLKemService` exposes three methods:

```csharp
(byte[] publicKey, byte[] privateKey) GenerateKeyPair();
(byte[] ciphertext, byte[] sharedSecret) Encapsulate(byte[] publicKey);
byte[] Decapsulate(byte[] ciphertext, byte[] privateKey);
```

`IMLDsaService` exposes three methods:

```csharp
(byte[] publicKey, byte[] privateKey) GenerateKeyPair();
byte[] Sign(byte[] message, byte[] privateKey);
bool Verify(byte[] message, byte[] signature, byte[] publicKey);
```

The factories are constructed directly with `new`. The `I*` interfaces are
DI-friendly, so you can also register `MLKemServiceFactory` against
`IMLKemServiceFactory` (and `MLDsaServiceFactory` against `IMLDsaServiceFactory`)
in a Microsoft.Extensions.DependencyInjection container and inject them where
needed.

## Usage

### ML-KEM-768 — encapsulate and decapsulate a shared secret

ML-KEM lets two parties agree on a shared secret. The recipient generates a key
pair and publishes the public key. The sender calls `Encapsulate` against that
public key, which yields a `ciphertext` and a `sharedSecret`; the sender keeps
the shared secret and transmits only the ciphertext. The recipient then calls
`Decapsulate` with the ciphertext and its private key to recover the *same*
shared secret.

```csharp
using System;
using System.Linq;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.Core.Extensions;

var kemFactory = new MLKemServiceFactory();
IMLKemService kem = kemFactory.CreateMLKemService(MLKemParameterSet.MLKem768);

// Recipient generates a key pair and publishes the public key.
(byte[] publicKey, byte[] privateKey) = kem.GenerateKeyPair();

// Sender encapsulates a fresh shared secret against the recipient's public key,
// then transmits only the ciphertext.
(byte[] ciphertext, byte[] senderSecret) = kem.Encapsulate(publicKey);

// Recipient decapsulates the ciphertext with its private key.
byte[] recipientSecret = kem.Decapsulate(ciphertext, privateKey);

// Both sides now hold the identical shared secret.
bool equal = senderSecret.SequenceEqual(recipientSecret);
Console.WriteLine($"Shared secrets match: {equal}");
Console.WriteLine(senderSecret.ToHexString());
```

Both `senderSecret` and `recipientSecret` are equal — that shared secret is what
you feed into a symmetric primitive (for example an AES key or a KDF) to protect
subsequent traffic.

### ML-DSA-65 — sign and verify a message

ML-DSA produces and verifies digital signatures. The signer generates a key pair
and keeps the private key. `Sign` produces a signature over the message bytes;
anyone holding the public key can call `Verify` to confirm the signature is valid
for that message.

```csharp
using System;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.Core.Extensions;

var dsaFactory = new MLDsaServiceFactory();
IMLDsaService dsa = dsaFactory.CreateMLDsaService(MLDsaParameterSet.MLDsa65);

// Signer generates a key pair and keeps the private key secret.
(byte[] publicKey, byte[] privateKey) = dsa.GenerateKeyPair();

byte[] message = "message".GetUtf8Bytes();

// Sign with the private key.
byte[] signature = dsa.Sign(message, privateKey);

// Verify with the public key.
bool valid = dsa.Verify(message, signature, publicKey);
Console.WriteLine($"Signature valid: {valid}");
```

To sign deterministically, create the service with `deterministic: true`:

```csharp
IMLDsaService dsa = dsaFactory.CreateMLDsaService(MLDsaParameterSet.MLDsa65, deterministic: true);
```

## Notes

- Keys, ciphertexts and signatures are raw `byte[]` values in their FIPS 203 /
  FIPS 204 encodings. Private keys are the **expanded** encodings, so they are
  directly usable by `Decapsulate` and `Sign` with no seed re-derivation.
- **ML-KEM shared-secret flow:** the sender calls `Encapsulate(recipientPublicKey)`
  to obtain `(ciphertext, sharedSecret)` and transmits only the `ciphertext`; the
  recipient calls `Decapsulate(ciphertext, privateKey)` to recover the same
  `sharedSecret`. The shared secret itself is never sent over the wire.
- **ML-DSA `deterministic` flag:** when `true`, signing the same message with the
  same key always yields the identical signature. When `false` (the default),
  signing is hedged and mixes in fresh randomness per call, so repeated signatures
  of the same message differ. Both forms are valid FIPS 204 signatures and verify
  identically.
- `MLKem768` and `MLDsa65` (NIST category 3) are the recommended defaults and
  match the parameter-set defaults on the factory methods. Choose a higher set
  only if your threat model calls for a larger security margin.
- The message bytes above come from the `GetUtf8Bytes()` string extension in
  `Enigma.Core.Extensions`; `ToHexString()` from the same namespace renders raw
  bytes as text for display.
