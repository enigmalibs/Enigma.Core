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
| `MLDsaPemServiceFactory` | Concrete ML-DSA PEM factory. Implements `IMLDsaPemServiceFactory`. Create with `new`. |
| `IMLDsaPemServiceFactory` | ML-DSA PEM factory interface. DI-friendly. |
| `IMLDsaPemService` | Converts ML-DSA keys between raw bytes and PEM text. |
| `MLPrivateKeyPemFormat` | Enum selecting which representation of a private key a PEM stores. |

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

## PEM serialization

`IMLKemService` and `IMLDsaService` work in raw `byte[]` keys, which is what the FIPS algorithms
themselves are defined on. To store a key in a file, paste it into a config, or hand it to another
tool, wrap it in PEM instead — a separate service per family handles that, and nothing about the
signing/encapsulation services changes.

Reading a PEM gives you something the raw `byte[]` API cannot: the **parameter set comes back with
the key**, recovered from the algorithm OID in the envelope. You never have to remember alongside
the file whether it holds an ML-DSA-44 or an ML-DSA-87 key.

### ML-DSA key PEM

`IMLDsaPemService` writes and reads the three standard envelopes:

| PEM label | Written when | Contents |
|-----------|--------------|----------|
| `PUBLIC KEY` | any public-key write | X.509 `SubjectPublicKeyInfo` |
| `PRIVATE KEY` | private-key write, no password | PKCS#8 `PrivateKeyInfo` |
| `ENCRYPTED PRIVATE KEY` | private-key write with a password | PKCS#8 `EncryptedPrivateKeyInfo` |

Encryption is PBES2: PBKDF2-HMAC-SHA256 with a 16-byte salt and 600,000 iterations, then
AES-256-CBC. That iteration count follows current OWASP guidance and costs roughly 0.6 s each time a
key is written or read — a deliberate one-time cost per import, not a per-operation one.

A private-key PEM can store the key in three ways, selected with `MLPrivateKeyPemFormat`:

| Value | PKCS#8 body (ML-DSA-65) | PEM size | |
|-------|------------------------:|---------:|--|
| `Seed` | 54 bytes | ~130 chars | The default. Smallest by far |
| `ExpandedKey` | 4,060 bytes | ~5,600 chars | Most interoperable |
| `SeedAndExpandedKey` | 4,098 bytes | ~5,650 chars | Both representations |

All three are lossless: a `Seed` PEM is expanded when it is read, so `FromPrivateKeyPem` always
hands back the **expanded** FIPS 204 encoding — exactly what `IMLDsaService.Sign` accepts.

The format can only be chosen when the PEM service generates the key itself, via
`GenerateKeyPairPem`. An expanded FIPS 204 private key does not contain the seed it was derived
from, so `ToPrivateKeyPem` — which serializes a key you already hold — always writes `ExpandedKey`
and takes no format argument.

```csharp
IMLDsaPemService CreateMLDsaPemService();
```

`IMLDsaPemService` exposes five methods:

```csharp
(string publicKeyPem, string privateKeyPem) GenerateKeyPairPem(
    MLDsaParameterSet parameterSet,
    char[]? password = null,
    MLPrivateKeyPemFormat format = MLPrivateKeyPemFormat.Seed);

string ToPublicKeyPem(byte[] publicKey, MLDsaParameterSet parameterSet);
string ToPrivateKeyPem(byte[] privateKey, MLDsaParameterSet parameterSet, char[]? password = null);

(byte[] publicKey, MLDsaParameterSet parameterSet) FromPublicKeyPem(string pem);
(byte[] privateKey, MLDsaParameterSet parameterSet) FromPrivateKeyPem(string pem, char[]? password = null);
```

#### Generate a password-protected key pair as PEM, then sign with it

```csharp
using System;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.Core.Extensions;

var pemFactory = new MLDsaPemServiceFactory();
IMLDsaPemService pem = pemFactory.CreateMLDsaPemService();

char[] password = "correct horse battery staple".ToCharArray();

// Generate straight to PEM. The private key is stored as its 32-byte seed (the default), so the
// encrypted PEM is a few lines rather than a few thousand characters.
(string publicKeyPem, string privateKeyPem) =
    pem.GenerateKeyPairPem(MLDsaParameterSet.MLDsa65, password);

Console.WriteLine(privateKeyPem);   // -----BEGIN ENCRYPTED PRIVATE KEY-----

// Read them back. The parameter set arrives with the key, decoded from the algorithm OID.
(byte[] privateKey, MLDsaParameterSet parameterSet) = pem.FromPrivateKeyPem(privateKeyPem, password);
(byte[] publicKey, _) = pem.FromPublicKeyPem(publicKeyPem);

// Both are the expanded FIPS 204 encodings, so they go straight into the signing service.
IMLDsaService dsa = new MLDsaServiceFactory().CreateMLDsaService(parameterSet);

byte[] message = "message".GetUtf8Bytes();
byte[] signature = dsa.Sign(message, privateKey);
Console.WriteLine($"Signature valid: {dsa.Verify(message, signature, publicKey)}");

// The library never clears your passphrase — you own its lifetime.
Array.Clear(password, 0, password.Length);
```

#### Serialize keys you already hold

```csharp
using Enigma.Core.Asymmetric.Pqc;

IMLDsaService dsa = new MLDsaServiceFactory().CreateMLDsaService(MLDsaParameterSet.MLDsa65);
(byte[] publicKey, byte[] privateKey) = dsa.GenerateKeyPair();

IMLDsaPemService pem = new MLDsaPemServiceFactory().CreateMLDsaPemService();

// Round-trips byte-identically: what you read back equals what you wrote.
string publicKeyPem = pem.ToPublicKeyPem(publicKey, MLDsaParameterSet.MLDsa65);
string privateKeyPem = pem.ToPrivateKeyPem(privateKey, MLDsaParameterSet.MLDsa65);

(byte[] samePublicKey, _) = pem.FromPublicKeyPem(publicKeyPem);
(byte[] samePrivateKey, _) = pem.FromPrivateKeyPem(privateKeyPem);
```

#### Choosing a private-key format explicitly

```csharp
using Enigma.Core.Asymmetric.Pqc;

IMLDsaPemService pem = new MLDsaPemServiceFactory().CreateMLDsaPemService();

// A larger PEM, but readable by any implementation that does not support seed expansion.
(string publicKeyPem, string privateKeyPem) = pem.GenerateKeyPairPem(
    MLDsaParameterSet.MLDsa65,
    password: null,
    format: MLPrivateKeyPemFormat.ExpandedKey);
```

### Error handling

The PEM services follow the same contract as the rest of the library:

| Situation | Exception |
|-----------|-----------|
| A `null` argument | `ArgumentNullException` |
| Empty, malformed, or truncated PEM text | `ArgumentException` |
| A PEM holding the wrong kind of key (a public key where a private one is expected, another algorithm, an unsupported parameter set) | `ArgumentException` |
| Key bytes of the wrong length for the parameter set | `ArgumentException` |
| An encrypted PEM read with no password, or with the wrong one | `CryptographicException` |
| An undefined enum value | `ArgumentOutOfRangeException` |

No BouncyCastle exception ever reaches your code; where one caused the failure it is preserved as
the `InnerException`.

## Notes

- Keys, ciphertexts and signatures are raw `byte[]` values in their FIPS 203 /
  FIPS 204 encodings. Private keys are the **expanded** encodings, so they are
  directly usable by `Decapsulate` and `Sign` with no seed re-derivation.
- **PEM is opt-in and additive:** `IMLDsaService` is unchanged by it. Reach for
  `IMLDsaPemService` when a key has to leave the process as text; keep using the
  `byte[]` API when it does not. Both describe the same keys, and a key can move
  between the two freely.
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
