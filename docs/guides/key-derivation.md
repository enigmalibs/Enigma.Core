# Key Derivation

Enigma.Core turns a low-entropy password into cryptographic key material through a small service/factory pattern: create an `IPbkdf2Service` from `Pbkdf2ServiceFactory` or an `IArgon2Service` from `Argon2ServiceFactory`, then call `DeriveKey` with the password, salt, cost parameters and desired key length per call. Both functions are BouncyCastle-backed. Each derivation is deterministic: the same inputs always produce the same key, which is what lets you re-derive a key for verification or decryption.

## Supported functions

| Function | Factory | Service | Namespace |
| --- | --- | --- | --- |
| PBKDF2 | `Pbkdf2ServiceFactory` | `IPbkdf2Service` | `Enigma.Core.KeyDerivation` |
| Argon2 | `Argon2ServiceFactory` | `IArgon2Service` | `Enigma.Core.KeyDerivation` |

- **PBKDF2** (Password-Based Key Derivation Function 2) iterates an HMAC over the password and salt; the iteration count is the tunable work factor. The backing pseudorandom function is chosen per call via `Pbkdf2Prf`:

  | `Pbkdf2Prf` | HMAC hash |
  | --- | --- |
  | `Pbkdf2Prf.HmacSha1` | SHA-1 (legacy interop; prefer a stronger PRF) |
  | `Pbkdf2Prf.HmacSha256` | SHA-256 (default) |
  | `Pbkdf2Prf.HmacSha384` | SHA-384 |
  | `Pbkdf2Prf.HmacSha512` | SHA-512 |

- **Argon2** is a memory-hard function whose tunable memory, time and parallelism costs make brute-force attacks expensive on both CPUs and GPUs. The variant and version are chosen per call:

  | `Argon2Variant` | Memory access | Notes |
  | --- | --- | --- |
  | `Argon2Variant.Argon2d` | data-dependent | maximizes GPU-cracking resistance; susceptible to side-channel timing attacks |
  | `Argon2Variant.Argon2i` | data-independent | resists side-channel timing attacks |
  | `Argon2Variant.Argon2id` | hybrid | recommended default; combines both strengths |

  | `Argon2Version` | Meaning |
  | --- | --- |
  | `Argon2Version.Version10` | version 1.0 (0x10); compatibility with older tools |
  | `Argon2Version.Version13` | version 1.3 (0x13); current spec and recommended default |

## Key types

Passwords, salts and the derived keys are all plain `byte[]` supplied by and returned to the caller — the service holds no key state.

- **Password** — the raw bytes to derive from. Encode a text password to UTF-8 with the `GetUtf8Bytes()` extension from `Enigma.Core.Extensions`, or with `System.Text.Encoding.UTF8.GetBytes(...)`. The array is used as-is: it is neither re-encoded nor cleared, so the caller owns its encoding and lifetime.
- **Salt** — should be random and unique per password. Generate it with `Enigma.Core.Utils.RandomUtils.GenerateRandomBytes(int size)`; 16 bytes is a common choice. The salt need not be secret — store or transmit it alongside the derived key's ciphertext so the key can be re-derived.
- **Derived key** — the return value, exactly `keySizeBytes` bytes long. Size it to the consumer, for example 32 bytes for an AES-256 key.

## Usage

Construct the factory directly with `new` — the factory is a plain class, there is no DI-container helper. (The `IPbkdf2ServiceFactory` / `IPbkdf2Service` and `IArgon2ServiceFactory` / `IArgon2Service` interfaces are DI-registration-friendly if you want to register them in your own container.)

### PBKDF2

Derive a 32-byte key from a UTF-8 password and a random 16-byte salt, using 600,000 iterations of PBKDF2-HMAC-SHA256.

```csharp
using Enigma.Core.Extensions;
using Enigma.Core.KeyDerivation;
using Enigma.Core.Utils;

var factory = new Pbkdf2ServiceFactory();
IPbkdf2Service pbkdf2 = factory.CreatePbkdf2Service();

byte[] password = "correct horse".GetUtf8Bytes();
byte[] salt = RandomUtils.GenerateRandomBytes(16); // random, unique per password

byte[] key = pbkdf2.DeriveKey(
    password,
    salt,
    iterations: 600_000,   // OWASP (2023) floor for PBKDF2-HMAC-SHA256
    keySizeBytes: 32,      // 256-bit key
    prf: Pbkdf2Prf.HmacSha256);

// key is 32 bytes. Store `salt` alongside the ciphertext so `key` can be re-derived later.
```

### Argon2

Derive a 32-byte key with Argon2id using RFC 9106's second recommended option: time cost 3, 64 MiB of memory and 4 lanes.

```csharp
using Enigma.Core.Extensions;
using Enigma.Core.KeyDerivation;
using Enigma.Core.Utils;

var argonFactory = new Argon2ServiceFactory();
IArgon2Service argon2 = argonFactory.CreateArgon2Service();

byte[] password = "correct horse".GetUtf8Bytes();
byte[] salt = RandomUtils.GenerateRandomBytes(16); // random, unique per password

byte[] key = argon2.DeriveKey(
    password,
    salt,
    iterations: 3,             // time cost (passes over memory)
    memorySizeKb: 65536,       // 64 MiB
    degreeOfParallelism: 4,    // lanes
    keySizeBytes: 32,          // 256-bit key
    variant: Argon2Variant.Argon2id,
    version: Argon2Version.Version13);

// key is 32 bytes. Store `salt` alongside the ciphertext so `key` can be re-derived later.
```

## Notes

### Cost parameters

Cost parameters are the whole point of a password KDF: tune them as high as your latency budget allows so that each guess an attacker makes is expensive, then keep them constant so the key re-derives identically.

- **PBKDF2** — `iterations` is the work factor. As a floor, OWASP recommends **at least 600,000 iterations** for PBKDF2-HMAC-SHA256 (2023 guidance). Raising the iteration count is the primary lever; a stronger PRF (`HmacSha512`) is a secondary consideration. Both `iterations` and `keySizeBytes` must be greater than zero, otherwise `DeriveKey` throws `System.ArgumentException`.
- **Argon2** — three independent costs. RFC 9106's second recommended option is `iterations = 3`, `memorySizeKb = 65536` (64 MiB) and `degreeOfParallelism = 4`. Memory cost is what makes Argon2 hard to parallelize on GPUs, so prefer raising `memorySizeKb` where your hardware allows. `Argon2Variant.Argon2id` and `Argon2Version.Version13` are the recommended defaults. Each of `iterations`, `memorySizeKb`, `degreeOfParallelism` and `keySizeBytes` must be greater than zero, otherwise `DeriveKey` throws `System.ArgumentException`.

For both services, `password` and `salt` must be non-null, otherwise `DeriveKey` throws `System.ArgumentNullException`.

### Password lifetime

Neither service mutates or clears the `password` array — it is read as-is and left untouched. The caller owns the password's lifetime, including zeroing the buffer once it is no longer needed if your threat model calls for it. Because the same salt is required to re-derive the same key, persist the salt (it need not be secret) even though the derived key and the password itself should not be stored.

### Re-derivation and record fields

To verify a password or decrypt data later, re-run `DeriveKey` with the identical password, salt and cost parameters — the derivation is deterministic. Persist the salt and every cost parameter (for PBKDF2: the iteration count and PRF; for Argon2: iterations, memory size, parallelism, variant and version) alongside the protected data so a future call reproduces the same key.
