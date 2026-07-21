# FEATURE-0399 — Encoding implementation (Base64, Hex, Base32)

- **Status:** DONE
- **Type:** FEATURE (single-phase)
- **Depends on:** FEATURE-61D1 (foundation — BouncyCastle package ref + CSV vector harness)
- **Suggested branch (at build):** `feature/feature-0399-encoding`
- **Basis:** ported from Enigma.Cryptography v5.0.0 (`/home/jo/Dev/Enigma.Cryptography`); redesign decisions validated by user 2026-07-21.

## Objective
Implement the three textual encoders — Base64, hexadecimal, and Base32/RFC 4648 — and their factory behind the frozen `Enigma.Core.Encoding` contract, porting the working behavior and test vectors from Enigma.Cryptography v5.0.0's `DataEncoding` module at MAXIMUM FIDELITY. BouncyCastle stays entirely internal (never in a public signature, base type, or public support member); the public surface remains the optionless single `IEncodingService` plus its factory, exactly as frozen by FEATURE-4442.

## Basis — port from Enigma.Cryptography v5.0.0
Exact old source files (from the spec's `oldToNewMapping`):
- `src/Enigma.Cryptography/DataEncoding/IEncodingService.cs`
- `src/Enigma.Cryptography/DataEncoding/Base64Service.cs` (delegates to `Org.BouncyCastle.Utilities.Encoders.Base64`)
- `src/Enigma.Cryptography/DataEncoding/HexService.cs` (delegates to `Org.BouncyCastle.Utilities.Encoders.Hex`; lowercase output)
- `src/Enigma.Cryptography/DataEncoding/Base32Service.cs` (pure built-in RFC 4648 bit-shift impl; no BouncyCastle)
- `src/Enigma.Cryptography/DataEncoding/IEncodingServiceFactory.cs`
- `src/Enigma.Cryptography/DataEncoding/EncodingServiceFactory.cs`

Old test files that carry the behavior forward:
- `src/UnitTests/DataEncoding/Base32ServiceTests.cs`
- `src/UnitTests/DataEncoding/Base64ServiceTests.cs`
- `src/UnitTests/DataEncoding/HexServiceTests.cs`
- `src/UnitTests/DataEncoding/EncodingServiceFactoryTests.cs`

## Scope & mapping
| Old (`DataEncoding`) | New home | Disposition | Note |
|---|---|---|---|
| `IEncodingService.cs` | `Encoding/IEncodingService.cs` | Renamespaced (public, frozen) | Same members; Decode param `data`→`encoded` |
| `Base64Service.cs` | `Encoding/Base64Service.cs` | Implement sealed stub | BC `Base64` encoder used INTERNALLY only |
| `HexService.cs` | `Encoding/HexService.cs` | Implement sealed stub | BC `Hex` encoder used INTERNALLY; lowercase output |
| `Base32Service.cs` | `Encoding/Base32Service.cs` | Implement sealed stub | Port verbatim; NO BouncyCastle |
| `IEncodingServiceFactory.cs` | `Encoding/IEncodingServiceFactory.cs` | Renamespaced (public, frozen) | Frozen order Base64/Base32/Hex |
| `EncodingServiceFactory.cs` | `Encoding/EncodingServiceFactory.cs` | Implement sealed stub | New per-scheme instance per `Create*` |
| `Utils/EncodingExtensions` round-trip behavior | (extensions ported in foundation FEATURE-61D1) | Tests move HERE | `EncodingExtensions` itself is ported in foundation against the Encoding stubs; its Base64/Hex/Base32 round-trip tests land in this feature (per `orchestrator_impl_choices`) |

## Contract amendments to the frozen skeleton (FEATURE-4442)
Approved by user 2026-07-21.

None — the frozen contract is implemented as-is.

The FEATURE-4442 source-parity note #3 asked whether Hex/Base32 exposed casing or padding options. Verified against v5.0.0: they did NOT — each old service is a fixed single-behavior encoder (Hex = lowercase; Base32 = canonical uppercase padded encode, tolerant decode). The frozen optionless single `IEncodingService` therefore represents the old public surface exactly, so MAXIMUM FIDELITY adds NO public member here. All divergences for this feature are behavioral details baked into the implementations, not surface changes; every one keeps principle-1 BC-hiding intact (no BC type appears in any public signature).

## BouncyCastle usage (internal only)
Used strictly behind `Base64Service` / `HexService` implementations; never in a public signature, return type, base type, or public support member:
- `Org.BouncyCastle.Utilities.Encoders.Base64.ToBase64String(byte[])` — `Base64Service.Encode`
- `Org.BouncyCastle.Utilities.Encoders.Base64.Decode(string)` — `Base64Service.Decode` (whitespace-tolerant)
- `Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(byte[])` — `HexService.Encode` (lowercase)
- `Org.BouncyCastle.Utilities.Encoders.Hex.Decode(string)` — `HexService.Decode`
- `Base32Service` uses NO BouncyCastle (pure `System.Text` / `System.Collections`).

Per `orchestrator_impl_choices`, the `BouncyCastle.Cryptography` (and `System.Buffers`) package references are added by the foundation feature (FEATURE-61D1), so this feature consumes them and does not add package refs itself.

## Redesign decisions
### Already frozen (FEATURE-4442)
- Namespace moved `DataEncoding` → `Enigma.Core.Encoding` (folder = namespace).
- Single `IEncodingService` shared by all three schemes; scheme is a factory choice, not a signature difference (consistent with the block-cipher/hash single-interface + per-algorithm-factory pattern).
- Frozen member set: `Encode(byte[] data):string` and `Decode(string encoded):byte[]` (Decode param renamed `data`→`encoded`).
- Three sealed per-scheme stubs (`Base64Service`, `Base32Service`, `HexService`) + one sealed `EncodingServiceFactory` with `CreateBase64Service`/`CreateBase32Service`/`CreateHexService`, all returning `IEncodingService`.
- Sync `byte[]`/`string` APIs — no `bufferSize`/`IProgress`/`CancellationToken` (all encoders are in-memory), matching the KeyDerivation/OTP decision.
- Factory declaration order Base64/Base32/Hex (old was Base64/Hex/Base32) — cosmetic, kept as frozen.

### Restored per user validation (2026-07-21)
No public members are restored for this feature — the old public surface already matches the frozen contract (see Contract amendments). The following behavioral fidelity points are settled implementation decisions:
- **BouncyCastle backend kept INTERNAL for Base64 & Hex** (`orchestrator_impl_choices`: BC encoders reintroduced internally). Rationale: preserves exact old behavior byte-for-byte — whitespace-tolerant Base64 decode and lowercase Hex output — across all three TFMs with no `netstandard2.0` polyfill (`Convert.To/FromHexString` is net5+ only, and `Convert.FromBase64String` is not whitespace-tolerant). BC never leaks into a public signature.
- **Null-argument guards preserved.** Every `Encode`/`Decode` throws `ArgumentNullException` on null before touching any backend, ported verbatim from the old services (BC would NRE instead).
- **Base32 ported verbatim.** The bit-shift buffer logic, `ReverseLookup` table, and padding loop are carried over: canonical uppercase `'='`-padded encode; decode tolerant of lowercase/mixed-case/embedded-whitespace/missing-padding; `FormatException` for characters outside the RFC 4648 alphabet (0/1/8/9). These asymmetric behaviors are locked by tests, not the signature.
- **Empty-input round-trip preserved** for all three schemes (`Encode([])→""`, `Decode("")→[]`).
- **Decode parameter name `encoded`** adopted from the frozen interface in all three impls (fresh library, no external callers).

### Open for PR
- None. Every divergence in the spec is resolved by a decision or by the confirmed no-options parity finding. No leftover parity items for this feature.

## Test plan
Port all four old test classes to `tests/Enigma.Core.UnitTests` under namespace `Enigma.Core.UnitTests.Encoding`, switching `using` to `Enigma.Core.Encoding` and adapting to the frozen member names. All vectors are inline — NO CSV vector files for this feature (unlike Hash/Hmac/BlockCiphers).

Ported vectors / cases to keep verbatim:
- RFC 4648 §10 Base32 vectors, both directions: `""`→`""`, `f`→`MY======`, `fo`→`MZXQ====`, `foo`→`MZXW6===`, `foob`→`MZXW6YQ=`, `fooba`→`MZXW6YTB`, `foobar`→`MZXW6YTBOI======`.
- Base64 known vector: `"Hello, World!"`→`SGVsbG8sIFdvcmxkIQ==` + round-trip.
- Hex lowercase vectors: `"Hello"`→`48656c6c6f`, `{0x00,0xFF,0x10}`→`00ff10` + round-trip (locks the lowercase-casing decision).
- Base32 tolerant-decode (lowercase / mixed-case / embedded-whitespace), missing-padding, and invalid-character (`FormatException`) cases.
- Round-trip and empty-input cases for all three schemes.
- `EncodingServiceFactory` `IsType` assertions for each `Create*Service`.

New tests the redesign warrants:
- Base64 **whitespace-tolerant decode** test — locks the internal-BC-backend decision (built-in `Convert` would reject it).
- `ArgumentNullException` test for each `Encode`/`Decode` across all three schemes.
- **Reflection test proving NO public member exposes a BouncyCastle type**: enumerate all public types in the `Enigma.Core.Encoding` namespace and assert no `Org.BouncyCastle` type appears in any parameter type, return type, base type, or interface — proves principle 1.
- `EncodingExtensions` Base64/Hex/Base32 round-trip tests (moved here from foundation per `orchestrator_impl_choices`).

No vectors require regeneration for this feature (the SHA3/Argon2/PQC regeneration notes apply to other features). The library must build/test clean across `netstandard2.0;net8.0;net10.0`; the test project targets net10.0.

## Dependencies
- **FEATURE-61D1 (foundation) must land first.** It adds the `BouncyCastle.Cryptography` + `System.Buffers` package references this feature's Base64/Hex impls consume, ports the `CsvData` + `SyncProgress<T>` test harness, and ports `EncodingExtensions` (which compiles against the frozen Encoding stubs). This feature adds no package refs of its own.
- No other feature is a prerequisite. Note the reverse direction: OTP (FEATURE-5761) depends on Encoding via `OtpProvisioningService` consuming `IEncodingServiceFactory` (Base32), so this feature should land before OTP.

## Phases
Single-phase — no phase subsections.

## Acceptance criteria
- `Enigma.Core` builds clean with **zero warnings** under `TreatWarningsAsErrors` across all three TFMs — `netstandard2.0`, `net8.0`, `net10.0` (CS1591 doc coverage included).
- **No `Org.BouncyCastle` type** appears in any public signature, return type, base type, or public support-type member of `Enigma.Core.Encoding` — verified by the reflection test (green).
- All ported RFC 4648 §10 Base32 vectors pass in both encode and decode directions.
- Base64 encodes `"Hello, World!"` to `SGVsbG8sIFdvcmxkIQ==` and round-trips; Base64 decode tolerates embedded whitespace; Hex encodes to LOWERCASE (`48656c6c6f`, `00ff10`) and round-trips.
- Base32 decode is tolerant of lowercase, mixed case, embedded whitespace, and missing padding, and throws `FormatException` for characters outside the RFC 4648 alphabet.
- Empty input round-trips to empty for all three schemes; null input throws `ArgumentNullException`.
- `EncodingServiceFactory.CreateBase64Service`/`CreateBase32Service`/`CreateHexService` return working encoders of the correct concrete type.
- The FEATURE-4442 source-parity note (member names; Hex/Base32 casing/padding options) is resolved in the plan and the internal-BouncyCastle-backend decision is recorded.
- `EncodingExtensions` round-trip tests pass.
- Roadmap/plan status updated; `docs/done/FEATURE-0399.md` written.
