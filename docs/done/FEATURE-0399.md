# FEATURE-0399 — Encoding implementation (Base64, Hex, Base32)

- **Status:** DONE
- **Type:** FEATURE (single-phase)
- **Branch:** `feature/feature-0399-encoding` (cut from `feature/feature-61d1-foundation` @ `8226112`)
- **Scope:** `DataEncoding` module.

## Summary
Implemented the three textual encoders behind the frozen `Enigma.Core.Encoding` contract, replacing
the FEATURE-4442 `NotImplementedException` stubs with the working behavior:

1. **`Base64Service`** — delegates to `Org.BouncyCastle.Utilities.Encoders.Base64` (internal only):
   canonical padded encode; whitespace-tolerant decode.
2. **`HexService`** — delegates to `Org.BouncyCastle.Utilities.Encoders.Hex` (internal only): lowercase
   encode; case-insensitive decode.
3. **`Base32Service`** — pure RFC 4648 bit-shift implementation, **no BouncyCastle**: canonical
   uppercase `'='`-padded encode; decode tolerant of case, embedded whitespace and missing padding;
   `FormatException` for characters outside the alphabet.
4. **`EncodingServiceFactory`** — returns a fresh per-scheme instance per `Create*Service` call, in the
   frozen declaration order Base64 / Base32 / Hex.

BouncyCastle stays entirely internal to Base64/Hex; it appears in no public signature, return type,
base type or field. Null guards (`ArgumentNullException`) are preserved on every `Encode`/`Decode`
before any backend call. The `Decode` parameter is named `encoded`, matching the frozen interface.

## Files / modules touched

### Modified — library (`src/Enigma.Core/Encoding/`)
- `Base64Service.cs` — implemented (BC `Base64` encoder, internal); null guards; XML docs note
  whitespace-tolerant decode.
- `HexService.cs` — implemented (BC `Hex` encoder, internal); null guards; XML docs note lowercase output.
- `Base32Service.cs` — ported verbatim (alphabet, `ReverseLookup`, bit-shift encode/decode, padding loop);
  `Decode` param renamed `data`→`encoded`; null guards.
- `EncodingServiceFactory.cs` — implemented; one new instance per `Create*Service`.

(The interfaces `IEncodingService.cs` / `IEncodingServiceFactory.cs` were already frozen by FEATURE-4442
and needed no change.)

### Created — tests (`tests/Enigma.Core.UnitTests/`)
- `Encoding/Base32ServiceTests.cs` — RFC 4648 §10 vectors (both directions), round-trip, empty-input,
  tolerant decode (lowercase / mixed / whitespace), missing-padding, invalid-character `FormatException`,
  null guards.
- `Encoding/Base64ServiceTests.cs` — round-trip, `"Hello, World!"`→`SGVsbG8sIFdvcmxkIQ==`, empty-input,
  **embedded-whitespace decode** (locks the internal-BC-backend decision), null guards.
- `Encoding/HexServiceTests.cs` — round-trip, lowercase known vectors (`48656c6c6f`, `00ff10`),
  empty-input, null guards.
- `Encoding/EncodingServiceFactoryTests.cs` — `IsType` assertions per `Create*Service`, plus a
  fresh-instance-per-call check.
- `Encoding/EncodingBouncyCastleIsolationTests.cs` — reflection guard scoped to the
  `Enigma.Core.Encoding` namespace, proving no `Org.BouncyCastle` type reaches its public surface.
- `Extensions/EncodingExtensionsRoundTripTests.cs` — the Base64/Hex/Base32 half of `EncodingExtensions`
  (moved here from the foundation, where the services were stubs), with round-trip, known-vector and
  empty-input cases.

## Deviations & follow-ups
- **Encoding-scoped reflection test is intentionally additive.** An assembly-wide
  `Api/BouncyCastleIsolationTests` (from FEATURE-61D1) already covers the whole public surface,
  including the Encoding types. The plan nonetheless calls for a namespace-scoped reflection test as an
  explicit acceptance criterion; the new `EncodingBouncyCastleIsolationTests` ties that criterion
  directly to a green test and adds a sanity assertion that the reflection scope actually finds the
  three services. This overlaps the assembly-wide guard by design — no redesign of the plan.
- **No CSV vectors.** As planned, all vectors are inline `[InlineData]`; the CSV harness is reserved for
  Hash/Hmac/BlockCiphers.
- **No package references added.** `BouncyCastle.Cryptography` (all TFMs) was already provided by the
  foundation (FEATURE-61D1); this feature only consumes it.
- **Line endings:** no CRLF/line-ending anomalies observed in the touched files; no action taken
  (recommendation-only per workflow).
- No open parity items remain (plan §"Open for PR" = none).

## Build / test evidence
- **Build:** `dotnet build -c Release` → **Build succeeded, 0 Warning(s), 0 Error(s)** across all three
  library TFMs (`netstandard2.0;net8.0;net10.0`) under `TreatWarningsAsErrors` + `GenerateDocumentationFile`
  (CS1591 doc coverage satisfied).
- **Tests:** `dotnet test -c Release` → **192 passed, 0 failed, 0 skipped** across both test TFMs
  (`net8.0`, `net10.0`), including all new Encoding and `EncodingExtensions` tests and the reflection guard.
- **Acceptance criteria:** all met — RFC 4648 Base32 vectors both directions; Base64 known vector +
  whitespace-tolerant decode; lowercase Hex; Base32 tolerant decode + invalid-character `FormatException`;
  empty round-trips; null → `ArgumentNullException`; factory concrete-type assertions; no BC type on the
  Encoding public surface (reflection green); `EncodingExtensions` round-trips green.
