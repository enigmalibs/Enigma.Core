# FEATURE-534F PHASE03 — StreamCiphers

- **Status:** DONE
- **Type:** FEATURE phase (3 of 3 — final; completes FEATURE-534F)
- **Branch:** `feature/feature-534f-phase03-streamciphers` (cut from `feature/feature-534f-phase02-blockciphers` @ `c0eacad`)
- **Basis:** ported from Enigma.Cryptography v5.0.0 (`/home/jo/Dev/Enigma.Cryptography`), `StreamCiphers` module.

## Summary
Implemented the stream-cipher subsystem behind the API frozen by FEATURE-4442 PHASE02, ported at maximum
fidelity from v5.0.0 and kept strictly BouncyCastle-free on the public surface. `StreamCipherService` and
`StreamCipherServiceFactory` now support ChaCha20 (original, 64-bit nonce), ChaCha20-RFC7539 (96-bit
nonce) and Salsa20, with per-call key/nonce. The public contract was already BC-free (frozen verbatim),
so only the stub bodies and internal wiring changed.

**Consistency with PHASE02.** The stream service reuses the exact patterns vetted by the PHASE02
adversarial review: the internal `Func<IBufferedCipher>` ctor (mirroring `HashService`/`BlockCipherService`),
the shared internal `NonDisposingStreamWrapper` (so the caller's streams are never closed), and a
`catch (CryptoException) → CryptographicException` wrap on both paths (so no BouncyCastle exception —
including the `MaxBytesExceededException` a ChaCha7539 keystream-limit overrun would raise — escapes).

### Members implemented
- **`StreamCipherService`** — internal `(Func<IBufferedCipher>, bufferSize)` ctor (positive-buffer guard);
  streaming encrypt/decrypt via `CipherStream` + `ArrayPool<byte>` (buffer cleared on return, wrapped in
  `NonDisposingStreamWrapper`); null-guards on input/output/key/nonce; `ParametersWithIV(KeyParameter, nonce)`
  built in a private `CreateInitializedCipher`.
- **`StreamCipherServiceFactory`** — the three `Create*Service(bufferSize)` members, each binding a
  BouncyCastle engine (`ChaCha7539Engine` / `ChaChaEngine` / `Salsa20Engine`) wrapped in a
  `BufferedStreamCipher` into a `StreamCipherService`.

(`IStreamCipherService`, `IStreamCipherServiceFactory` were already frozen correctly and are BC-free — no
change. No AAD/mode/padding concepts apply to stream ciphers.)

## Files / modules touched

### Modified — library (`src/Enigma.Core/Symmetric/StreamCiphers/`)
- `StreamCipherService.cs` — implemented (streaming, validation, non-disposing wrapper, exception wrapping).
- `StreamCipherServiceFactory.cs` — implemented the three `Create*Service` members.

(No new library files — `NonDisposingStreamWrapper` from PHASE02 is reused across the assembly.)

### Created — tests (`tests/Enigma.Core.UnitTests/StreamCiphers/`)
- `StreamCipherKat.cs` (shared KAT helper), `ChaCha20Tests`, `ChaCha20Rfc7539Tests`, `Salsa20Tests`
  (encrypt + decrypt KAT, 20 vectors each).
- `StreamCipherServiceFactoryTests` — three services, fresh-per-call, bufferSize guard.
- `StreamCipherValidationTests` — null input/output/key/nonce guards.
- `StreamCipherStreamLifetimeAndSizeTests` — caller streams left open, multi-buffer round-trip,
  progress reporting, pre-cancelled-token cancellation.
- `SymmetricStreamCipherBouncyCastleIsolationTests` — namespace-scoped principle-1 reflection guard.

### Created — test vectors (`tests/Enigma.Core.UnitTests/StreamCiphers/`)
- `chacha20.csv`, `chacha20rfc7539.csv`, `salsa20.csv` — ported verbatim (20 rows each); auto-copied by
  the test project's existing `**/*.csv` glob.

## Adversarial review
A focused adversarial review (single agent, decompiling BouncyCastle 2.6.2 to verify exception behaviour
rather than assume it) found **no defects**. It confirmed: no BouncyCastle type on the public surface; no
BouncyCastle exception can escape (`MaxBytesExceededException : CryptoException` is caught during the
read/write loop; `Init` throws only BCL `ArgumentException`/`InvalidOperationException` for bad key/nonce
length, which is the correct, non-leaking response); caller streams are never disposed; the pooled buffer
is returned+cleared on all paths (rented after `Init`, so an `Init` throw leaks nothing); calls are
thread-safe; and only the netstandard2.0-safe array-based async overloads are used. Two non-defect
observations were noted (wrong key/nonce length surfaces as a BCL `ArgumentException`, not tied to any
Phase C criterion; no dedicated empty-input/wrong-length test — optional hardening).

## Deviations & follow-ups
- **Public `Func<IBufferedCipher>` / JCA-string constructors dropped** (design, per the frozen redesign):
  reintroduced only as the internal `Func<IBufferedCipher>` engine ctor.
- **Improvements over the verbatim v5.0.0 port** (consistent with PHASE02; no change to cryptographic
  behaviour): all BouncyCastle cipher exceptions wrapped in `CryptographicException`, and caller streams
  no longer disposed (via the shared `NonDisposingStreamWrapper`).
- **Optional hardening (not blocking):** dedicated tests for wrong key/nonce length and empty-input
  round-trip could be added; both behave correctly today and neither maps to a Phase C acceptance
  criterion.
- **Line endings:** no CRLF/line-ending anomalies observed in the touched files (all LF); no action taken
  (recommendation-only per workflow).

## Build / test evidence
- **Build:** `dotnet build -c Release` → **Build succeeded, 0 Warning(s), 0 Error(s)** across all three
  library TFMs (`netstandard2.0;net8.0;net10.0`) under `TreatWarningsAsErrors` +
  `GenerateDocumentationFile` + `EnforceCodeStyleInBuild`.
- **Tests:** `dotnet test` → **2902 passed, 0 failed, 0 skipped** across both test TFMs (`net8.0`,
  `net10.0`); +270 over PHASE02's 2632. The StreamCiphers namespace contributes 135 tests per TFM,
  confirmed via `--filter-namespace Enigma.Core.UnitTests.StreamCiphers`.
- **Acceptance criteria (PHASE03):** all met — ChaCha20 / ChaCha20-RFC7539 / Salsa20 KAT vectors pass
  (encrypt + decrypt, 20 rows each); no BouncyCastle type on the public stream surface (namespace-scoped +
  assembly-wide reflection guards green); progress reported and a pre-cancelled token throws
  `OperationCanceledException`; every service/factory member no longer throws `NotImplementedException`;
  XML docs on every public member.

## FEATURE-534F — complete
With PHASE03 done, the whole Symmetric feature is complete: **Padding** (PHASE01), **BlockCiphers** —
12 algorithms × 4 modes incl. GCM + AAD (PHASE02), and **StreamCiphers** (PHASE03). The FEATURE-534F
roadmap row is flipped to DONE.
