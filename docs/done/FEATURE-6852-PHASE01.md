# FEATURE-6852-PHASE01 — `RsaKey` + PBES2 write / three-format read (additive)

**Status:** DONE
**Type:** FEATURE (multi-phase, phase 1 of 2)
**Branch:** `feature/feature-6852-phase01-rsakey` (cut from `feature/feature-5413-phase02-mlkem-pem` @ `a32601e`)

## Summary

Added the `RsaKey` handle and moved the RSA module's PEM plumbing onto the shared
`Enigma.Core.Internal.PemEnvelope` created by FEATURE-5413-PHASE01. **Nothing was removed** — every
existing PEM-string overload on `IPublicKeyService` still exists and still behaves as before, which
is what keeps the whole suite green between the two halves of this item.

Three things landed:

1. **`RsaKey`** — a `public sealed class` in `Enigma.Core.Asymmetric.PublicKey` with exactly six
   public members: `KeySizeBits`, `HasPrivateKey`, `ImportPublicKeyPem`, `ImportPrivateKeyPem`,
   `ExportPublicKeyPem`, `ExportPrivateKeyPem`. It parses a PEM **once** so a later phase can drop
   the per-call re-parse (and the per-call passphrase) from the service. Its BouncyCastle key is
   reachable only through a plain `internal` `BcKey` property.
2. **`PemUtils` re-pointed at `PemEnvelope`.** All four members keep their exact signatures and their
   `internal` visibility; each is now a thin delegate. The `AES-256-CBC` constant, the `PemReader` /
   `PemWriter` use and the BouncyCastle exception mapping are all gone from the file — they exist
   once, in `PemEnvelope`.
3. **The encrypted private-key write format changed to PBES2**, as a consequence of (2).

### The format change, and why reading did not break

Writing an encrypted private key moved from the traditional OpenSSL envelope
(`RSA PRIVATE KEY` + `Proc-Type: 4,ENCRYPTED` + `DEK-Info: AES-256-CBC`, keyed by OpenSSL's legacy
`EVP_BytesToKey` — MD5, a single iteration) to **PBES2** (`ENCRYPTED PRIVATE KEY`,
PBKDF2-HMAC-SHA256 at 600 000 iterations, AES-256-CBC, 16-byte salt).

**Reading accepts all three forms** — unencrypted PKCS#8, traditional OpenSSL, and PBES2 — so
existing user key files keep working. The API breaks in PHASE02; the file format does not.

The unencrypted write path is byte-for-byte unchanged in shape (PKCS#8 `PRIVATE KEY`), so
`X509CertificateService.cs:199`, which writes with `password: null`, is unaffected. The certificate
fixture's encrypted key simply becomes PBES2, which the read path accepts — all 162 certificate
tests pass **unmodified**.

### Fixture-before-flip ordering

The plan's ordering constraint was honoured literally: **the legacy fixture was generated first**,
against the unmodified writer, before `PemUtils` was touched. A throwaway console project referencing
the then-current `Enigma.Core` called `GenerateRsaKeyPair(2048, "legacy1234")`, asserted the output
carried `BEGIN RSA PRIVATE KEY` + `Proc-Type` + `DEK-Info`, and wrote it to
`tests/Enigma.Core.UnitTests/PublicKey/pk_key_legacy_encrypted.pem` (LF-normalized).

That file is now the library's **only** producer of the traditional OpenSSL format. Had the writer
flipped first, the backward-compatibility guarantee would have become untestable.

No `.csproj` edit was required, exactly as the plan predicted: the existing `<None Update="**/*.pem">`
glob copies it to the test output directory.

### The two re-based assertions

Both changes were deliberate format re-basings, not weakenings:

- `RsaKeyGenerationTests.GenerateRsaKeyPair_WithPassword_ProducesAes256CbcEncryptedPrivateKeyPem` →
  **`…_ProducesPbes2EncryptedPrivateKeyPem`**. It now asserts `BEGIN ENCRYPTED PRIVATE KEY` and the
  *absence* of `RSA PRIVATE KEY`, `Proc-Type` and `DEK-Info` — a strictly stronger statement than the
  three `Contains` it replaced.
- `RsaArgumentValidationTests.PrivateKeyOperation_UnsupportedDekAlgorithm_ThrowsArgumentException`
  built its input by string-replacing `DEK-Info: AES-256-CBC` in freshly generated output, which no
  longer contains that header. It now string-replaces in the committed legacy fixture instead. The
  behaviour it pins is unchanged: an unrecognised DEK cipher is a structural PEM defect →
  `ArgumentException`.

No other test file was modified. `git diff --stat -- tests/` covers exactly those two files.

## Files/modules touched

**Created — product**
- `src/Enigma.Core/Asymmetric/PublicKey/RsaKey.cs` — the handle.

**Modified — product**
- `src/Enigma.Core/Asymmetric/PublicKey/PemUtils.cs` — rewritten as a thin adapter over `PemEnvelope`
  (129 → 51 lines). Keeps its four signatures, its `internal` visibility and its
  `ArgumentNullException` guards (the PEM-string API contract, and what
  `Certificates/X509CertificateService.cs` depends on at lines 36, 57, 89, 183 and 199).

**Created — tests**
- `tests/Enigma.Core.UnitTests/PublicKey/RsaKeyTests.cs` — 36 test cases.
- `tests/Enigma.Core.UnitTests/PublicKey/pk_key_legacy_encrypted.pem` — traditional-OpenSSL encrypted
  RSA-2048 fixture, passphrase **`legacy1234`** (recorded in both tests that read it).

**Modified — tests**
- `tests/Enigma.Core.UnitTests/PublicKey/RsaKeyGenerationTests.cs` — one test re-based + renamed.
- `tests/Enigma.Core.UnitTests/PublicKey/RsaArgumentValidationTests.cs` — the `DEK-Info`
  characterization test re-based on the committed fixture.

**Modified — docs (documentation freshness sweep, accepted)**
- `README.md:21` — the RSA feature line said "optionally AES-256-CBC-encrypted private keys"; now
  "PBES2-encrypted", matching the PQC line directly beneath it.
- `docs/guides/public-key.md` — the three places describing the encrypted write format
  (the "Protecting the private key with a passphrase" lead-in, the sample's inline comment, and the
  *Encrypted private keys* note) now say PBES2, and a new note states that reading still accepts all
  three forms so older key files keep loading. Accuracy edits only — the guide is rewritten wholesale
  in PHASE02.

**Untouched, deliberately**
- `src/Enigma.Core/Internal/PemEnvelope.cs` — out of scope; **no change was needed**, so no deviation
  to record there.
- `IPublicKeyService` / `PublicKeyService` — PHASE02.
- All `Certificates/` product code and tests.

## Deviations & follow-ups

- **`pk_key1.pem` is a 4096-bit key, not 2048.** The plan describes it only as "a PBES2
  `ENCRYPTED PRIVATE KEY` file (passphrase `test1234`)" and says nothing about its size; an initial
  2048 assertion failed against it. Turned to advantage: `ImportPrivateKeyPem_Pbes2Fixture_Succeeds`
  now asserts `KeySizeBits == 4096`, giving `KeySizeBits` a second, independently-sized witness
  alongside the 2048/3072 theory.
- **`RsaKey` construction is a private constructor plus an `internal static FromBcKey` factory.** The
  plan allowed "an `internal` constructor or factory"; the factory form was chosen so PHASE02's
  `GenerateRsaKey` has a construction point that is already exercised in this phase rather than
  arriving unused.
- **Non-RSA rejection is covered using ML-DSA PEMs.** `RsaKey.Import*` must reject a structurally
  valid PEM carrying another key family; the cheapest real witness is an ML-DSA-44 key pair from
  `MLDsaPemService`. This is the only cross-module reference in the new test file.
- **Acceptance criteria 3, 6 and 11 of the item preamble are now discharged for `PemEnvelope`.** This
  phase is the first place `PemEnvelope`'s `AsymmetricCipherKeyPair` unwrap (the traditional OpenSSL
  envelope decodes to a key pair, not a bare key) and its exception-mapping branches 1 and 4 become
  observable through a public API — FEATURE-5413-PHASE01 specified them but had no RSA caller to
  assert them. Both are now covered by `ImportPrivateKeyPem_LegacyTraditionalOpenSsl_Succeeds` and
  the four passphrase-failure tests.
- **Line endings:** no CRLF noise observed. Every touched file — including the generated `.pem`
  fixture, which was explicitly LF-normalized before being written — is LF-only, consistent with
  `.gitattributes` `* text=auto eol=lf`. No action taken or recommended.
- **Follow-up (PHASE02):** `PublicKeyBouncyCastleIsolationTests`'s doc comment still describes the
  surface as "PEM strings … and the `(string, string)` key-pair tuple". The guard walks the namespace
  by reflection, so it already covers `RsaKey` and is green; the prose is updated in PHASE02, where
  the plan schedules it.
- **Doc sweep accepted, scoped to accuracy.** `README.md` and `docs/guides/public-key.md` were
  corrected in place (see *Files/modules touched*). Every code sample in the guide still targets the
  PEM-string API, which is still the real API in this phase — those samples become wrong only when
  PHASE02 cuts the surface, which is where the plan schedules the rewrite. Nothing was pre-emptively
  written against an API that does not exist yet.

## Build/test evidence

```
dotnet build Enigma.Core.slnx -c Release
  Build succeeded.  0 Warning(s)  0 Error(s)
  → netstandard2.0, net8.0, net10.0

dotnet test --solution Enigma.Core.slnx -c Release
  Test run summary: Passed!
  total: 3594   failed: 0   succeeded: 3594   skipped: 0
  → net8.0 and net10.0
```

**3522 → 3594 tests** (+72 = **36 new test cases × 2 test TFMs**). The two re-based tests were
renamed/re-pointed, not added or removed, so the delta is entirely `RsaKeyTests`.

Targeted re-runs, all green:

| Filter | Result |
|---|---|
| `--filter-class '*Isolation*'` | 22 passed, 0 failed |
| `--filter-namespace 'Enigma.Core.UnitTests.PublicKey'` | 170 passed, 0 failed |
| `--filter-namespace 'Enigma.Core.UnitTests.Certificates'` | 162 passed, 0 failed |

### Measured suite-time delta

The plan budgeted roughly **+5 s** for the extra PBES2 work. Measured against a read-only
`git archive a32601e` export of the pre-change tree, built and run identically on this machine
(two runs each):

| Tree | Run 1 | Run 2 | Mean |
|---|---|---|---|
| Before (`a32601e`, 3522 tests) | 10.10 s | 9.55 s | **9.8 s** |
| After (3594 tests) | 11.46 s | 12.23 s | **11.9 s** |

**Wall-clock delta ≈ +2.1 s (~+21 %)** — well inside budget. The gap between prediction and
measurement is parallelism, not a cheaper PBKDF2: total CPU time rose from ~1 m 16 s to ~1 m 35 s
(**≈ +19 s**, which is the ~600 ms-per-PBES2-pass cost the plan measured), but xUnit spreads that
across collections so most of it never reaches the wall clock. **The iteration count was not
lowered.**

## Acceptance criteria

| # | Criterion | Evidence |
|---|---|---|
| 1 | Legacy fixture committed, traditional-OpenSSL, copied to output | `pk_key_legacy_encrypted.pem`; `LegacyEncryptedFixture_IsInTheTraditionalOpenSslFormat` reads it from the output directory and asserts all three markers |
| 2 | Six public members, sealed, not `IDisposable`, plain `internal` BC member, XML-documented | `RsaKey_ExposesExactlyTheSixDocumentedPublicMembers`, `RsaKey_IsSealed_AndNotDisposable`, `RsaKey_ExposesItsBouncyCastleKeyOnlyAsPlainInternal` (which also asserts `!IsFamilyOrAssembly`); docs state immutable/thread-safe, cannot-be-wiped, and caller-owns-the-passphrase |
| 3 | All three private-key forms import | `ImportPrivateKeyPem_UnencryptedPkcs8_Succeeds`, `…_LegacyTraditionalOpenSsl_Succeeds`, `…_Pbes2Fixture_Succeeds` (`pk_key1.pem` / `test1234`) |
| 4 | Export → re-import round trip, unencrypted and encrypted | `ExportPrivateKeyPem_Unencrypted_ReImportsToAnEquivalentKey`, `…_Encrypted_…`; equivalence = byte-identical deterministic signature + cross-decryption + same public PEM + same size |
| 5 | `ExportPrivateKeyPem(pwd)` → `ENCRYPTED PRIVATE KEY`, no `Proc-Type`/`DEK-Info`; no-arg → `PRIVATE KEY` | `ExportPrivateKeyPem_WithPassword_EmitsPbes2`, `…_NoPassword_EmitsUnencryptedPkcs8` |
| 6 | Wrong and missing password → `CryptographicException`, on legacy **and** PBES2 | the four `ImportPrivateKeyPem_{Pbes2,Legacy}_{Wrong,Missing}Password_…` tests |
| 7 | `KeySizeBits` 2048/3072; `HasPrivateKey` true/false | `KeySizeBits_ReportsTheModulusSize` (theory), plus 4096 from the fixture; `HasPrivateKey_DistinguishesTheTwoKindsOfHandle` |
| 8 | `ExportPrivateKeyPem` on public-only → `InvalidOperationException`; `ExportPublicKeyPem` on private → verifying PEM | `ExportPrivateKeyPem_OnPublicOnlyHandle_ThrowsInvalidOperationException`, `ExportPublicKeyPem_OnPrivateHandle_DerivesTheVerifyingPublicHalf` (also asserts it equals the generator's own public PEM) |
| 9 | `null` → `ArgumentNullException`; empty/whitespace/malformed/wrong-type → `ArgumentException` naming `pem`; no BC exception escapes | two null tests, two 4-case theories, two wrong-kind tests, two non-RSA-family tests — all asserting `ParamName == "pem"` |
| 10 | `PemUtils` keeps four signatures + `internal`, no cipher constant, no reader/writer, no mapping | `PemUtils.cs` is 51 lines of delegation; the whole solution builds and all 3594 tests pass against it |
| 11 | Whole suite passes with only the two sanctioned assertion changes | `git diff --stat -- tests/` lists exactly `RsaKeyGenerationTests.cs` and `RsaArgumentValidationTests.cs` |
| 12 | All `Certificates` tests pass unmodified | 162 passed; no file under `tests/…/Certificates/` appears in the diff |
| 13 | Both isolation guards green with `RsaKey` exported | `--filter-class '*Isolation*'` → 22 passed |
| 14 | This document | records the format change, the fixture-before-flip ordering, the two re-based assertions, the measured suite-time delta, and build/test counts |
