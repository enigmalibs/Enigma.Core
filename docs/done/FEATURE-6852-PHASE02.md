# FEATURE-6852-PHASE02 — Cut the PEM-string surface (BREAKING)

**Status:** DONE
**Branch:** `feature/feature-6852-phase02-breaking-cut`
**Plan:** `docs/plan/FEATURE-6852.md` (PHASE02)

## Summary

`IPublicKeyService` now takes keys as `RsaKey` handles and nothing else. Every PEM-string overload and
`GenerateRsaKeyPair` were **deleted outright** — no `[Obsolete]` shim, no transitional overload, no
"legacy" namespace — leaving exactly the seven members the plan specifies. The `char[] password`
parameter is gone from the whole service: a passphrase is supplied once, at
`RsaKey.ImportPrivateKeyPem`, and never again.

The consequence the item exists for: a private key is parsed and CRT-validated **once per key** instead
of once per call. In the 1.x shape, ~84 % of a `Sign(data, encryptedPem, password)` call was key
reconstruction.

Three things beyond the mechanical retype were needed:

1. **A derived public half for the public operations.** Design decision 7 says a private-holding handle
   is accepted by `Verify` / `EncryptPkcs1` / `EncryptOaep`. That cannot be satisfied by passing
   `key.BcKey` through: BouncyCastle's `RsaCoreEngine` selects the private exponentiation from the
   **key type alone**, not from the cipher's direction, so handing it a private key would silently
   perform the wrong operation (and `RsaDigestSigner` rejects a private key for verification outright).
   `RsaKey` therefore gained an `internal RsaKeyParameters BcPublicKey` — `BcKey` when the handle is
   public-only, the CRT-derived public key otherwise — and every public operation reads that. It also
   removed the duplicate derivation: `ExportPublicKeyPem()` is now one line over the same member.
2. **`GenerateRsaKey` hands out the private half only**, wrapped by `RsaKey.FromBcKey`. It is a CRT key,
   so the public half stays derivable and one handle covers both directions.
3. **Guard order per method**, as the plan prescribes: `ArgumentNullException` for
   `data`/`ciphertext`/`signature`/`key`, then the private-key-required check
   (`ArgumentException`, `paramName: "key"`), then the operation.

## Files/modules touched

### Product code (modified)

| File | Change |
|---|---|
| `src/Enigma.Core/Asymmetric/PublicKey/IPublicKeyService.cs` | reduced to the seven specified members; XML docs rewritten around the handle, the once-only passphrase, and `ArgumentException` for a public-only handle |
| `src/Enigma.Core/Asymmetric/PublicKey/PublicKeyService.cs` | rewritten against `RsaKey`; **no reference to `PemUtils` remains**; `GenerateRsaKeyPair` → `GenerateRsaKey`; `RequirePrivate` helper carries the public-only guard |
| `src/Enigma.Core/Asymmetric/PublicKey/RsaKey.cs` | added `internal BcPublicKey` (see Deviations); `ExportPublicKeyPem` now delegates to it; two doc/comment updates for `GenerateRsaKey` now existing |

Not touched, as the plan requires: `PemUtils.cs` (still `internal`, still four signatures),
`Certificates/` product code, `PemEnvelope.cs`, `IPublicKeyServiceFactory` / `PublicKeyServiceFactory`,
`RsaOaepHash`, `RsaSignatureAlgorithm`.

### Tests (modified)

| File | Change |
|---|---|
| `PublicKey/RsaKeyFixture.cs` | holds `PrivateKey` / `PublicKey` handles; keeps `PrivateKeyPem` / `PublicKeyPem` for the import-side tests (see Deviations) |
| `PublicKey/RsaArgumentValidationTests.cs` | ported; the passphrase failure modes moved to `ImportPrivateKeyPem`; six PEM-guard facts retired into `RsaKeyTests` (see Deviations); +6 null-key, +3 public-only-handle, +2 further null/enum guards |
| `PublicKey/RsaEncryptDecryptTests.cs` | ported; +3 new: private-holding handle accepted by the public operations, cross-handle interoperability of the derived public half, and the import-once regression test |
| `PublicKey/RsaOaepTests.cs` | ported |
| `PublicKey/RsaServiceTests.cs` | ported — fixture PEMs now import to handles, passphrase supplied at the import |
| `PublicKey/RsaSignatureAlgorithmTests.cs` | ported |
| `PublicKey/RsaKeyGenerationTests.cs` | ported to `GenerateRsaKey`; the "caller's password array is not cleared" assertion moved onto `ExportPrivateKeyPem` |
| `PublicKey/RsaKeyTests.cs` | ported (**not in the plan's scope table** — see Deviations); the BC-member accessibility test became a theory covering `BcKey` **and** `BcPublicKey` |
| `PublicKey/PublicKeyBouncyCastleIsolationTests.cs` | doc comment rewritten for the handle surface; asserts `RsaKey` is in the walked type list |
| `Certificates/CertificateKeyFixture.cs` | compile fix only — 5 sites, `GenerateRsaKey(2048).ExportPrivateKeyPem(...)`; one doc comment says PBES2 |
| `Certificates/Pkcs12Tests.cs` | compile fix only — 3 sites (`:39`, `:49`, `:50`) exactly as the plan specifies |
| `Pqc/MLDsaPemErrorTests.cs`, `Pqc/MLKemPemErrorTests.cs` | compile fix only — one `RsaPems()` helper each (**not in the plan's scope table** — see Deviations) |

### Tests (created)

| File | Purpose |
|---|---|
| `PublicKey/PublicKeyServiceSurfaceTests.cs` | machine-checks acceptance criteria 1 and 3: exactly seven members, no `char[]` and no `string` parameter or return anywhere on the interface, no `[Obsolete]` on any exported type or member in the namespace |

### Docs

| File | Change |
|---|---|
| `docs/guides/public-key.md` | **rewritten** (~256 lines changed): handle-based intro, `RsaKey` in the key-types table, both surfaces listed, a "which handle can do what" section, seven reworked samples, and a **Migration** section (seven-row table, worked passphrase example, the read-compatibility guarantee, why it is not `IDisposable`) |
| `docs/guides/certificates.md` | minimal fix — 4 RSA snippets, the `IPublicKeyService` row, the `GenerateRsaKeyPair` note bullet (now PBES2 + read compatibility), and "key pair" → "key" wording |
| `README.md` | doc sweep — the "Public-key (RSA)" feature bullet now leads with the `RsaKey` handle and the once-only passphrase |
| `docs/guides/README.md` | doc sweep — the public-key guide's index line mentions the handle |
| `docs/roadmap.md`, `docs/plan/FEATURE-6852.md` | PHASE02 → `IN PROGRESS` → `DONE`; the item's own row flips to `DONE` |

## Deviations & follow-ups

- **`RsaKey` gained one `internal` member.** The plan's design step 2 says "every method reads
  `key.BcKey`". Followed literally, the public operations would be wrong — see point 1 of the Summary.
  `internal RsaKeyParameters BcPublicKey` is the fix; it stays plain `internal` (never
  `protected internal`), keeps `RsaKey`'s **public** surface at the six members PHASE01 pinned, and
  `RsaKeyTests` now asserts its accessibility alongside `BcKey`'s. Both isolation guards stay green.
- **Three files the plan's PHASE02 scope table does not list** had to change, because they were created
  or last touched *by* PHASE01, after the plan was written:
  - `PublicKey/RsaKeyTests.cs` — PHASE01's own new test file, which drove the service through PEM
    strings in ~10 places. Ported like its siblings; every assertion kept, several strengthened by
    running against handles directly.
  - `Pqc/MLDsaPemErrorTests.cs` and `Pqc/MLKemPemErrorTests.cs` — one `GenerateRsaKeyPair(2048)` each,
    used to mint a wrong-key-family fixture. Mechanical two-line fix; no assertion touched.
- **The fixture keeps its two PEM properties.** The plan says `RsaKeyFixture` "holds an `RsaKey`
  instead of two PEM strings"; it now holds both handles *and* the PEMs, because the import-side tests
  (`RsaKeyTests`, and the malformed/wrong-kind guards) need real PEM text and re-exporting per access
  would be wasted work. The handles are what the service tests use.
- **Six PEM-guard facts in `RsaArgumentValidationTests` were retired rather than duplicated.** The plan
  says they "move to the `RsaKey.Import*` call site" — but PHASE01's `RsaKeyTests` already asserts
  exactly that, and more (it also pins `ParamName == "pem"`). Their two distinct inputs (`"garbage"`,
  `"not a pem at all"`) were folded into `RsaKeyTests`'s two malformed-PEM theories so no input is lost,
  and `RsaArgumentValidationTests` carries a `<remarks>` pointing at where the coverage lives. Net
  effect: the same guarantees, asserted once, with the parameter name checked.
- **`ExportPublicKeyPem`'s `InvalidOperationException` branch is now also reachable through the
  service.** A private handle that is not a CRT key would make a public operation throw
  `InvalidOperationException` rather than a key-argument error. It stays unreachable in practice —
  BouncyCastle's `PrivateKeyFactory` always produces `RsaPrivateCrtKeyParameters` for RSA, so no
  importable PEM can produce such a handle — and it is defensive in both places for the same reason.
- **`RsaKeyGenerationTests` no longer tests a password at generation time**, because
  `GenerateRsaKey` takes none. The passphrase assertions it owned (`DoesNotClearCallerPassword`,
  encrypted-format, encrypted re-parse) moved onto `ExportPrivateKeyPem` / `ImportPrivateKeyPem`, where
  the passphrase now lives.
- **Line endings:** no CRLF/LF churn observed in this dev's diff; the repository already normalizes via
  `.gitattributes` `* text=auto eol=lf`. No action taken or recommended.
- **Follow-up (FEATURE-57A9):** `X509CertificateService` still takes private keys as PEM text with a
  `password` parameter, so `PemUtils` survives and `CertificateKeyFixture` exports each generated handle
  straight back to PEM. That is the next item, exactly as the plan schedules it.
- **Follow-up (recorded, not built):** `RsaKey.ExportRsaParameters` / `ImportRsaParameters` for
  `System.Security.Cryptography` interop, and a public-only projection such as
  `RsaKey.ExtractPublicKey()` — the internal `BcPublicKey` added here would make the latter a two-line
  addition. Both remain out of scope per the plan.
- **Doc sweep accepted, both candidates.** `README.md`'s feature bullet and `docs/guides/README.md`'s
  index line each described the module in one line that predated the handle — neither was wrong, both
  were incomplete. `RELEASENOTES.md` was deliberately left alone: the 2.0.0 notes belong to
  FEATURE-19C7, which this document supplies the copy for. `CLAUDE.md` and `SECURITY.md` needed nothing.
- **Doc-tooling note:** PHASE01's completion doc records targeted re-runs as
  `--filter-class` / `--filter-namespace`; this runner takes `-class` / `-namespace` (single dash). The
  numbers below were collected with the working form.

## Build/test evidence

```
dotnet build Enigma.Core.slnx -c Release
  Build succeeded.  0 Warning(s)  0 Error(s)
  → netstandard2.0, net8.0, net10.0

dotnet test --solution Enigma.Core.slnx -c Release
  Test run summary: Passed!
  total: 3626   failed: 0   succeeded: 3626   skipped: 0
  duration: 11s 395ms
  → net8.0 (11s 270ms) and net10.0 (11s 296ms)
```

**3594 → 3626 tests** (+32 = **16 new test cases × 2 test TFMs**), all of them in the `PublicKey`
namespace:

| Class | Before | After | Δ |
|---|---|---|---|
| `RsaKeyTests` | 36 | 39 | +3 (BC-member theory ×2, two malformed-PEM theories +1 input each) |
| `RsaArgumentValidationTests` | 19 | 24 | +5 (+6 null-key, +3 public-only-handle, +2 null/enum, −6 retired PEM guards) |
| `RsaEncryptDecryptTests` | 4 | 7 | +3 (public ops on a private handle, cross-handle interop, import-once regression) |
| `RsaKeyGenerationTests` | 8 | 10 | +2 |
| `PublicKeyServiceSurfaceTests` | 0 | 3 | +3 (new file) |

Targeted re-runs (net10.0; double for both TFMs), all green:

| Filter | Result |
|---|---|
| `-class '*Isolation*'` | 11 passed, 0 failed |
| `-namespace 'Enigma.Core.UnitTests.PublicKey'` | 101 passed, 0 failed (85 before → +16) |
| `-namespace 'Enigma.Core.UnitTests.Certificates'` | 81 passed, 0 failed (unchanged) |
| `-namespace 'Enigma.Core.UnitTests.Pqc'` | 180 passed, 0 failed (unchanged) |

Suite wall-clock is **11.4 s**, statistically unchanged from PHASE01's measured 11.9 s: this phase adds
no PBES2 pass to the common path — the fixture generates its key rather than importing an encrypted PEM,
and the one new encrypted round trip (`OneImportedHandle_ServesManyOperations_WithoutReImporting`) pays
for a single write + single read instead of the per-call re-parse the old API forced. **No security
constant was changed.**

## Acceptance criteria

| # | Criterion | Evidence |
|---|---|---|
| 1 | `IPublicKeyService` has exactly the seven members; no `[Obsolete]` anywhere in the item | `IPublicKeyService_ExposesExactlyTheSevenSpecifiedMembers` and `NoPublicKeyMember_IsMarkedObsolete` assert both by reflection; `grep -rn Obsolete src/` finds only a comment in `PemEnvelope.cs` describing a BouncyCastle base type |
| 2 | `PublicKeyService.cs` has no `PemUtils` reference; `grep PemUtils src/` matches only `PemUtils.cs` and `Certificates/X509CertificateService.cs` | verified — those are the only two source hits (remaining hits are generated `bin`/`obj` XML docs) |
| 3 | No `char[]` password parameter on `IPublicKeyService` | `IPublicKeyService_TakesKeysOnlyAsRsaKey_AndNoPassphrase` (also rejects any `string` parameter or return, so a PEM overload cannot creep back) |
| 4 | Generate → export → re-import → sign/verify **and** encrypt/decrypt, encrypted and unencrypted | `GenerateRsaKey_Unencrypted_RoundTripsThroughExportAndReImport`, `GenerateRsaKey_Encrypted_ReImportsWithPassword`, `GenerateRsaKey_RoundTripsThroughEncryptAndSign_OnTheHandleItself` |
| 5 | Public-only handle → `ArgumentException(paramName: "key")` on `Sign`/`DecryptPkcs1`/`DecryptOaep`; private-holding handle accepted by `Verify`/`EncryptPkcs1`/`EncryptOaep` | the three `…_PublicOnlyHandle_ThrowsArgumentExceptionNamingTheKey` tests; `PublicOperations_AcceptAPrivateHoldingHandle` and `PrivateHoldingHandle_EncryptsInteroperablyWithItsPublicOnlyCounterpart` |
| 6 | Every pre-existing behavioural assertion present; nothing dropped or weakened | PKCS#1 round-trip, all four OAEP hashes, mismatched hash, corrupt ciphertext, every `RsaSignatureAlgorithm`, both defaults, tampered/wrong message → `false`, all exception-type assertions, and "the caller's password array is not cleared" (now on `ExportPrivateKeyPem`, plus `ImportPrivateKeyPem_DoesNotClearCallerPassword` and the encrypted round trip) — see the Δ table for the six retired duplicates and where their inputs landed |
| 7 | Fixture-file tests still pass on `pk_key1.pem` (PBES2, `test1234`), `pub_key1.pem`, `pk_key_legacy_encrypted.pem` | `RsaServiceTests` (3), `RsaKeyTests.ImportPrivateKeyPem_{Pbes2Fixture,LegacyTraditionalOpenSsl}_Succeeds`, `LegacyEncryptedFixture_IsInTheTraditionalOpenSslFormat`, `ImportPrivateKeyPem_UnsupportedDekAlgorithm_ThrowsArgumentException` |
| 8 | All `Certificates` tests pass with only the mechanical edits in `CertificateKeyFixture.cs` (5 sites) and `Pkcs12Tests.cs` (3 sites); no certificate product file touched | 81 × 2 passed, count unchanged; `git diff --stat` lists exactly those two test files under `tests/…/Certificates/` and nothing under `src/…/Certificates/` |
| 9 | Both isolation guards green, `PublicKeyBouncyCastleIsolationTests` updated for `RsaKey` | `-class '*Isolation*'` → 11 passed; the guard now asserts `typeof(RsaKey)` is among the walked types, and its doc comment describes the handle surface |
| 10 | `public-key.md` rewritten with the migration section; `certificates.md`'s RSA snippets compile against the new API | the guide's Migration section carries the seven-row table verbatim, the old-vs-new passphrase example, the read-compatibility note and the not-`IDisposable` rationale; every `certificates.md` snippet now calls `GenerateRsaKey().ExportPrivateKeyPem()` |
| 11 | This document holds the release-note copy for FEATURE-19C7 plus the usual record; the item's roadmap row flips to `DONE` | below; roadmap updated |

---

## Release-note copy for FEATURE-19C7

Ready to paste. Written for a 2.0.0 release-notes "Breaking changes" section.

### RSA keys are now handles, not PEM strings (breaking)

`IPublicKeyService` no longer accepts PEM text. A key is parsed once into an `RsaKey` handle and that
handle is passed to every operation:

```csharp
RsaKey key = RsaKey.ImportPrivateKeyPem(pem, password);

byte[] signature = rsa.Sign(message, key);
byte[] plaintext = rsa.DecryptOaep(ciphertext, key);
```

Parsing an RSA private key costs far more than using it — BouncyCastle validates the CRT components on
construction — and the old API paid that cost on **every call**. For a 2048-bit key, roughly 84 % of a
`Sign(data, encryptedPem, password)` call was key reconstruction. Importing once removes it.

**Every PEM-string overload was removed outright.** There are no `[Obsolete]` members and no
compatibility shims.

| Removed | Replacement |
|---|---|
| `(string, string) GenerateRsaKeyPair(int, char[]?)` | `RsaKey GenerateRsaKey(int)` + `RsaKey.ExportPublicKeyPem()` / `ExportPrivateKeyPem(char[]?)` |
| `EncryptPkcs1(byte[], string)` | `EncryptPkcs1(byte[], RsaKey)` |
| `DecryptPkcs1(byte[], string, char[]?)` | `DecryptPkcs1(byte[], RsaKey)` |
| `EncryptOaep(byte[], string, RsaOaepHash)` | `EncryptOaep(byte[], RsaKey, RsaOaepHash)` |
| `DecryptOaep(byte[], string, RsaOaepHash, char[]?)` | `DecryptOaep(byte[], RsaKey, RsaOaepHash)` |
| `Sign(byte[], string, RsaSignatureAlgorithm, char[]?)` | `Sign(byte[], RsaKey, RsaSignatureAlgorithm)` |
| `Verify(byte[], byte[], string, RsaSignatureAlgorithm)` | `Verify(byte[], byte[], RsaKey, RsaSignatureAlgorithm)` |

#### The passphrase is supplied once, at the import

`DecryptPkcs1`, `DecryptOaep` and `Sign` no longer take a `char[] password` — no member of
`IPublicKeyService` does. Supply the passphrase to `RsaKey.ImportPrivateKeyPem` and reuse the handle:

```csharp
// 1.x — the passphrase travelled with every private-key call
byte[] signature = rsa.Sign(message, privateKeyPem, RsaSignatureAlgorithm.Sha256WithRsa, password);
byte[] recovered = rsa.DecryptOaep(ciphertext, privateKeyPem, RsaOaepHash.Sha256, password);

// 2.0.0 — supplied once, where the key is parsed
RsaKey key = RsaKey.ImportPrivateKeyPem(privateKeyPem, password);
byte[] signature = rsa.Sign(message, key, RsaSignatureAlgorithm.Sha256WithRsa);
byte[] recovered = rsa.DecryptOaep(ciphertext, key, RsaOaepHash.Sha256);
```

As before, the library never clears a passphrase array — the caller owns clearing it.

#### `GenerateRsaKeyPair` → `GenerateRsaKey`

A rename, not just a retype: one `RsaKey` carries both halves, so "key pair" no longer described the
return value. The single handle serves both directions — `Verify`, `EncryptPkcs1` and `EncryptOaep`
accept a private-holding handle and use its derived public half. Serialize either half with
`ExportPublicKeyPem()` / `ExportPrivateKeyPem(char[]?)`.

A public-only handle passed to `Sign`, `DecryptPkcs1` or `DecryptOaep` throws `ArgumentException`.

#### Encrypted private-key PEMs are now written as PBES2 — reading is unchanged

`ExportPrivateKeyPem(password)` emits a PKCS#8 `ENCRYPTED PRIVATE KEY` (PBKDF2-HMAC-SHA256 at 600 000
iterations + AES-256-CBC) instead of the traditional OpenSSL envelope (`RSA PRIVATE KEY` with
`Proc-Type`/`DEK-Info`), whose derivation was OpenSSL's legacy `EVP_BytesToKey` — MD5, a single
iteration.

**The file format did not break, only the API.** `ImportPrivateKeyPem` — and the certificate service —
read all three forms: unencrypted PKCS#8, PBES2, and the traditional OpenSSL envelope, including every
file earlier versions of this library wrote. No key file needs converting; to move one onto the stronger
derivation, import it and export it again. (An encrypted import now takes noticeably longer for that
reason: a one-time ~0.6 s per key, not per operation.)

#### `RsaKey` is not `IDisposable`

Deliberately. BouncyCastle holds RSA private components as arbitrary-precision integers — immutable
managed objects the garbage collector may copy — so there is no address a `Dispose` could reliably
overwrite, and offering one would imply a guarantee the runtime cannot make. Treat the lifetime of a
private handle as the lifetime of the secret.

#### Migration guide

`docs/guides/public-key.md` was rewritten for the new API and carries a **Migration** section with the
table above, the worked passphrase example, and the file-format compatibility details.
