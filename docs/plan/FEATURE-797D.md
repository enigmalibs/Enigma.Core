# FEATURE-797D — BouncyCastle 2.7.0 upgrade & v1.1.0 release

**Status:** TODO (multi-phase)
**Type:** FEATURE (multi-phase)
**Branch (per phase, at build time):** `feature/feature-797d-phaseNN-<slug>` — one branch per phase, cut from current `HEAD`.

## Objective

Move Enigma.Core's runtime dependency from **BouncyCastle.Cryptography 2.6.2 → 2.7.0**, prove that
nothing breaks — with particular attention to **ML-KEM** and **ML-DSA** — and then cut and prepare
the **v1.1.0** NuGet release.

No public API is added, removed or changed. The library's own behaviour is unchanged; the only
consumer-visible effect is the raised BouncyCastle floor.

## Context & constraints

- **Evolution of an existing, published codebase.** Enigma.Core 1.0.0 is on nuget.org and tagged
  `1.0.0` (bare tag format). The roadmap is otherwise fully `DONE`.
- Library multi-targets `netstandard2.0;net8.0;net10.0`; tests target `net8.0;net10.0`.
  **No TFM change this release** — BouncyCastle 2.7.0 still ships `netstandard2.0` / `net461` /
  `net6.0` assemblies, so nothing to log in a *Compatibility* TFM note.
- Central Package Management (`Directory.Packages.props`) — never put `Version=` on a
  `PackageReference`.
- Shared build gates: `TreatWarningsAsErrors=true`, `EnforceCodeStyleInBuild=true`,
  `Nullable=enable`, `ImplicitUsings=disable`, `LangVersion=14`. **An obsolescence warning is a build
  failure** — this is what turns two BouncyCastle deprecations into mandatory code edits.
- Tests are MTP-native (`xunit.v3` + `coverlet.collector`, no `Microsoft.NET.Test.Sdk`); 3254 tests
  across the two test TFMs.
- **Load-bearing invariant** — no `Org.BouncyCastle.*` type on the public surface
  (`tests/…/Api/BouncyCastleIsolationTests.cs` plus the per-category isolation tests). Both product
  edits in this item are inside `internal` code, so the invariant is untouched — but the guard tests
  must stay green.
- `.gitattributes` already enforces `eol=lf` and every file this item touches is LF —
  **no line-ending recommendation to make** (per `dev-workflow`, CRLF is recommendation-only and is
  never fixed inside a dev).
- Published/default branch for the runbook: **`main`**.

## Planning-time evidence (verified, re-confirm at build time)

The upgrade was executed during planning against a throwaway `git ls-files` snapshot of the tree
(the repository itself was not modified). Findings:

| Area | Result |
|---|---|
| Package availability | `BouncyCastle.Cryptography` **2.7.0** is published; license **MIT** (`Copyright © Legion of the Bouncy Castle Inc. 2000-2026`) — redistribution unaffected |
| TFMs shipped by 2.7.0 | `.NETFramework4.6.1`, `net6.0`, `.NETStandard2.0` — unchanged from 2.6.2 |
| **ML-KEM / ML-DSA public API** | **Additive only.** Added: `MLDsaPrivateKeyParameters.DefaultFormat` (`= SeedOnly`, `static readonly`), `MLKemParameterSet.EncapsulationLength`, `MLKemParameterSet.SecretLength`. **Nothing removed, nothing obsoleted.** |
| **ML-KEM / ML-DSA behaviour** | **Unchanged.** Generated encodings byte-identical (KEM-1024 pub 1568 / priv 3168; DSA-87 pub 2592 / priv 4896); `FromEncoding(GetEncoded())` round-trips; the pinned fixtures (`kem1024_A_private.key` + `encapsulation.bin` → `secret.bin`, and `dsa87_{A,B}_public.key` + `signature.bin`) produce identical results under both versions |
| `DefaultFormat = SeedOnly` | Affects BouncyCastle's **PKCS#8 / ASN.1** serialization default, **not** the raw `GetEncoded()` path this library uses — confirmed empirically (private key still 4896 bytes for ML-DSA-87 under 2.7.0) |
| Compile break 1 (`src/`) | `PemUtils.cs:67` → **CS0104**. 2.7.0 adds `Org.BouncyCastle.OpenSsl.PasswordException` and demotes `Org.BouncyCastle.Security.PasswordException` to its `[Obsolete]` base; the file imports both namespaces, so the bare name is ambiguous |
| Compile break 2 (`tests/`) | `Certificates/CertificateInfoTests.cs:141` → **CS0618**: `new DerInteger(int)` is obsolete (`Use ValueOf instead.`) |
| After both edits | Release build **clean, 0 warnings**, all three TFMs; **3254 / 3254 tests pass** on net8.0 and net10.0 |
| PEM exception mapping | Probed across both versions and **identical** — only the namespace moved. `wrong password → InvalidCipherTextException`, `no password → PasswordException`, `PKCS#8 bad password → PemException` are all already caught and mapped to `CryptographicException`. The one uncaught type, `EncryptionException` (reachable via an unknown `DEK-Info` algorithm), was **equally uncaught in 2.6.2** and falls through to `catch (IOException) → ArgumentException("malformed")` — a defensible mapping for an unsupported cipher header, and **not** a 2.7.0 regression |
| Other outdated packages | `coverlet.collector` 6.0.4 → **10.0.1** (test-only, `PrivateAssets=all`, never redistributed). `xunit.v3` 3.2.2, `PolySharp` 1.16.0, `System.Buffers` 4.6.1 are already latest |
| Docs referencing a BC version | `README.md:47`, `CLAUDE.md:68`, `docs/RELEASE.md:63`, `RELEASENOTES.md:34`. **None of the 13 guides under `docs/guides/` names a BouncyCastle version** |

This is a planning aid, not a substitute for the build-time run: `/build` re-executes the upgrade in
the repository and re-verifies everything from scratch.

## Design decisions (from the interview)

1. **Version = 1.1.0** (not a 1.0.1 patch). No public API is added, but raising the runtime
   dependency floor is consumer-visible — anyone pinned to BouncyCastle 2.6.x must move — which is
   more than a patch normally implies. SLH-DSA (FIPS 205), available in 2.7.0, was considered as a
   feature to "earn" the minor bump and **deliberately declined** as out of scope; see
   *Out of scope / suggestions recorded*.
2. **The dependency floor moves to `>= 2.7.0` — forced, not chosen.** `OpenSsl.PasswordException`
   does not exist in 2.6.x, so once the library binds to it the assembly cannot load against an
   older BouncyCastle. There is no source-and-binary-compatible alternative: catching the
   `Security.` base instead raises **CS0618**, which `TreatWarningsAsErrors` turns into a build
   failure.
3. **Bump `coverlet.collector` in the same release** (6.0.4 → 10.0.1). Test-only and
   `PrivateAssets=all`, so it never enters the package; the full suite verifies it in the same run.
   Recorded in the notes as a test-only transition.
4. **Add PQC encoding-contract tests.** The existing fixed-vector tests prove that a *pinned* key
   still works; they would not catch `GenerateKeyPair` starting to return a **seed** instead of the
   **expanded** encoding (a round-trip test still passes in that world, while every previously
   persisted key breaks). `DefaultFormat = SeedOnly` is upstream signalling that this area is moving,
   so the XML-doc promise gets turned into an enforced assertion.
5. **Do not add an `EncryptionException` catch to `PemUtils`.** Behaviour is identical across both
   BouncyCastle versions, and an unknown DEK algorithm is a structural PEM defect rather than a
   decryption failure — so `ArgumentException` is the right answer. Adding the catch would be a
   deliberate behaviour change (`ArgumentException` → `CryptographicException`) shipped in a release
   billed as a dependency bump. Instead the current behaviour is **pinned by a characterization
   test** so future BouncyCastle drift shows up as a red test.
6. **No *Breaking Changes & Migration* section** in the release notes — Enigma.Core's own API and
   behaviour are unchanged. The raised floor is recorded under *Dependencies* plus a *Compatibility*
   line.
7. **Release stops at pack-verify.** The build makes the in-repo edits, packs once into a throwaway
   directory to inspect the real artifact, deletes it, and **prints** the tag / pack / push runbook.
   Tagging and publishing remain the maintainer's.
8. **Historical `docs/plan/` and `docs/done/` records are not rewritten.** They are dated statements
   of what was true when that work shipped; ~15 of them mention 2.6.2 and stay as written.

## Definition of Done (applies to every phase)

Standard `dev-workflow` DoD:

1. `dotnet build Enigma.Core.slnx -c Release` succeeds with **zero warnings** across all three TFMs.
2. `dotnet test --solution Enigma.Core.slnx -c Release` passes in full on **net8.0 and net10.0**
   (prefix `DOTNET_ROOT=~/.dotnet` if the test apphost cannot find the runtime).
3. Every acceptance criterion of the phase is met.
4. Roadmap row + this plan file's phase status updated.
5. `docs/done/FEATURE-797D-PHASENN.md` written.

---

## PHASE01 — Upgrade to BouncyCastle 2.7.0

**Status:** TODO
**Branch:** `feature/feature-797d-phase01-bouncycastle-270`

### Scope

**In scope**

| File | Change |
|---|---|
| `Directory.Packages.props` | `BouncyCastle.Cryptography` 2.6.2 → **2.7.0**; `coverlet.collector` 6.0.4 → **10.0.1** |
| `src/Enigma.Core/Asymmetric/PublicKey/PemUtils.cs` | resolve the CS0104 ambiguity at line 67 |
| `tests/Enigma.Core.UnitTests/Certificates/CertificateInfoTests.cs` | `new DerInteger(1)` → `DerInteger.ValueOf(1)` (line 141) |
| `tests/Enigma.Core.UnitTests/Pqc/MLKemEncodingContractTests.cs` | **new** |
| `tests/Enigma.Core.UnitTests/Pqc/MLDsaEncodingContractTests.cs` | **new** |
| `tests/Enigma.Core.UnitTests/PublicKey/RsaArgumentValidationTests.cs` | +1 characterization test |

**Out of scope**
- Any other product-code change; in particular **no** new `catch` clause in `PemUtils` (decision 5).
- Any change to the pinned PQC fixture bytes (`*.key`, `*.bin`, `message.txt`) — they are the
  cross-version compatibility evidence and must pass **unmodified**.
- `xunit.v3`, `PolySharp`, `System.Buffers` (already latest).
- Version bump and all release documentation — that is PHASE02.

### Design / approach

1. **Package versions.** Edit `Directory.Packages.props` only (CPM). Restore and confirm both
   transitions resolve.

2. **CS0104 fix — `PemUtils.cs`.** The file imports both `Org.BouncyCastle.OpenSsl` and
   `Org.BouncyCastle.Security`, and 2.7.0 defines `PasswordException` in both. Bind explicitly to
   the **OpenSsl** type:

   ```csharp
   // 2.7.0 moved PasswordException into Org.BouncyCastle.OpenSsl; the Security namespace keeps an
   // [Obsolete] base of the same name, so the unqualified name is ambiguous across the two usings.
   using PasswordException = Org.BouncyCastle.OpenSsl.PasswordException;
   ```

   with the alias placed among the file's existing `using` directives, leaving line 67's
   `catch (PasswordException ex)` unchanged. A fully-qualified `catch` is equally acceptable if that
   reads better in context. **Do not** bind to `Org.BouncyCastle.Security.PasswordException` — it is
   `[Obsolete]` and would raise CS0618, failing the build.

3. **CS0618 fix — `CertificateInfoTests.cs:141`.** Inside the malformed-SAN fixture, replace
   `new DerInteger(1)` with `DerInteger.ValueOf(1)`. The DER payload is identical, so the test's
   intent (an implicitly-tagged constructed SEQUENCE under a `dNSName` tag) is preserved.

4. **PQC encoding-contract tests.** Two new classes under `tests/Enigma.Core.UnitTests/Pqc/`,
   following the existing naming and `Service()`-helper style of the neighbouring PQC tests. Each is
   a `[Theory]` over every parameter set, asserting the **exact** FIPS encoding sizes returned by the
   public services, plus an explicit assertion that the private key is **not** seed-length (the
   contract the XML docs promise: the *expanded* encoding, never the seed).

   | ML-KEM set | public | private | ciphertext | shared secret |
   |---|---:|---:|---:|---:|
   | `MLKem512`  | 800  | 1632 | 768  | 32 |
   | `MLKem768`  | 1184 | 2400 | 1088 | 32 |
   | `MLKem1024` | 1568 | 3168 | 1568 | 32 |

   | ML-DSA set | public | private |
   |---|---:|---:|
   | `MLDsa44` | 1312 | 2560 |
   | `MLDsa65` | 1952 | 4032 |
   | `MLDsa87` | 2592 | 4896 |

   The ML-KEM class exercises `GenerateKeyPair` → `Encapsulate` → `Decapsulate` so the ciphertext and
   shared-secret sizes come from a real round trip. The seed guard asserts the private-key length is
   neither 32 nor 64 bytes.

5. **PEM characterization test.** Add to `RsaArgumentValidationTests`, beside the existing
   `PrivateKeyOperation_WrongPassword_ThrowsCryptographicException`: take an AES-256-CBC-encrypted
   private-key PEM, replace `DEK-Info: AES-256-CBC` with a bogus algorithm name, and assert
   `ArgumentException`. This pins the current mapping (BouncyCastle's `EncryptionException` →
   `catch (IOException)` → `ArgumentException("The private-key PEM is malformed.")`) so a future
   BouncyCastle change to that path surfaces as a red test rather than silently.

6. **Verification.** Full Release build across all three TFMs, then the whole suite on both test
   TFMs. Confirm specifically that the four PQC fixed-vector tests and every BouncyCastle-isolation
   test pass with their fixtures untouched.

### Acceptance criteria

1. `Directory.Packages.props` pins `BouncyCastle.Cryptography` **2.7.0** and `coverlet.collector`
   **10.0.1**; no `Version=` attribute appears on any `PackageReference`.
2. `dotnet build Enigma.Core.slnx -c Release` succeeds with **0 warnings** on
   `netstandard2.0`, `net8.0` and `net10.0`.
3. The full suite passes on **net8.0 and net10.0** with **0 failures** (baseline 3254 tests, plus the
   new ones).
4. `MLKemEncodingContractTests` and `MLDsaEncodingContractTests` pass for **all six** parameter sets,
   including the not-a-seed assertions.
5. `MLKemFixedVectorTests` and `MLDsaFixedVectorTests` pass with **byte-identical fixtures** — no
   `*.key`, `*.bin` or `message.txt` file is regenerated or modified.
6. The unsupported-DEK characterization test passes.
7. `Api/BouncyCastleIsolationTests` and every per-category isolation test remain green — no
   BouncyCastle type reaches the public surface.
8. `PemUtils` gained **no** new `catch` clause; the only product-code change in the phase is the
   `PasswordException` binding.
9. `docs/done/FEATURE-797D-PHASE01.md` records: the two obsolescence fixes with their compiler error
   codes, both dependency transitions, the ML-KEM/ML-DSA cross-version evidence (API additive-only,
   encodings byte-identical, fixtures unchanged), and the build/test counts.

---

## PHASE02 — Release v1.1.0

**Status:** TODO
**Branch:** `feature/feature-797d-phase02-release-110`

Follows `dotnet-release`'s **routine release** path (a published version already exists), which is a
single phase: version, notes, callout, dependency log, pack-verify, runbook.

### Scope

**In scope**

| File | Change |
|---|---|
| `src/Enigma.Core/Enigma.Core.csproj` | `<Version>` 1.0.0 → **1.1.0**; rewrite `<PackageReleaseNotes>` |
| `RELEASENOTES.md` | **prepend** a 1.1.0 section |
| `README.md` | what's-new callout `1.0` → `1.1`; line 47 `BouncyCastle 2.6.2` → `2.7.0` |
| `SECURITY.md` | supported-versions table `1.0.x` → `1.1.x` |
| `CLAUDE.md` | line 68 runtime dependency `2.6.2` → `2.7.0` |
| `docs/RELEASE.md` | line 63 expected dependency floor `2.6.2` → `2.7.0` |

**Out of scope**
- The 13 guides under `docs/guides/` — none names a BouncyCastle version, so they are untouched and
  **the snippet-verification gate does not fire this release**.
- Historical `docs/plan/` and `docs/done/` records (decision 8).
- `README.md` badges (the NuGet-version badge self-tracks; no Downloads badge — house set) and the
  supported-TFM list (the TFM set did not move).
- `CHANGELOG.md` — `RELEASENOTES.md` is the single release-notes source; do not add one.
- Any `src/` behaviour change, any tag, any publish.

### Design / approach

1. **csproj.** `<Version>1.1.0</Version>`. Replace `<PackageReleaseNotes>` with a short prose summary
   mirroring the top of the new `RELEASENOTES.md` section, ending
   `See RELEASENOTES.md for the full details.` Confirm in passing that the 12 packable-library
   properties are all still present, `GeneratePackageOnBuild` is still off, and no symbol property
   (`IncludeSymbols`, `SymbolPackageFormat`, `PublishRepositoryUrl`, `EmbedUntrackedSources`) has
   crept in.

2. **`RELEASENOTES.md`.** Prepend a `# Enigma.Core v1.1.0 Release Notes` section above the 1.0.0 one,
   using the subsequent-release variant and only the non-empty sub-sections, in order:

   - **Dependencies** — `BouncyCastle.Cryptography 2.6.2 → 2.7.0`;
     `coverlet.collector 6.0.4 → 10.0.1` (test-only, not redistributed).
   - **Compatibility** — target frameworks unchanged (`netstandard2.0`, `net8.0`, `net10.0`); the
     **minimum BouncyCastle.Cryptography is now 2.7.0**, so consumers pinned to 2.6.x must upgrade;
     ML-KEM and ML-DSA key, ciphertext and signature encodings are unchanged, so material persisted
     by 1.0.0 keeps working.
   - **Version** — `1.1.0`.

   No *New Features*, no *Fixes*, and explicitly **no *Breaking Changes & Migration*** section
   (decision 6).

3. **README.** Update the callout to
   `> **What's new in 1.1** — …` with a one-line highlight, and the *Installation* line to
   `…built on BouncyCastle 2.7.0.` Leave everything else alone; keep the packed-README link rule
   (only `LICENSE.md` / `RELEASENOTES.md` linked, guides referenced in prose).

4. **`SECURITY.md`, `CLAUDE.md`, `docs/RELEASE.md`.** One-line version refreshes as tabled above.

5. **Pack-verify (run locally, then delete).**

   ```bash
   dotnet pack src/Enigma.Core/Enigma.Core.csproj -c Release -o ./artifacts-verify
   ```

   Inspect the artifact and its nuspec, then **delete `./artifacts-verify`** — it is never committed.

6. **Print the runbook** (never run it) — pre-flight build/test, merge to `main`, **bare `1.1.0`
   tag** (matching the existing `1.0.0` tag), publish `dotnet pack` into `./artifacts`, and
   `dotnet nuget push`. The API key is never echoed, stored or committed. Follow with the
   post-publish verification list.

### Acceptance criteria

1. `src/Enigma.Core/Enigma.Core.csproj` carries `<Version>1.1.0</Version>` and a
   `<PackageReleaseNotes>` mirroring the new notes section.
2. `RELEASENOTES.md` has a top **1.1.0** section with the *Dependencies*, *Compatibility* and
   *Version* sub-sections described above, recording **both** `old → new` transitions; the 1.0.0
   section is preserved below it unmodified.
3. `README.md` (callout + BouncyCastle line), `SECURITY.md`, `CLAUDE.md` and `docs/RELEASE.md` are
   all consistent at **1.1.0 / BouncyCastle 2.7.0**; badges and the TFM list are unchanged.
4. Release build clean with **0 warnings** and the full suite green — re-verified in this phase.
5. **Pack-verify passes**: the `.nupkg` version is `1.1.0`; the verify directory contains the
   `.nupkg` and **nothing else** (no `.snupkg`); `README.md` is embedded and **non-empty**;
   `LICENSE.md` is embedded; the nuspec's `version`, `title`, `license type="file"`, `readme` and
   `releaseNotes` are correct; the dependency groups show
   **`BouncyCastle.Cryptography >= 2.7.0`** on all three TFMs and `System.Buffers` on
   `netstandard2.0` only. The verify directory is then deleted.
6. The tag / pack / push runbook is **printed, not run**, using the bare `1.1.0` tag format.
7. `docs/done/FEATURE-797D-PHASE02.md` records the files changed, the pack-verify findings
   (including the observed per-TFM dependency floors), and states that tagging and publishing remain
   the maintainer's.
8. The item's roadmap row flips to `DONE` alongside PHASE02.

---

## Out of scope / suggestions recorded (not planned here)

- **SLH-DSA (FIPS 205).** BouncyCastle 2.7.0 exposes `SlhDsaSigner`, `SlhDsaKeyPairGenerator` and 12
  parameter sets (`sha2`/`shake` × 128/192/256 × `f`/`s`). It would round out the PQC category
  alongside ML-KEM and ML-DSA and would genuinely justify a minor version, but it is a full
  service + factory + enum + guide + test-suite build — its own FEATURE, not part of a dependency
  bump. **Considered during the interview and deliberately declined.**
- **`netstandard2.0` is compiled but never executed.** The test project targets `net8.0;net10.0`
  only, so the library's `netstandard2.0` assembly — and the BouncyCastle `netstandard2.0` assembly
  backing it — are verified by compilation alone, never by a running test. This gap is
  **pre-existing**, not introduced by this upgrade; closing it (e.g. by adding a `net472` test TFM)
  would be its own work item.
- **`coverlet.collector` 6 → 10 in isolation.** Bundled into PHASE01 here because the suite verifies
  it immediately. If it turns out to break coverage collection, revert that single line and record
  it as a held-back dependency in the notes rather than blocking the release.
